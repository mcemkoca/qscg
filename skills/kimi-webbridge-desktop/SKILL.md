---
name: kimi-webbridge
description: |
  Kimi WebBridge lets AI control the user's real browser — navigate, click, type, read, screenshot, and interact with any website using the user's actual login sessions. Use this skill whenever the user wants to interact with websites, automate browser tasks, scrape web content, or perform any action requiring a real browser. Also use when the user mentions "browser", "webpage", "open URL", "screenshot", or asks to read/interact with any website. Use even for simple-sounding browser requests — the daemon handles all complexity.
---

# Kimi WebBridge

Control the user's real browser (with their login sessions) via a local daemon at `http://127.0.0.1:10086`.

## Environment

This skill assumes the user is running the **Kimi Desktop App**, which bundles the daemon and manages its lifecycle (starts when the app opens, stops when it closes). You should NOT use CLI commands to start/stop/restart the daemon — doing so would conflict with the app.

## Health check (always do this first)

```bash
curl -s http://127.0.0.1:10086/status
```

Then act on the result:

- **`running: true` and `extension_connected: true`** — healthy. Proceed with the tool calls below.
- **Anything else** (no response, `running: false`, `extension_connected: false`) — **Read `references/operations.md`** in this skill directory. It explains how to recover via the Desktop App.

## Tools

| Tool | Args | Returns | Note |
|------|------|---------|------|
| `navigate` | `url`, `newTab`(bool), `group_title` | `{success, url, tabId}` | Always use `newTab:true` on first call. `group_title` sets the tab group's visible label |
| `find_tab` | `url`, `active`(bool) | `{success, url, tabId}` | **Reuse an already-open tab** — pass any URL or domain; `active:true` picks the tab the user is currently viewing, default picks the leftmost match |
| `snapshot` | — | `{url, title, tree}` with `@e` refs | **Accessibility tree** (text) — use this to read page content and locate elements |
| `click` | `selector` (@e ref or CSS) | `{success, tag, text}` | Synthetic `el.click()` — does NOT focus `[contenteditable]`; see Trusted input primitives |
| `fill` | `selector`, `value` | `{success, tag}` | |
| `evaluate` | `code` (supports async/await) | `{type, value}` | |
| `screenshot` | `format`(png\|jpeg), `quality`(0-100), optional `selector` (@e/CSS) | `{format, dataLength, data}` (base64) | Full page floods context — use helper script (saves to disk, returns path). With `selector` only that element is captured (small, OK to call API directly) |
| `network` | `cmd`(start\|stop\|list\|detail), `filter`, `requestId` | request/response data | |
| `upload` | `selector`, `files`(string[]) | `{success, fileCount}` | |
| `mouse_click` | `selector` (@e ref or CSS) | `{success, x, y, tag, text}` | CDP real mouse events. Use when `click` fails OR to focus `[contenteditable]` |
| `key_type` | `text` | `{success, length}` | CDP `Input.insertText` at cursor of focused element. Required for `[contenteditable]` |
| `send_keys` | `keys` (e.g. `"Enter"`, `"Escape"`) | `{success, dispatched, os}` | Real keyboard events. Use for `Enter` (submit form) or `Escape` (close modal). For typing text use `key_type` |
| `save_as_pdf` | `paper_format`, `landscape`, `scale`, `print_background`, `file_name` | `{path, sizeBytes, mimeType, pageTitle}` | Render current page → PDF, saved under `/tmp/kimi-webbridge-pdfs/` |
| `list_tabs` | — | `{success, tabs:[{tabId, url, title, active, groupTitle}]}` | Inspect tabs in the current session |
| `close_tab` | — | `{success, closed: bool}` | Close the current tab in the session |
| `close_session` | — | `{success, closed: int}` | Close all tabs — `closed` is the count. Always call at task end |

### Using find_tab

Use `find_tab` when the user explicitly asks to operate on an already-open tab. It matches by domain, so any URL on the same site works. Without `active:true`, returns the leftmost matching tab; with `active:true`, returns the tab the user is currently viewing — pass it when the user says "用我打开的 X" / "在我当前的 X 页面上".

```bash
curl -s -X POST http://127.0.0.1:10086/command \
  -d '{"action":"find_tab","args":{"url":"https://www.kimi.com","active":true},"session":"kimi"}'
```

If `find_tab` returns "no open tab found", the page is not open — fall back to `navigate` with `newTab:true`.

### Call Format

```bash
curl -s -X POST http://127.0.0.1:10086/command \
  -H 'Content-Type: application/json' \
  -d '{"action":"navigate","args":{"url":"https://example.com","newTab":true}}'
```

## Sessions

Each session maps to a separate browser tab group. Use different session names for different sites to keep operations isolated.

Add `"session":"name"` to the request body:

```bash
curl -s -X POST http://127.0.0.1:10086/command \
  -d '{"action":"navigate","args":{"url":"https://example.com","newTab":true},"session":"my-task"}'
```

Always assign distinct session names when working with multiple sites in parallel.

## Screenshots: Use the Helper Script

**Never call the screenshot API directly** — it returns base64-encoded image data (hundreds of KB of text) that will flood the context window.

Use `scripts/screenshot.sh` instead. It decodes and saves the image to disk, returning only the file path:

```bash
# Default — saves to /tmp/kimi-webbridge-screenshots/{timestamp}.png
bash "$(dirname "$SKILL_PATH")/scripts/screenshot.sh"

# With a session
bash "$(dirname "$SKILL_PATH")/scripts/screenshot.sh" -s my-task

# Custom output path
bash "$(dirname "$SKILL_PATH")/scripts/screenshot.sh" -o /tmp/page.png

# JPEG format, quality 60
bash "$(dirname "$SKILL_PATH")/scripts/screenshot.sh" -f jpeg -q 60
```

After getting the file path, use the Read tool to view the image.

If `$SKILL_PATH` is unavailable, call the script by its absolute path.

## Prefer snapshot over CSS/JS selectors

`snapshot` returns interactive elements with `@e` refs based on semantic role/name. Use them directly with click/fill — they survive CSS class hash changes that break manually-written selectors.

Fall back to `evaluate` (JS) only when:
- The target has no `@e` ref in the snapshot
- You need attributes not in the snapshot (e.g., `href`)
- You need to dispatch complex event sequences, or scroll

## Evaluate Tips

- Always use compact `JSON.stringify(data)` — never add `null, 2` formatting. Indentation and newlines can inflate the response several times over, causing truncation during transmission.

## Trusted input primitives

`click` and `fill` are DOM-level — they cover the vast majority of cases and should be your default. The CDP-level primitives (`mouse_click`, `key_type`) exist for specific failures, not as a "more powerful" alternative.

### Click: when to escalate to `mouse_click`

| Default | Escalation | When to escalate |
|---------|-----------|------------------|
| `click` | `mouse_click` | (a) Element triggers a popup via `mousedown`/`mouseup` (search inputs, dropdown triggers). Verify by running `el.click()` in DevTools — if the popup doesn't open, escalate. (b) You need to **focus a `[contenteditable]`** — `click` fires a synthetic event but leaves `document.activeElement` on `BODY`, so a follow-up `key_type` writes to nothing. |

Don't blindly prefer CDP. `mouse_click` is more fragile than `el.click()` on many sites — escalate only with evidence.

### Text input: which tool

| Target | Tool | Why |
|--------|------|-----|
| `<input>` / `<textarea>` | `fill` | Sets `value` and dispatches `input`/`change`. |
| `[contenteditable]` / rich-text editor | `key_type` (after focusing) | `fill` cannot — contentEditable has no `value`. `key_type` uses CDP `Input.insertText`, which fires `beforeinput`/`input` for editor frameworks (ProseMirror, Lexical, etc.). |

`key_type` writes at the **cursor of the currently focused element** — works on inputs too, but `fill` is simpler for those. To use `key_type` on `[contenteditable]`, **first put real focus on it** with one of:

```bash
# Option A: real CDP mouse click — places caret as a side-effect of focus
{"action":"mouse_click","args":{"selector":"#editor"}}

# Option B: explicit JS focus + caret placement
{"action":"evaluate","args":{"code":"(()=>{const el=document.querySelector('#editor');el.focus();const r=document.createRange();r.selectNodeContents(el);r.collapse(false);const s=getSelection();s.removeAllRanges();s.addRange(r);})()"}}
```

The `click` tool alone is **not enough** for contenteditable — empirically verified, `document.activeElement` stays on `BODY`.

## Save the current page as PDF

`save_as_pdf` renders the current page to PDF, writes it to `/tmp/kimi-webbridge-pdfs/`, and returns the file path (the daemon strips the base64 — agent never sees raw PDF bytes).

All args optional:
- `paper_format`: `letter` (default) \| `a4` \| `legal` \| `a3` \| `tabloid`
- `landscape`: `false` (default)
- `scale`: `1.0` (default), range `[0.1, 2.0]`
- `print_background`: `true` (default) — keep background colors
- `file_name`: caller-supplied name; if absent, derived from page title

Decoded PDF cap is 100 MB. Above that the daemon refuses; reduce `scale` or split the page.

## Versions

Daemon (bundled by the Kimi Desktop App), extension, and this skill share a 1:1 version string. Read both via:

```bash
curl -s http://127.0.0.1:10086/status | jq '{version, extension_version}'
```

If a tool returns an error containing **"Please update the Kimi WebBridge extension"**, the user's extension is older than this skill. Tell the user:

> 请更新 Kimi WebBridge 浏览器扩展后重试：https://kimi.com/features/webbridge

Don't retry the failed tool. Don't auto-switch skill versions based on `extension_version` — the pairing protocol isn't finalized.
