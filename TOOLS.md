# TOOLS.md - Local Notes

Skills define _how_ tools work. This file is for _your_ specifics — the stuff that's unique to your setup.

## Workflow Rules

### GitHub — Doğrulama Sonrası Push
- **Kural:** Her başarılı doğrulama, test, veya onaylanan değişiklik sonrası `git add`, `git commit`, `git push` — hemen, gecikmeden.
- **Mantık:** Yerel drift kabul edilemez. "Sonra pushlarım" yok. Doğrulama = Push.
- **Mesaj stili:** `feat: ...`, `fix: ...`, `docs: ...`, `refactor: ...` — kararlı, net commit mesajları.
- **Branch:** Main/master üzerinde çalışıyorsak, doğrudan push. PR gerektiren projelerde branch + PR.

## What Goes Here

Things like:

- Camera names and locations
- SSH hosts and aliases
- Preferred voices for TTS
- Speaker/room names
- Device nicknames
- Anything environment-specific

## Examples

```markdown
### Cameras

- living-room → Main area, 180° wide angle
- front-door → Entrance, motion-triggered

### SSH

- home-server → 192.168.1.100, user: admin

### TTS

- Preferred voice: "Nova" (warm, slightly British)
- Default speaker: Kitchen HomePod
```

## Why Separate?

Skills are shared. Your setup is yours. Keeping them apart means you can update skills without losing your notes, and share skills without leaking your infrastructure.

---

Add whatever helps you do your job. This is your cheat sheet.

## Related

- [Agent workspace](/concepts/agent-workspace)
