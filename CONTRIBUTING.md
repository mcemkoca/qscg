# Contributing to QSCG

Hey — thanks for even considering a PR. This is a solo project that grew out of a late-night obsession with lattice math, so every contribution, no matter how small, genuinely helps.

## The short version

1. Fork, branch (`feature/your-thing` or `fix/whatever`), code.
2. Run `pytest tests/ -v` before pushing. If it fails, fix it.
3. Open a PR with a clear description. I'll review within a few days.
4. Don't overthink commit messages — `feat: add X`, `fix: handle Y`, `docs: clarify Z` is plenty.

## What I'm looking for

- **Bug fixes** — especially in the modular ML-DSA sign/verify loop (it's hanging, I know, help wanted).
- **Algorithm implementations** — LMS, XMSS, Classic McEliece, anything from the roadmap.
- **Tests** — KAT vectors, property-based tests, fuzzing.
- **Documentation** — if something confused you, others are confused too. Write it down.
- **Benchmarks** — performance data on different CPUs, Python versions, PyPy.

## Style

- Black formatting (`black src/ tests/`).
- Type hints on public APIs.
- Google-style docstrings.
- No custom crypto primitives — follow the NIST spec, not your intuition.
- Constant-time where secrets are involved. If you're unsure, ask.

## Big changes?

Open an issue first. I don't want you to spend a week on a PR I have to reject because the direction was wrong. I'll respond — promise.

## Recognition

Every merged PR gets a shout-out in the release notes. If you want your name in `CONTRIBUTORS.md`, just say so in the PR description.

Questions? Open a Discussion or email me at mcemkoca0@gmail.com.

— deuterium12
