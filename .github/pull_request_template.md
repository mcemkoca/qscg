<!--
  Thank you for your contribution to qscg! Please fill out the following template
to help reviewers understand and evaluate your changes efficiently.

  PR title format (Conventional Commits):
  <type>(<scope>): <short description>

  Examples:
    feat(ml-kem): add AVX2-optimized key generation
    fix(ml-dsa): correct signature verification boundary check
    docs(readme): update installation instructions for Python 3.12
    refactor: simplify NTT polynomial multiplication
-->

## Description

<!-- Provide a clear and concise description of the changes. -->

## Related Issue

<!-- Link to the related issue(s). Use "Closes #X" to auto-close on merge. -->
Closes #

## Type of Change

<!-- Check all that apply. -->

- [ ] Bug fix (non-breaking change which fixes an issue)
- [ ] New feature (non-breaking change which adds functionality)
- [ ] Breaking change (fix or feature that would cause existing functionality to not work as expected)
- [ ] Documentation update
- [ ] Refactoring (no functional changes, no API changes)
- [ ] Test additions or improvements
- [ ] Build/CI or dependency changes
- [ ] Performance improvement

## Algorithm / Standard Compliance

<!-- For cryptographic changes only. -->

- [ ] Change aligns with NIST FIPS 203/204/205 specifications
- [ ] Test vectors from official NIST CAVP/KAT are included or updated
- [ ] No deviations from the standard without explicit justification and documentation

## Checklist

- [ ] I have read the [Contributing Guidelines](/CONTRIBUTING.md)
- [ ] My code follows the project's style guidelines (PEP 8, Black, isort)
- [ ] I have performed a self-review of my own code
- [ ] I have commented my code, particularly in hard-to-understand areas
- [ ] I have made corresponding changes to the documentation
- [ ] I have added or updated tests that prove my fix is effective or my feature works
- [ ] New and existing unit tests pass locally with my changes (`pytest`)
- [ ] Lint and type checks pass (`ruff check .`, `mypy qscg`)
- [ ] I have updated the [CHANGELOG.md](/CHANGELOG.md) with a summary of my changes
- [ ] Breaking changes are documented with migration notes

## Screenshots (if applicable)

<!-- Add screenshots for UI changes, benchmark results, or architectural diagrams. -->

## Test Plan

<!-- Describe how you tested your changes. Include commands, test environments, and edge cases. -->

```bash
# Example test commands
pytest tests/ -v --tb=short
pytest tests/test_mlkem.py -k "test_keygen" -v
```

**Test Environment:**
- OS: 
- Python version: 
- Architecture: 

## Benchmarks (if applicable)

<!-- For performance-related changes, include before/after benchmark results. -->

| Operation | Before | After | Improvement |
|-----------|--------|-------|-------------|
|           |        |       |             |

## Breaking Changes

<!-- If this PR introduces breaking changes, describe them here and provide migration guidance. -->

**None.**

<!-- Or:
### Breaking Changes
- `MLKEM.encaps()` now returns a `EncapsResult` dataclass instead of a tuple.
- Migration: Change `ct, ss = kem.encaps(pk)` to `result = kem.encaps(pk); ct = result.ciphertext; ss = result.shared_secret`.
-->
