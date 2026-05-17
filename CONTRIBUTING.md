# Contributing to qscg

Welcome to the **qscg** (Quantum-Safe Cryptography GitHub) project! We're thrilled that you're considering contributing. This document provides comprehensive guidelines to help you get started, ensure your contributions align with project standards, and make the contribution process smooth for everyone.

**qscg** is an open-source Python library implementing NIST FIPS 203/204/205 post-quantum cryptography standards. Contributions from cryptographers, security researchers, developers, and enthusiasts are all valued.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Development Environment Setup](#development-environment-setup)
- [Branch Naming Conventions](#branch-naming-conventions)
- [Commit Message Conventions](#commit-message-conventions)
- [Pull Request Process](#pull-request-process)
- [Code Style Guidelines](#code-style-guidelines)
- [Testing Requirements](#testing-requirements)
- [Documentation](#documentation)
- [Code Review Process](#code-review-process)
- [Community Guidelines](#community-guidelines)
- [Recognition](#recognition)

---

## Quick Start

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/qscg.git
   cd qscg
   ```
3. **Create a branch** following our [naming conventions](#branch-naming-conventions).
4. **Make your changes** with tests and documentation.
5. **Run the test suite** and ensure everything passes.
6. **Submit a Pull Request** following our [PR template](/.github/pull_request_template.md).

---

## Development Environment Setup

### Prerequisites

- **Python**: 3.9 or higher
- **Git**: 2.30 or higher
- **pip** or **uv** for dependency management

### Setting Up Your Local Environment

```bash
# Clone the repository
git clone https://github.com/mcemkoca/qscg.git
cd qscg

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install development dependencies
pip install -e ".[dev]"

# Or using uv
uv pip install -e ".[dev]"

# Verify installation
pytest --version
black --version
ruff --version
mypy --version
```

### Pre-commit Hooks

We use pre-commit hooks to enforce code quality automatically. Install them with:

```bash
pre-commit install
```

Hooks run on every commit to check formatting, linting, and type hints. To run them manually:

```bash
pre-commit run --all-files
```

---

## Branch Naming Conventions

All branches must follow this naming convention to keep the repository organized:

| Prefix | Purpose | Example |
|--------|---------|---------|
| `feature/` | New features or enhancements | `feature/ml-kem-avx2-backend` |
| `bugfix/` | Bug fixes | `bugfix/ml-dsa-sig-verification` |
| `hotfix/` | Critical production fixes | `hotfix/security-boundary-check` |
| `docs/` | Documentation changes only | `docs/api-reference-update` |
| `refactor/` | Code refactoring without behavior changes | `refactor/ntt-optimization` |
| `test/` | Test additions or improvements | `test/ml-kem-kat-vectors` |
| `chore/` | Maintenance, dependencies, CI/CD | `chore/update-github-actions` |

### Rules

- Use **lowercase** with **hyphens** as separators (kebab-case).
- Keep names **descriptive but concise** (max 50 characters recommended).
- Include an issue number when applicable: `bugfix/42-constant-time-comparison`.

---

## Commit Message Conventions

We follow the **[Conventional Commits](https://www.conventionalcommits.org/)** specification. This enables automated changelog generation and clear version bumping.

### Format

```
<type>(<scope>): <short summary>

<body>

<footer>
```

### Types

| Type | Description |
|------|-------------|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation changes |
| `style` | Code style changes (formatting, no logic change) |
| `refactor` | Code refactoring |
| `perf` | Performance improvement |
| `test` | Test additions or corrections |
| `build` | Build system or dependency changes |
| `ci` | CI/CD configuration changes |
| `chore` | Maintenance tasks |
| `security` | Security-related changes |

### Scopes

Common scopes for this project:

- `ml-kem` — ML-KEM (FIPS 203) module
- `ml-dsa` — ML-DSA (FIPS 204) module
- `slh-dsa` — SLH-DSA (FIPS 205) module
- `ntt` — Number Theoretic Transform utilities
- `encoding` — Serialization/deserialization
- `random` — Randomness and entropy sources
- `benchmarks` — Performance benchmarks
- `docs` — Documentation
- `ci` — CI/CD pipeline

### Examples

```bash
feat(ml-kem): add support for encapsulated key export

Implement `export_encapsulated_key` method on MLKEM class to allow
serialization of ciphertext-shared_secret pairs for storage.

Closes #87

fix(ml-dsa): prevent timing side-channel in rejection sampling

Replace conditional comparison with constant-time equivalent using
`secrets.compare_digest` to eliminate timing leakage.

Security: CVE-2024-XXXX
docs(readme): update Python version badge and install instructions

Add Python 3.12 and 3.13 badges. Update pip install command to
reflect latest PyPI release.
```

---

## Pull Request Process

1. **Open a draft PR early** — This allows maintainers to provide guidance while work is in progress. Prefix the title with `WIP:` or `DRAFT:`.

2. **Complete the PR template** — Every PR must fill out the [pull request template](/.github/pull_request_template.md) including:
   - Clear description of changes
   - Linked issues (use `Closes #X`)
   - Change type classification
   - Full checklist completion
   - Test plan description

3. **Ensure CI passes** — All GitHub Actions checks (tests, linting, type checking) must pass before review.

4. **Request review** — Once ready, request review from at least one maintainer. For cryptographic changes, two reviews are required.

5. **Address feedback** — Respond to all review comments. Mark conversations as resolved only after pushing fixes.

6. **Squash and merge** — Maintainers will squash and merge using the PR title as the commit message.

### PR Size Guidelines

- **Small PRs are preferred.** Aim for under 400 lines of changed code.
- If your change is large, consider splitting it into multiple smaller PRs.
- Each PR should address **one logical change**.

---

## Code Style Guidelines

We enforce strict code quality standards to maintain consistency and readability across the codebase.

### Python Code Style

- **PEP 8**: Follow [PEP 8](https://peps.python.org/pep-0008/) style guidelines.
- **Black**: Code is formatted with [Black](https://black.readthedocs.io/) (line length: 88 characters).
- **isort**: Imports are sorted with [isort](https://pycqa.github.io/isort/) using the Black profile.
- **Ruff**: Linting is performed with [Ruff](https://docs.astral.sh/ruff/).
- **mypy**: Type hints are checked with [mypy](https://mypy.readthedocs.io/) in strict mode.

### Configuration

```toml
# pyproject.toml
[tool.black]
line-length = 88
target-version = ['py39', 'py310', 'py311', 'py312', 'py313']

[tool.isort]
profile = "black"
line_length = 88

[tool.ruff]
line-length = 88
target-version = "py39"
```

### Running Checks

```bash
# Format code
black qscg/ tests/
isort qscg/ tests/

# Lint
ruff check qscg/ tests/

# Type check
mypy qscg/

# Run all checks (same as CI)
pre-commit run --all-files
```

### Cryptography-Specific Guidelines

- **Constant-time operations**: All operations involving secret data (keys, seeds, private coefficients) must be constant-time. Never branch on secret values.
- **Secure memory**: Use `secrets` module or secure memory zeroization where applicable.
- **No custom crypto**: Do not implement your own cryptographic primitives. All algorithms must follow published NIST specifications exactly.
- **Docstrings**: All public functions must have docstrings following the Google style.

### Example

```python
from typing import Tuple

from qscg.constants import ML_KEM_768_PARAMS
from qscg.utils import constant_time_select


def generate_keypair(seed: bytes) -> Tuple[bytes, bytes]:
    """Generate an ML-KEM-768 keypair from a seed.

    Args:
        seed: A 64-byte random seed.

    Returns:
        A tuple of (encapsulation_key, decapsulation_key).

    Raises:
        ValueError: If the seed length is not 64 bytes.
    """
    if len(seed) != 64:
        raise ValueError(f"Expected seed of length 64, got {len(seed)}")
    # ... implementation
```

---

## Testing Requirements

All contributions must include appropriate tests. Untested code will not be merged.

### Test Framework

We use **pytest** as our test runner:

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=qscg --cov-report=term-missing

# Run specific test file
pytest tests/test_ml_kem.py -v

# Run with benchmark
pytest tests/ --benchmark-only
```

### Test Types

1. **Unit tests**: Test individual functions and classes in isolation.
2. **Integration tests**: Test module interactions and end-to-end workflows.
3. **Known Answer Tests (KAT)**: Cryptographic test vectors from NIST specifications **must** be included for every algorithm.
4. **Property-based tests**: Use Hypothesis for testing cryptographic invariants.
5. **Benchmarks**: Use pytest-benchmark for performance regression tests.

### Test Coverage

- Minimum coverage requirement: **90%** for new code.
- KAT vectors must cover all parameter sets (512, 768, 1024 for ML-KEM; 44, 65, 87 for ML-DSA).

### Test File Organization

```
tests/
├── conftest.py           # Shared fixtures and configuration
├── test_ml_kem.py        # ML-KEM algorithm tests
├── test_ml_dsa.py        # ML-DSA algorithm tests
├── test_slh_dsa.py       # SLH-DSA algorithm tests
├── test_ntt.py           # NTT utility tests
├── test_encoding.py      # Serialization tests
├── test_kat_vectors.py   # Known answer tests
└── benchmarks/           # Performance benchmarks
```

---

## Documentation

Good documentation is essential for a cryptography library.

### What to Document

- **Public API**: Every public class, method, and function.
- **Algorithms**: High-level descriptions with references to NIST documents.
- **Security considerations**: Warnings about proper usage and common pitfalls.
- **Migration guides**: For breaking changes between versions.

### Documentation Format

- Python docstrings: [Google style](https://google.github.io/styleguide/pyguide.html#383-functions-and-methods)
- Markdown for guides and README files.
- Type hints on all public APIs.

### Building Documentation

```bash
# Install docs dependencies
pip install -e ".[docs]"

# Build documentation
mkdocs serve  # or sphinx-build for API docs
```

---

## Code Review Process

All contributions undergo code review before merging.

### Review Criteria

- **Correctness**: Does the code implement the specification accurately?
- **Security**: Are there any side-channels, timing leaks, or unsafe operations?
- **Testing**: Are tests comprehensive and passing?
- **Documentation**: Is the change well-documented?
- **Style**: Does the code follow project conventions?
- **Performance**: Are there unnecessary allocations or inefficient operations?

### Review Timeline

- Initial review: **within 3 business days**
- Cryptographic changes: **within 5 business days** (may require external expert review)
- Follow-up reviews: **within 2 business days**

### Merge Requirements

- At least **1 approving review** from a maintainer (2 for crypto changes)
- All CI checks **passing**
- No **unresolved conversations**
- Up-to-date with the **main branch**

---

## Community Guidelines

We are committed to providing a welcoming and inclusive experience for everyone.

- **Be respectful**: Treat all community members with respect and professionalism.
- **Be constructive**: Provide helpful feedback and assume good intent.
- **Be patient**: Maintainers are volunteers; responses may take a few days.
- **Stay on topic**: Keep discussions focused on the project.
- **No security discussions in public**: Report vulnerabilities privately per [SECURITY.md](/SECURITY.md).

For the complete set of community standards, please read our [Code of Conduct](/CODE_OF_CONDUCT.md).

---

## Recognition

Contributors will be recognized in the following ways:

- **All Contributors specification**: We follow the [All Contributors](https://allcontributors.org/) specification.
- **Release notes**: Significant contributions are acknowledged in release notes.
- **Contributors section**: A `CONTRIBUTORS.md` or section in the README lists all contributors.
- **Badges**: Active contributors may receive collaborator access to the repository.

To add yourself to the contributors list, comment on your merged PR with:

```
@all-contributors please add @USERNAME for <contribution_type>
```

Contribution types include: `code`, `test`, `doc`, `bug`, `security`, `example`, `review`.

---

## Questions?

If you have questions not covered by this guide:

- Open a [GitHub Discussion](https://github.com/mcemkoca/qscg/discussions)
- Join the conversation in existing issues
- Contact maintainers privately for sensitive topics

Thank you for contributing to quantum-safe cryptography! 🔐
