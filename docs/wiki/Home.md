<img src="https://raw.githubusercontent.com/mcemkoca/qscg/main/docs/logo.png" alt="QSCG Logo" width="120" align="right"/>

# QSCG - Quantum-Safe Cryptography GitHub Repository

> **Post-Quantum Cryptography Toolkit for Python**
> 
> [![PyPI](https://img.shields.io/pypi/v/qscg)](https://pypi.org/project/qscg)
> [![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
> [![Python](https://img.shields.io/badge/python-3.9%2B-blue)](https://www.python.org)
> [![NIST](https://img.shields.io/badge/NIST-PQC%20Standards-green)](https://csrc.nist.gov/projects/post-quantum-cryptography)
> [![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()

Welcome to the **QSCG** official wiki. This documentation provides comprehensive guidance on quantum-safe cryptographic algorithms, implementation details, API references, and migration strategies for the post-quantum era.

---

## Table of Contents

1. [Project Overview](#project-overview)
2. [Key Features](#key-features)
3. [Quick Start](#quick-start)
4. [Wiki Navigation](#wiki-navigation)
5. [Version Information](#version-information)
6. [Contributing](#contributing)
7. [License](#license)

---

## Project Overview

**QSCG** is a production-ready Python library implementing the NIST-standardized post-quantum cryptographic algorithms. With the imminent arrival of cryptographically-relevant quantum computers, traditional public-key cryptosystems (RSA, ECC, Diffie-Hellman) face existential threats from Shor's algorithm. QSCG provides a practical migration path to quantum-resistant security.

The library implements three NIST-standardized algorithms:

| Algorithm | FIPS Standard | Purpose | Quantum-Resistant |
|-----------|--------------|---------|-------------------|
| ML-KEM | FIPS 203 | Key Encapsulation | Yes |
| ML-DSA | FIPS 204 | Digital Signatures | Yes |
| SLH-DSA | FIPS 205 | Stateless Hash Signatures | Yes |

Additionally, QSCG provides **hybrid encryption** through AES-256-GCM with post-quantum key encapsulation, ensuring defense-in-depth during the transition period.

---

## Key Features

- **NIST-Compliant Implementations**: All algorithms follow FIPS 203, 204, and 205 specifications exactly
- **Multiple Security Levels**: Support for NIST security levels 1, 3, and 5
- **Pure Python + Optimized Backends**: Works anywhere with optional C extensions for performance
- **Type Hints**: Fully typed codebase with mypy compliance
- **Comprehensive Testing**: >95% test coverage with known-answer tests (KAT) from NIST
- **CLI Tool**: Command-line interface for rapid testing and key generation
- **Hybrid Cryptography**: Combine post-quantum and classical algorithms
- **Educational Resources**: Built-in threat analysis and migration guidance

### Supported Platforms

| Platform | Python 3.9 | Python 3.10 | Python 3.11 | Python 3.12 |
|----------|-----------|-------------|-------------|-------------|
| Linux x86_64 | ✅ | ✅ | ✅ | ✅ |
| Linux ARM64 | ✅ | ✅ | ✅ | ✅ |
| macOS x86_64 | ✅ | ✅ | ✅ | ✅ |
| macOS ARM64 | ✅ | ✅ | ✅ | ✅ |
| Windows x86_64 | ✅ | ✅ | ✅ | ✅ |

---

## Quick Start

### Installation

```bash
# Install from PyPI
pip install qscg

# Verify installation
qscg --version
qscg --help
```

### Basic Usage: Key Encapsulation (ML-KEM)

```python
from qscg import MLKEM

# Initialize with NIST security level 3
kem = MLKEM(level=3)

# Generate keypair
public_key, private_key = kem.generate_keypair()
print(f"Public key size: {len(public_key)} bytes")

# Encapsulate shared secret
ciphertext, shared_secret = kem.encapsulate(public_key)

# Decapsulate shared secret
decrypted_secret = kem.decapsulate(ciphertext, private_key)

# Verify
assert shared_secret == decrypted_secret
print("ML-KEM key encapsulation successful!")
```

### Basic Usage: Digital Signatures (ML-DSA)

```python
from qscg import MLDSA

# Initialize signer with security level 3
dsa = MLDSA(level=3)

# Generate signing keypair
public_key, private_key = dsa.generate_keypair()

# Sign a message
message = b"Hello, quantum-safe world!"
signature = dsa.sign(message, private_key)
print(f"Signature size: {len(signature)} bytes")

# Verify signature
is_valid = dsa.verify(message, signature, public_key)
assert is_valid
print("ML-DSA signature verified!")
```

### Basic Usage: Hybrid Encryption

```python
from qscg import HybridKEM

# Combine ML-KEM with classical X25519 for hybrid security
hybrid = HybridKEM(pq_level=3)

pk, sk = hybrid.generate_keypair()
ciphertext, shared_secret = hybrid.encapsulate(pk)
recovered = hybrid.decapsulate(ciphertext, sk)

assert shared_secret == recovered
print("Hybrid key encapsulation successful!")
```

### Command-Line Quick Test

```bash
# Run all algorithm tests
qscg --test

# Run specific algorithm tests
qscg --kem --level 3
qscg --dsa --level 3
qscg --slh --level 1
qscg --aes

# Full threat analysis
qscg --analysis

# Check NIST compliance
qscg --nist
```

---

## Wiki Navigation

| Page | Description | Link |
|------|-------------|------|
| **Home** | This page - project overview and quick start | [Home](Home) |
| **Algorithms & Standards** | Detailed NIST PQC algorithm explanations, mathematical foundations, and comparisons | [Algorithms-and-Standards](Algorithms-and-Standards) |
| **API Documentation** | Complete Python API reference with all classes, methods, and examples | [API-Documentation](API-Documentation) |
| **CLI Usage** | Command-line tool guide with all commands and usage scenarios | [CLI-Usage](CLI-Usage) |
| **Quantum Threat Analysis** | Quantum threat analysis and migration planning guide | [Quantum-Threat-Analysis](Quantum-Threat-Analysis) |

---

## Version Information

| Attribute | Details |
|-----------|---------|
| **Current Version** | v2.2.0 |
| **Release Date** | 2025-01-15 |
| **Python Support** | 3.9, 3.10, 3.11, 3.12 |
| **NIST Standards** | FIPS 203, FIPS 204, FIPS 205 (Final) |
| **License** | MIT License |
| **Author** | M.C. Emre Koca (mcemkoca) |

### Changelog (v2.2.0)

- Added SLH-DSA (FIPS 205) full implementation with all security levels
- Enhanced hybrid encryption with AES-256-GCM integration
- Improved NTT (Number Theoretic Transform) performance
- Added comprehensive threat analysis module (`--analysis` CLI flag)
- Added NIST compliance verification tool (`--nist` CLI flag)
- Added HNDL (Harvest Now, Decrypt Later) analysis
- Performance optimizations for ML-KEM and ML-DSA key generation
- Expanded test coverage to >95%
- Added type hints throughout the codebase

---

## Contributing

Contributions are welcome. Please see the [Contributing Guide](https://github.com/mcemkoca/qscg/blob/main/CONTRIBUTING.md) for details.

### Reporting Issues

- Use [GitHub Issues](https://github.com/mcemkoca/qscg/issues) for bug reports
- Include Python version, OS, and QSCG version
- Provide minimal reproducible examples when possible

### Development Setup

```bash
git clone https://github.com/mcemkoca/qscg.git
cd qscg
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

This project is licensed under the MIT License. See the [LICENSE](https://github.com/mcemkoca/qscg/blob/main/LICENSE) file for details.

The cryptographic implementations are based on NIST FIPS 203, 204, and 205 standards, which are in the public domain.

---

> **Last Updated**: 2025-01-15 | QSCG v2.2.0
>
> For questions or support, please open an issue on [GitHub](https://github.com/mcemkoca/qscg/issues).
