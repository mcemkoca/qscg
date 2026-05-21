<div align="center">

<img src="https://raw.githubusercontent.com/mcemkoca/qscg/main/logo.png" alt="QSCG Logo" width="180">

# QSCG &mdash; Quantum-Safe Cryptography GitHub Repository

**NIST FIPS 203/204/205 compliant post-quantum cryptography — ML-KEM, ML-DSA, SLH-DSA — v3.0.0**

[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/204/final)
[![NIST FIPS 205](https://img.shields.io/badge/NIST-FIPS%20205-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/205/final)

<p align="center">
  <a href="#installation">Installation</a> &bull;
  <a href="#usage">Usage</a> &bull;
  <a href="#project-structure">Structure</a> &bull;
  <a href="#algorithm-comparison">Comparison</a> &bull;
  <a href="#contributing">Contributing</a> &bull;
  <a href="#security">Security</a>
</p>

</div>

---

<p align="center">
  <img src="https://img.shields.io/badge/version-3.0.0-blue?style=for-the-badge&logo=github&logoColor=white&label=VERSION" alt="Version: 3.0.0">
  <img src="https://img.shields.io/github/actions/workflow/status/mcemkoca/qscg/ci.yml?branch=main&style=for-the-badge&logo=githubactions&logoColor=white&label=BUILD" alt="Build Status">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=for-the-badge&logo=python&logoColor=white&label=PYTHON" alt="Python 3.9+">
  <img src="https://img.shields.io/github/license/mcemkoca/qscg?style=for-the-badge&logo=open-source-initiative&logoColor=white&label=LICENSE" alt="License: MIT">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/code%20style-black-000000?style=flat-square&logo=python&logoColor=white" alt="Code style: Black">
  <img src="https://img.shields.io/badge/imports-isort-1674b1?style=flat-square&logo=python&logoColor=white" alt="Imports: isort">
  <img src="https://img.shields.io/badge/linting-ruff-261230?style=flat-square&logo=python&logoColor=white" alt="Linting: Ruff">
  <img src="https://img.shields.io/badge/security-CodeQL-purple?style=flat-square&logo=github&logoColor=white" alt="Security: CodeQL">
  <img src="https://img.shields.io/badge/pre--commit-enabled-brightgreen?style=flat-square&logo=pre-commit&logoColor=white" alt="pre-commit enabled">
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/qscg?style=flat-square&logo=pypi&logoColor=white&label=PyPI" alt="PyPI Version">
  <img src="https://img.shields.io/pypi/dm/qscg?style=flat-square&logo=pypi&logoColor=white&label=Downloads" alt="PyPI Downloads">
  <img src="https://img.shields.io/github/stars/mcemkoca/qscg?style=flat-square&logo=github&logoColor=white&label=Stars" alt="GitHub Stars">
  <img src="https://img.shields.io/github/contributors/mcemkoca/qscg?style=flat-square&logo=github&logoColor=white&label=Contributors" alt="Contributors">
  <img src="https://img.shields.io/github/last-commit/mcemkoca/qscg?style=flat-square&logo=git&logoColor=white&label=Last%20Commit" alt="Last Commit">
  <img src="https://img.shields.io/github/repo-size/mcemkoca/qscg?style=flat-square&logo=github&logoColor=white&label=Repo%20Size" alt="Repo Size">
</p>

<p align="center">
  <img src="https://img.shields.io/codecov/c/github/mcemkoca/qscg?style=flat-square&logo=codecov&logoColor=white&label=Coverage" alt="Code Coverage">
  <img src="https://img.shields.io/badge/tests-pytest-blue?style=flat-square&logo=pytest&logoColor=white" alt="Tests: pytest">
  <img src="https://img.shields.io/badge/docs-mkdocs-blue?style=flat-square&logo=read-the-docs&logoColor=white" alt="Documentation">
  <img src="https://img.shields.io/badge/status-stable-success?style=flat-square&logo=checkmarx&logoColor=white" alt="Status: Stable">
</p>

---

## :warning: Quantum Threat is Real

> **NIST has officially published the first three post-quantum cryptography standards in August 2024.**
> The transition to quantum-safe algorithms is no longer optional &mdash; it is a necessity.

| Threat Vector | Affected Cryptography | Quantum Algorithm | Risk Level |
|:---:|:---:|:---:|:---:|
| Key Exchange | RSA, Diffie-Hellman, ECC | Shor's Algorithm | :red_circle: **CRITICAL** |
| Digital Signatures | RSA, ECDSA, EdDSA | Shor's Algorithm | :red_circle: **CRITICAL** |
| Symmetric Encryption | AES-128 | Grover's Algorithm | :yellow_circle: **MODERATE** |
| Hash Functions | SHA-256, SHA-3 | Hidden Subgroup Problem | :green_circle: **LOW** |

QSCG provides a complete, ready-to-use implementation of all three NIST-approved post-quantum standards so you can secure your applications **today**.

---

## :sparkles: Features

- :closed_lock_with_key: **ML-KEM (FIPS 203)** &mdash; Complete NIST-compliant Key Encapsulation
  - ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), ML-KEM-1024 (Level 5)
  - K-PKE + Fujisaki-Okamoto CCA2 transform | NTT-domain polynomial arithmetic
- :memo: **ML-DSA (FIPS 204)** &mdash; Complete Fiat-Shamir with Aborts Digital Signatures
  - ML-DSA-44, ML-DSA-65, ML-DSA-87 parameter sets
  - Power2Round, rejection sampling, hint compression | Complete NTT (q=8380417)
- :hash: **SLH-DSA (FIPS 205)** &mdash; Complete Stateless Hash-Based Signatures
  - WOTS+ chain hashing, FORS Merkle trees, XMSS L-trees, d-layer Hypertree
- :key: **AES-256-GCM** Hybrid Encryption layer for data-at-rest protection
- :computer: **Desktop GUI Application** for interactive cryptographic operations
- :zap: **High Performance** Incomplete NTT (7-layer) + Complete NTT (8-layer), Montgomery form
- :shield: **Constant-Time Operations** branch-free comparison, timing-safe select
- :white_check_mark: **NIST Compliant** domain-separated hash functions (G, H, J, KDF, PRF)
- :package: **Professional Package Structure** `src/qscg/` with 4 modules, 24 files
- :notebook_with_decorative_cover: **Comprehensive Documentation** with NIST spec references
- :gear: **Modular Architecture** algorithm selection at runtime via SecurityLevel enum
- :test_tube: **Full Test Suite** 132+ tests covering all 3 PQC algorithms
- :atom: **Quantum Tunneling** — IBM Quantum integration, QRNG, QKD BB84, Quantum-Safe TLS

---

## :framed_picture: Architecture Diagrams

This repository includes **8 detailed architecture diagrams** in the `diagrams/` directory:

| # | Diagram | Description |
|---|---------|-------------|
| 1 | `01_ml_kem_keygen.png` | ML-KEM Key Generation flow |
| 2 | `02_ml_kem_encaps.png` | ML-KEM Encapsulation/Decapsulation |
| 3 | `03_ml_dsa_sign.png` | ML-DSA Signature Generation & Verification |
| 4 | `04_slh_dsa_tree.png` | SLH-DSA Hash Tree structure |
| 5 | `05_hybrid_encryption.png` | AES-256-GCM Hybrid Encryption scheme |
| 6 | `06_system_architecture.png` | Overall QSCG system architecture |
| 7 | `07_security_levels.png` | NIST Security Level mapping |
| 8 | `08_migration_timeline.png` | Quantum migration roadmap |

```
diagrams/
├── 01_ml_kem_keygen.png
├── 02_ml_kem_encaps.png
├── 03_ml_dsa_sign.png
├── 04_slh_dsa_tree.png
├── 05_hybrid_encryption.png
├── 06_system_architecture.png
├── 07_security_levels.png
└── 08_migration_timeline.png
```

---

## :rocket: Installation

### Prerequisites

- Python 3.9 or newer
- pip 21.0+
- (Optional) virtualenv or conda for isolated environment

### From PyPI (Recommended)

```bash
pip install qscg
```

### From Source

```bash
# Clone the repository
git clone https://github.com/mcemkoca/qscg.git
cd qscg

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install package in development mode
pip install -e .
```

### Verify Installation

```bash
python -c "import qscg; print(qscg.__version__)"
```

### GUI Application

```bash
# Launch the desktop GUI
python src/quantum_safe_gui.py
```

---

## 🚀 Quick Start

### Installation
```bash
pip install -r requirements.txt
```

### CLI Usage

```bash
# Show help
python qscg_v2_1_final.py --help

# Show version
python -c "from qscg.common.constants import __version__; print(__version__)"

# Run all tests
python qscg_v2_1_final.py --test

# ML-KEM key generation
python qscg_v2_1_final.py --kem 3 --encapsulate

# ML-DSA signing
python qscg_v2_1_final.py --dsa 3 --sign "My quantum-safe message"

# SLH-DSA signing
python qscg_v2_1_final.py --slh 3 --slh-sign "Important document"

# AES-256-GCM encryption
python qscg_v2_1_final.py --aes --encrypt "Secret data"

# Analysis
python qscg_v2_1_final.py --analysis
python qscg_v2_1_final.py --nist
python qscg_v2_1_final.py --hndl
```

### Python API Usage

#### 1. ML-KEM Key Encapsulation (FIPS 203) — v3.0.0
```python
from qscg.ml_kem.ml_kem import MLKEM
from qscg.common.constants import SecurityLevel

# Generate keys and encapsulate at Level 3 (recommended)
kem = MLKEM(level=SecurityLevel.LEVEL_3)
ek, dk = kem.KeyGen()

# Encapsulate — produces shared secret + ciphertext
ciphertext, shared_secret = kem.Encaps(ek)
print(f"Ciphertext: {len(ciphertext)} bytes")
print(f"Shared Secret: {shared_secret.hex()[:32]}...")

# Decapsulate — recover shared secret
recovered = kem.Decaps(dk, ciphertext)
assert shared_secret == recovered, "Decapsulation failed!"
print("ML-KEM roundtrip: OK")
```

#### 2. ML-DSA Digital Signature (FIPS 204) — v3.0.0
```python
from qscg.ml_dsa.ml_dsa import MLDSA
from qscg.common.constants import SecurityLevel

# Sign at Level 3 (recommended)
dsa = MLDSA(level=SecurityLevel.LEVEL_3)
pk, sk = dsa.keygen()
print(f"Public Key: {len(pk)} bytes")
print(f"Secret Key: {len(sk)} bytes")

# Sign
message = b"Quantum-safe document"
signature = dsa.sign(sk, message)
print(f"Signature: {len(signature)} bytes")

# Verify
valid = dsa.verify(pk, message, signature)
assert valid, "Signature verification failed!"
print("ML-DSA verify: OK")

# Tamper resistance
invalid = dsa.verify(pk, b"tampered message", signature)
assert not invalid, "Should reject tampered message!"
print("Tamper resistance: OK")
```

#### 3. SLH-DSA Hash-Based Signature (FIPS 205) — v3.0.0
```python
from qscg.slh_dsa.slh_dsa import SLHDSA
from qscg.common.constants import SecurityLevel

# Sign at Level 1 (smallest signatures)
slh = SLHDSA(level=SecurityLevel.LEVEL_1)
pk, sk = slh.keygen()
print(f"Public Key: {len(pk)} bytes")
print(f"Secret Key: {len(sk)} bytes")

# Sign
message = b"Long-term secure document"
sig = slh.sign(message, sk)
print(f"Signature: {len(sig)} bytes")

# Verify
valid = slh.verify(message, sig, pk)
assert valid, "SLH-DSA verification failed!"
print("SLH-DSA verify: OK")
```

#### 4. AES-256-GCM Hybrid Encryption
```python
from qscg_v2_1_final import AES256GCM

# Generate or provide key
key = AES256GCM.generate_key()
aes = AES256GCM(key)

# Encrypt
plaintext = b"Sensitive data"
ciphertext = aes.encrypt(plaintext)
print(f"Encrypted: {len(ciphertext)} bytes")

# Decrypt
decrypted = aes.decrypt(ciphertext)
assert decrypted == plaintext
print(f"Decrypted successfully: {decrypted.decode()}")
```

#### 5. Combined Hybrid Usage
```python
from qscg_v2_1_final import MLKEM, AES256GCM, SecurityLevel

# Step 1: Generate ephemeral PQC key pair
kem = MLKEM(level=SecurityLevel.LEVEL_3)
kp = kem.keygen()

# Step 2: Encapsulate shared secret
ct, shared_secret = kem.encapsulate(kp.public_key)

# Step 3: Use shared secret as AES key
aes = AES256GCM(shared_secret)
message = b"Classified: Quantum attack plan"
encrypted = aes.encrypt(message)

# Step 4: Decrypt using decapsulated secret
recovered_secret = kem.decapsulate(kp.secret_key, ct.ciphertext)
aes2 = AES256GCM(recovered_secret)
decrypted = aes2.decrypt(encrypted)
assert decrypted == message
```

---

## :file_folder: Project Structure

```
qscg/
:handshake:                    # GitHub metadata
├── .github/
│   ├── workflows/            # CI/CD pipelines
│   │   ├── ci.yml            # Main CI (test + lint)
│   │   ├── codeql.yml        # Security analysis
│   │   └── release.yml       # Release automation
│   ├── CODE_OF_CONDUCT.md    # Community guidelines
│   ├── CONTRIBUTING.md       # Contribution guide
│   ├── FUNDING.yml           # Sponsorship info
│   └── SECURITY.md           # Security policy
├── diagrams/                 # Architecture diagrams (8 PNG)
│   ├── 01_ml_kem_keygen.png
│   ├── 02_ml_kem_encaps.png
│   ├── 03_ml_dsa_sign.png
│   ├── 04_slh_dsa_tree.png
│   ├── 05_hybrid_encryption.png
│   ├── 06_system_architecture.png
│   ├── 07_security_levels.png
│   └── 08_migration_timeline.png
├── docs/                     # Documentation
│   ├── api/                  # API reference
│   ├── examples/             # Code examples
│   └── tutorials/            # Step-by-step guides
├── src/
│   └── qscg/                   # Main package (v3.0.0)
│       ├── __init__.py
│       ├── common/               # Core utilities
│       │   ├── __init__.py
│       │   ├── constants.py      # NIST parameters
│       │   ├── hashing.py        # Domain-separated hash (G, H, J, PRF)
│       │   └── utilities.py      # Modular arithmetic
│       ├── ml_kem/               # ML-KEM module (FIPS 203)
│       │   ├── __init__.py
│       │   ├── k_pke.py          # K-PKE (KeyGen/Encrypt/Decrypt)
│       │   ├── ml_kem.py         # Fujisaki-Okamoto CCA2 wrapper
│       │   ├── ntt.py            # Incomplete NTT (q=3329)
│       │   ├── polynomial.py     # R_q ring + PolyVector
│       │   ├── sampling.py       # CBD, Parse, SampleNTT
│       │   └── encode.py         # ByteEncode, Compress
│       ├── ml_dsa/               # ML-DSA module (FIPS 204)
│       │   ├── __init__.py
│       │   ├── ml_dsa.py         # Fiat-Shamir with Aborts
│       │   ├── ntt.py            # Complete NTT (q=8380417)
│       │   ├── polynomial.py     # R_q + Power2Round/Decompose
│       │   ├── sampling.py       # SampleInBall, ExpandA/S/Mask
│       │   └── encode.py         # BitPack, HintBitPack
│       ├── slh_dsa/              # SLH-DSA module (FIPS 205)
│       │   ├── __init__.py
│       │   ├── slh_dsa.py        # Main SLH-DSA class
│       │   ├── wots.py           # WOTS+ chain hashing
│       │   ├── fors.py           # FORS Merkle trees
│       │   ├── xmss.py           # XMSS L-trees
│       │   ├── hypertree.py      # d-layer Hypertree
│       │   └── address.py        # ADRS 32-byte address
│       └── quantum/              # Quantum Computing Integration
│           ├── __init__.py
│           ├── qrng.py           # Quantum Random Number Generator
│           ├── tls_tunnel.py     # Quantum-Safe TLS Tunnel
│           └── qkd_bb84.py       # BB84 QKD Protocol
├── tests/                      # Test suite
│   ├── __init__.py
│   ├── test_mlkem.py           # ML-KEM tests
│   ├── test_mldsa.py           # ML-DSA tests
│   ├── test_slh_dsa.py         # SLH-DSA tests
│   └── test_kat.py             # NIST Known Answer Tests
├── qscg_v2_1_final.py        # Main CLI entry point
├── LICENSE                   # MIT License
├── mkdocs.yml                # Documentation config
├── pyproject.toml            # Project configuration
├── README.md                 # This file
├── requirements.txt          # Python dependencies
└── setup.py                  # Package setup
```

---

## :chart_with_upwards_trend: Algorithm Comparison

<a name="algorithm-comparison"></a>

### Classical vs. Lattice-Based Cryptography

| Property | RSA-2048 | ECDSA (P-256) | **ML-KEM-768** | **ML-DSA-65** | **SLH-DSA-SHA2-128s** |
|:---------|:--------:|:-------------:|:--------------:|:-------------:|:---------------------:|
| **Security Basis** | Integer Factoring | Elliptic Curve Logarithm | **Module-Lattice (MLWE)** | **Module-Lattice (MSIS/MLWE)** | **Hash Function Collision** |
| **NIST Level** | ~2 | ~2 | **3** | **3** | **1** |
| **Public Key Size** | 256 B | 33 B | **1,184 B** | **1,952 B** | **32 B** |
| **Secret Key Size** | 256 B | 32 B | **2,400 B** | **4,032 B** | **64 B** |
| **Ciphertext/Sig Size** | 256 B | 64 B | **1,088 B** | **3,293 B** | **7,856 B** |
| **Speed (ops/sec)** | ~2,000 | ~3,000 | **>50,000** | **>20,000** | **~100** |
| **Quantum Secure?** | :x: **NO** | :x: **NO** | :white_check_mark: **YES** | :white_check_mark: **YES** | :white_check_mark: **YES** |

### NIST Security Levels Explained

| Level | Classical Equivalent | Quantum Resistance | Use Case |
|:-----:|:--------------------:|:------------------:|:---------|
| **1** | AES-128 | Grover-limited | Standard applications |
| **2** | SHA-256/SHA-3-256 | Collision-resistant | High-security applications |
| **3** | AES-192 | Grover-limited | Government, finance, critical infrastructure |
| **4** | SHA-384/SHA-3-384 | Collision-resistant | Long-term confidentiality |
| **5** | AES-256 | Grover-limited | Maximum security, classified data |

---

## :atom_symbol: Quantum Threat Analysis

### Shor's Algorithm (1994)

Threatens all **public-key cryptography** based on:
- Integer factorization (RSA)
- Discrete logarithm (Diffie-Hellman)
- Elliptic curve discrete logarithm (ECDSA, EdDSA)

**Impact**: A sufficiently large quantum computer (~20 million physical qubits estimated) can break RSA-2048 in ~8 hours. All current TLS/SSL handshakes, SSH connections, and digital signatures become insecure.

### Grover's Algorithm (1996)

Provides a **quadratic speedup** for unstructured search:
- Reduces AES-128 security to ~64-bit equivalent
- Reduces AES-192 security to ~96-bit equivalent
- **AES-256 remains secure** (~128-bit equivalent quantum security)

**Mitigation**: Double symmetric key lengths (AES-256 is quantum-safe).

### Hidden Subgroup / Hidden Shift Problems

Affects certain **hash-based** constructions. SLH-DSA's security relies solely on the collision resistance of the underlying hash function (SHA2 or SHAKE), which remains secure against quantum attacks when properly parameterized.

### Harvest Now, Decrypt Later (HNDL)

| Phase | Timeline | Action Required |
|:-----:|:--------:|:----------------|
| **Current** | 2024-2027 | Adversaries are recording encrypted traffic |
| **Near-term** | 2027-2033 | Early quantum computers emerge (CRQC risk) |
| **Critical** | 2033-2038 | Full-scale quantum computers operational |
| **Post-quantum** | 2038+ | All classical PKC considered broken |

> :warning: **Data with long confidentiality requirements must be encrypted with quantum-safe algorithms TODAY.**

---

## :calendar: Migration Timeline

| Date | Milestone | Source |
|:----:|:----------|:-------|
| **Aug 2024** | NIST publishes FIPS 203, 204, 205 | [NIST IR 8547](https://csrc.nist.gov/pubs/ir/8547/final) |
| **2025-2026** | Initial vendor implementations | Industry adoption |
| **Jan 2026** | CNSA 2.0 Timeline: Software/Firmware Signing | [NSA CNSA 2.0](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF) |
| **2027-2029** | Browsers enable PQC by default | Chrome, Firefox, Safari |
| **2028** | CNSA 2.0 Timeline: Web Browsers/Cloud | NSA mandate |
| **2030** | CNSA 2.0 Timeline: Operating Systems | NSA mandate |
| **2033** | CNSA 2.0 Timeline: Full PQC requirement | NSA mandate |
| **2035** | Estimated CRQC emergence (various agencies) | DHS, EU, UK NCSC |
| **2038+** | Classical PKC sunset | Global standards bodies |

### Recommended Migration Strategy

```
Phase 1 (NOW):     Inventory all cryptographic assets
Phase 2 (2025):    Deploy QSCG for new applications
Phase 3 (2026):    Enable hybrid (classic + PQC) modes
Phase 4 (2028):    Full PQC for sensitive data
Phase 5 (2030):    Remove classical algorithms entirely
```

---

## :test_tube: Testing

QSCG includes a comprehensive test suite with NIST Known Answer Tests (KAT) vectors.

### Run All Tests

```bash
# Run the full test suite
pytest tests/ -v --tb=short

# Run with coverage
pytest tests/ -v --cov=qscg --cov-report=term-missing --cov-report=html

# Run specific algorithm tests
pytest tests/test_mlkem.py -v
pytest tests/test_mldsa.py -v
pytest tests/test_slh_dsa.py -v

# Run NIST Known Answer Tests (verifies standard compliance)
pytest tests/test_kat.py -v
```

### Performance Benchmarks

```bash
# Run benchmark suite
python qscg_v2_1_final.py --benchmark

# Output example:
# ML-KEM-512 KeyGen:    25,000 ops/sec
# ML-KEM-768 KeyGen:    18,000 ops/sec
# ML-KEM-1024 KeyGen:   12,000 ops/sec
# ML-DSA-44 Sign:       15,000 ops/sec
# ML-DSA-65 Sign:        8,000 ops/sec
# ML-DSA-85 Sign:        5,000 ops/sec
# SLH-DSA-128s Sign:       150 ops/sec
# SLH-DSA-128s Verify:    8,000 ops/sec
```

### Continuous Integration

All commits are tested via GitHub Actions:
- **Python 3.9/3.10/3.11/3.12/3.13** matrix testing
- **Ubuntu, macOS, Windows** platform coverage
- **CodeQL** security analysis
- **Bandit** SAST scanning
- **Coverage** reporting to Codecov

---

## :handshake: Contributing

We welcome contributions from the community! Please read our [Contributing Guide](.github/CONTRIBUTING.md) for details on:

- Code of Conduct
- Development setup
- Branch naming conventions
- Commit message format (Conventional Commits)
- Pull request process
- Code review guidelines

### Quick Start for Contributors

```bash
# Fork and clone
git clone https://github.com/YOUR_USERNAME/qscg.git
cd qscg

# Setup development environment
pip install -r requirements.txt
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install

# Create a branch
git checkout -b feat/your-feature-name

# Make changes and test
pytest tests/ -v

# Commit and push
git commit -m "feat: add your feature"
git push origin feat/your-feature-name
```

### Contributors

<a href="https://github.com/mcemkoca/qscg/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=mcemkoca/qscg" alt="Contributors" />
</a>

---

## :shield: Security

### Security Policy

Please review our [Security Policy](.github/SECURITY.md) for:
- Supported versions
- Vulnerability reporting process
- Disclosure timeline
- Security advisories

### Reporting Vulnerabilities

If you discover a security vulnerability, please **DO NOT** open a public issue. Instead:

1. Email **security@qscg.dev** (or open a private security advisory on GitHub)
2. Provide detailed description and reproduction steps
3. Allow 90 days for remediation before public disclosure

### Security Features

- Constant-time implementations to prevent timing attacks
- Side-channel resistant memory handling
- Secure random number generation via `os.urandom` / `secrets`
- Input validation on all public APIs
- Automated security scanning via CodeQL and Bandit

---

## :page_with_curl: Code of Conduct

This project adheres to a [Code of Conduct](.github/CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## :scroll: License

```
MIT License

Copyright (c) 2026 Mehmet Cem Koca (mcemkoca)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Full license text available in [LICENSE](LICENSE).

---

## :pray: Acknowledgments

This project builds upon the groundbreaking work of many researchers and organizations:

- **[NIST](https://www.nist.gov/)** &mdash; For leading the Post-Quantum Cryptography Standardization process and publishing FIPS 203/204/205
- **[CRYSTALS Team](https://pq-crystals.org/)** &mdash; For developing the CRYSTALS-Kyber (ML-KEM) and CRYSTALS-Dilithium (ML-DSA) algorithms
- **[SPHINCS+ Team](https://sphincs.org/)** &mdash; For developing the SPHINCS+ (SLH-DSA) hash-based signature scheme
- **[pqclean](https://github.com/PQClean/PQClean)** &mdash; For clean, portable reference implementations
- **[Open Quantum Safe](https://openquantumsafe.org/)** &mdash; For the OpenSSL integration and testing framework
- **[EU Horizon Programme](https://research-and-innovation.ec.europa.eu/index_en)** &mdash; For funding post-quantum research initiatives
- The entire **post-quantum cryptography research community** for their tireless work securing our digital future

---

## :email: Contact & Support

| Channel | Link | Purpose |
|:--------|:-----|:--------|
| **GitHub Issues** | [github.com/mcemkoca/qscg/issues](https://github.com/mcemkoca/qscg/issues) | Bug reports, feature requests |
| **GitHub Discussions** | [github.com/mcemkoca/qscg/discussions](https://github.com/mcemkoca/qscg/discussions) | Q&A, ideas, community chat |
| **Security Advisory** | [Private Reporting](https://github.com/mcemkoca/qscg/security/advisories) | Vulnerability reports |
| **Wiki** | [github.com/mcemkoca/qscg/wiki](https://github.com/mcemkoca/qscg/wiki) | Full documentation |
| **Author** | [@mcemkoca](https://github.com/mcemkoca) — M.Cem Koca {Deuterium12} | Direct contact |

---

## 📚 Wiki Documentation

Comprehensive documentation is available in the [GitHub Wiki](https://github.com/mcemkoca/qscg/wiki) and [`docs/wiki`](docs/wiki/) directory:

| Wiki Page | Description |
|:----------|:------------|
| **[Home](docs/wiki/Home.md)** | Project overview, quick start, navigation |
| **[Algorithms & Standards](docs/wiki/Algorithms-and-Standards.md)** | ML-KEM, ML-DSA, SLH-DSA deep dives |
| **[API Documentation](docs/wiki/API-Documentation.md)** | Complete Python API reference with examples |
| **[CLI Usage](docs/wiki/CLI-Usage.md)** | Command-line interface guide |
| **[Quantum Threat Analysis](docs/wiki/Quantum-Threat-Analysis.md)** | HNDL, migration timeline, sector guides |

---

<div align="center">

**:star: Star this repository if it helps you secure your applications against quantum threats!**

**Built with ❤️ by [M.Cem Koca {Deuterium12}](https://github.com/mcemkoca)**

</div>
