<div align="center">

<img src="https://raw.githubusercontent.com/mcemkoca/qscg/main/logo.png" alt="QSCG Logo" width="160">

# QSCG — Quantum-Safe Cryptography GitHub

**A Python toolkit for post-quantum cryptography — because RSA's days are numbered.**

I started this project in late 2024, right after NIST published the first three PQC standards (FIPS 203, 204, 205). At the time, almost no Python library had a clean, from-scratch implementation of ML-KEM, ML-DSA, and SLH-DSA that you could actually read and learn from. Most options were thin wrappers around C code. I wanted something different: a codebase where you can trace every polynomial multiplication, every NTT butterfly, every hash invocation, and understand *why* it works.

Three years later, QSCG is a working reference implementation, a testbed for hybrid protocols, and (hopefully) a decent starting point for anyone who wants to understand lattice-based cryptography without drowning in assembly or opaque optimized libraries.

[![NIST FIPS 203](https://img.shields.io/badge/NIST-FIPS%20203-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/203/final)
[![NIST FIPS 204](https://img.shields.io/badge/NIST-FIPS%20204-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/204/final)
[![NIST FIPS 205](https://img.shields.io/badge/NIST-FIPS%20205-blue?style=flat-square&logo=gnuprivacyguard)](https://csrc.nist.gov/pubs/fips/205/final)

</div>

<p align="center">
  <a href="#whats-new">What's New</a> •
  <a href="#roadmap">Roadmap</a> •
  <a href="#installation">Install</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#python-api">API</a> •
  <a href="#project-structure">Structure</a> •
  <a href="#testing">Testing</a> •
  <a href="#contributing">Contributing</a>
</p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/mcemkoca/qscg/ci.yml?branch=main&style=flat-square&logo=githubactions&logoColor=white&label=CI" alt="CI Status">
  <img src="https://img.shields.io/badge/python-3.9%2B-blue?style=flat-square&logo=python&logoColor=white" alt="Python 3.9+">
  <img src="https://img.shields.io/github/license/mcemkoca/qscg?style=flat-square&logo=open-source-initiative&logoColor=white" alt="MIT License">
  <img src="https://img.shields.io/badge/tests-pytest-blue?style=flat-square&logo=pytest&logoColor=white" alt="Tests: pytest">
  <img src="https://img.shields.io/badge/CNSA%202.0-partial-yellow?style=flat-square&logo=nsa&logoColor=white" alt="CNSA 2.0: Partial">
</p>

---

## 🆕 What's New

> **Latest update — v3.0.0 (May 2026)**

| Feature | Status | Description |
|:--------|:------:|:------------|
| **ML-KEM (FIPS 203)** | ✅ Stable | Module-lattice KEM — key generation, encapsulation, decapsulation |
| **ML-DSA (FIPS 204)** | ✅ Stable | Module-lattice signatures — sign & verify with NIST parameter sets |
| **SLH-DSA (FIPS 205)** | 🔄 WIP | Stateless hash-based signatures — core structures implemented |
| **AES-256-GCM Hybrid** | ✅ Stable | Symmetric layer for data-at-rest and hybrid encryption |
| **HQC (NIST IR 8545)** | 🧪 Experimental | Code-based KEM — educational implementation |
| **FN-DSA / FALCON** | 🧪 Experimental | NTRU lattice compact signatures — research prototype |
| **Quantum Threat Analyzer** | ✅ Available | Mosca's Inequality, sector-specific migration guidance |
| **Protocol Extensions** | 🧪 Experimental | QUIC PQC, Signal v4, WireGuard handshake sketches |
| **Branch Ruleset** | ✅ Active | `main` protected — PR + review + status checks required |

**Recent changes:**
- `main` branch now protected via GitHub Ruleset (PR + 1 review + 7 CI checks required)
- Modular package structure under `src/qscg/` (ML-KEM, ML-DSA, SLH-DSA, common utilities)
- CLI entry point: `qscg_v2_1_final.py` — single-file reference + command interface
- 9 architecture diagrams in `diagrams/`
- Wiki docs: `docs/wiki/` (Algorithms, API, CLI, Threat Analysis)

---

## 🗺️ Roadmap

> Informed by [Ahmed et al. (2025), *A Survey of Post-Quantum Cryptography Support in Cryptographic Libraries*](https://arxiv.org/abs/2508.16078)

| Milestone | Target | Issue | Description |
|:----------|:------:|:-----:|:------------|
| **LMS / XMSS** | Q3 2026 | [#3](https://github.com/mcemkoca/qscg/issues/3) | Stateful hash signatures (SP 800-208) for firmware signing — critical for CNSA 2.0 compliance |
| **Hybrid X25519+ML-KEM** | Q3 2026 | [#4](https://github.com/mcemkoca/qscg/issues/4) | Production-ready hybrid key exchange (IETF draft) for TLS 1.3 and HNDL protection |
| **Side-channel Audit** | Q2 2026 | [#5](https://github.com/mcemkoca/qscg/issues/5) | KyberSlash-style timing attack mitigation; constant-time review of ML-KEM decapsulation |
| **Benchmark Suite** | Q3 2026 | [#6](https://github.com/mcemkoca/qscg/issues/6) | Standardized ops/sec and latency benchmarks vs wolfSSL, Bouncy Castle, Botan |
| **CNSA 2.0 Matrix** | Q2 2026 | [#7](https://github.com/mcemkoca/qscg/issues/7) | Compliance documentation mapping QSCG algorithms to NSA CNSA 2.0 requirements |
| **ML-DSA Modular Fix** | Q2 2026 | — | Fix rejection-sampling loop in `src/qscg/ml_dsa/ml_dsa.py` sign/verify |
| **FN-DSA / FALCON** | Q4 2026 | — | NTRU lattice compact signatures (smaller sigs than ML-DSA) |
| **Classic McEliece** | 2027 | — | Code-based KEM with very large public keys (conservative alternative) |

**Government timeline alignment (NSM-10 / CNSA 2.0):**
- **2025** → Software/firmware signing with PQC (LMS/XMSS target)
- **2026** → Traditional network equipment transition (hybrid TLS target)
- **2035** → Full quantum-resistant migration

---

## ⚠️ Why Post-Quantum Cryptography Matters

> NIST published the first three PQC standards in **August 2024**. The transition is no longer optional.

| Threat | Classical Crypto | Quantum Algorithm | Risk |
|:-------|:----------------|:------------------|:----:|
| Key Exchange | RSA, DH, ECC | Shor's Algorithm | 🔴 Critical |
| Digital Signatures | RSA, ECDSA, EdDSA | Shor's Algorithm | 🔴 Critical |
| Symmetric Encryption | AES-128 | Grover's Algorithm | 🟡 Moderate |
| Hash Functions | SHA-256, SHA-3 | Hidden Subgroup | 🟢 Low |

**Harvest Now, Decrypt Later (HNDL):** Adversaries are already recording encrypted traffic today to decrypt once quantum computers become available. Data with long confidentiality requirements must be protected **now**.

---

## 🚀 Installation

**Requirements:** Python 3.9+

```bash
# Clone
git clone https://github.com/mcemkoca/qscg.git
cd qscg

# Install dependencies
pip install -r requirements.txt

# Or install in editable mode
pip install -e .
```

**Verify:**
```bash
python -c "import qscg; print(qscg.__version__)"
python qscg_v2_1_final.py --version
```

---

## ⚡ Quick Start

### CLI

```bash
# Show all options
python qscg_v2_1_final.py --help

# Run self-tests
python qscg_v2_1_final.py --test

# ML-KEM key encapsulation
python qscg_v2_1_final.py --kem 3 --encapsulate

# ML-DSA sign a message
python qscg_v2_1_final.py --dsa 3 --sign "My quantum-safe message"

# Quantum threat analysis
python qscg_v2_1_final.py --analysis
python qscg_v2_1_final.py --nist
```

### Python API

```python
from qscg_v2_1_final import MLKEM, MLDSA, AES256GCM, SecurityLevel, setup_logging

setup_logging()

# --- ML-KEM (FIPS 203) ---
kem = MLKEM(level=SecurityLevel.LEVEL_3)
kp = kem.keygen()
ct, secret = kem.encapsulate(kp.public_key)
recovered = kem.decapsulate(kp.secret_key, ct.ciphertext)
assert secret == recovered

# --- ML-DSA (FIPS 204) ---
dsa = MLDSA(level=SecurityLevel.LEVEL_3)
keys = dsa.keygen()
sig = dsa.sign(keys.secret_key, b"Important document")
assert dsa.verify(keys.public_key, b"Important document", sig.signature)

# --- AES-256-GCM Hybrid ---
key = AES256GCM.generate_key()
aes = AES256GCM(key)
ciphertext = aes.encrypt(b"Classified data")
plaintext = aes.decrypt(ciphertext)
```

See [`docs/wiki/API-Documentation.md`](docs/wiki/API-Documentation.md) for the full API reference.

---

## 🏗️ Project Structure

```
qscg/
├── .github/
│   └── workflows/            # CI: test matrix, code quality, security scan
├── diagrams/                 # 9 architecture & visualization PNGs
│   ├── diagram1_overview.png
│   ├── diagram2_mlkem_detailed.png
│   ├── diagram3_ntt_visualization.png
│   ├── diagram4_hybrid_crypto.png
│   ├── diagram5_quantum_resistance.png
│   ├── diagram6_comparison.png
│   ├── diagram7_performance_charts.png
│   ├── diagram8_architecture.png
│   └── gui_v3_preview.png
├── docs/
│   └── wiki/                 # Markdown wiki pages
│       ├── Home.md
│       ├── Algorithms-and-Standards.md
│       ├── API-Documentation.md
│       ├── CLI-Usage.md
│       └── Quantum-Threat-Analysis.md
├── src/
│   └── qscg/                 # Modular package (installable)
│       ├── common/           # constants, hashing, utilities
│       ├── ml_kem/           # FIPS 203 implementation
│       ├── ml_dsa/           # FIPS 204 implementation
│       ├── slh_dsa/          # FIPS 205 structures
│       └── __init__.py
├── quantum_safe_crypto/      # v3.0 experimental / research modules
│   ├── hqc.py, hqc_v2.py     # HQC code-based KEM
│   ├── fndsa.py              # FN-DSA / FALCON signatures
│   ├── ntru_ntt.py           # NTRU lattice utilities
│   ├── quantum_threat.py     # Risk analysis toolkit
│   ├── protocols/            # QUIC / Signal / WireGuard sketches
│   └── docs/                 # Academic references
├── tests/                    # pytest suite
│   ├── test_qscg.py          # Core algorithm tests
│   ├── test_mldsa.py         # ML-DSA specific
│   ├── test_hqc.py           # HQC tests
│   ├── test_fndsa.py         # FN-DSA tests
│   ├── test_protocols.py     # Protocol extension tests
│   └── test_quantum_threat.py
├── qscg_v2_1_final.py       # Main CLI & single-file reference
├── pyproject.toml            # Package metadata (v3.0.0)
├── requirements.txt
├── setup.py
├── LICENSE                   # MIT
└── README.md                 # This file
```

---

## 📊 Algorithm Comparison

| Algorithm | Standard | Security Basis | NIST Level | Public Key | Signature / Ciphertext | Speed | Quantum-Safe |
|:----------|:---------|:-------------|:----------:|:----------:|:--------------------:|:-----:|:------------:|
| **ML-KEM-768** | FIPS 203 | Module-Lattice (MLWE) | 3 | 1,184 B | 1,088 B | >50K ops/s | ✅ |
| **ML-DSA-65** | FIPS 204 | Module-Lattice (MSIS) | 3 | 1,952 B | 3,293 B | >20K ops/s | ✅ |
| **SLH-DSA-128s** | FIPS 205 | Hash (SHA2/SHAKE) | 1 | 32 B | 7,856 B | ~100 ops/s | ✅ |
| RSA-2048 | PKCS#1 | Integer Factoring | ~2 | 256 B | 256 B | ~2K ops/s | ❌ |
| ECDSA (P-256) | — | EC Discrete Log | ~2 | 33 B | 64 B | ~3K ops/s | ❌ |

---

## 🧪 Testing

```bash
# Run all tests
pytest tests/ -v

# Specific modules
pytest tests/test_qscg.py -v
pytest tests/test_mldsa.py -v

# NIST compliance check (KAT vectors — when available)
pytest tests/test_kat.py -v

# Benchmark
python qscg_v2_1_final.py --benchmark
```

**CI Matrix:** Python 3.9–3.11 × Ubuntu, plus CodeQL + Bandit + pip-audit.

---

## 🤝 Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for:
- Branch naming (`feature/`, `bugfix/`, `docs/`, etc.)
- Conventional Commits format
- PR process (ruleset-enforced: 1 review + passing CI)
- Code style (Black, isort, flake8)

**Quick contributor flow:**
```bash
git checkout -b feature/your-feature
# ... edit ...
pytest tests/ -v
pre-commit run --all-files   # if installed
git commit -m "feat(scope): description"
git push origin feature/your-feature
# Open PR — 1 review + all checks green required
```

---

## 🛡️ Security

- Constant-time operations where applicable
- Secure random via `secrets` / `os.urandom`
- Input validation on all public APIs
- Automated scanning: CodeQL + Bandit + pip-audit

Report vulnerabilities privately: [GitHub Security Advisories](https://github.com/mcemkoca/qscg/security/advisories)

---

## 📜 License

MIT License — see [`LICENSE`](LICENSE).

---

## 🙏 Acknowledgments

- **[NIST](https://www.nist.gov/)** — PQC Standardization Process
- **[CRYSTALS Team](https://pq-crystals.org/)** — Kyber (ML-KEM) & Dilithium (ML-DSA)
- **[SPHINCS+ Team](https://sphincs.org/)** — Hash-based signatures (SLH-DSA)
- **[PQClean](https://github.com/PQClean/PQClean)** — Portable reference implementations
- **[Open Quantum Safe](https://openquantumsafe.org/)** — OpenSSL integration & testing

---

<div align="center">

**Crafted by [deuterium12](https://github.com/mcemkoca) (M. Cem Koca)**

If you found this useful, a ⭐ on GitHub is the best tip jar I know of. If something's broken or unclear, open an issue — I read every single one.

</div>
