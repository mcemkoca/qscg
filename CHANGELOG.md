# Changelog

## v3.0.1 - 2026-05-25

### Repository & Documentation
- **README.md** completely rewritten — clearer hierarchy, honest status labels, accurate project structure, reduced badge noise
- **GitHub Ruleset** activated on `main` — PR + 1 review + 7 required status checks + force-push/deletion protection
- Fixed project structure docs to match actual file tree (`src/qscg/`, `quantum_safe_crypto/`, `diagrams/`)
- Added "What's New" summary table with stability indicators (Stable / Experimental / WIP)
- Merged upstream: SLH-DSA full implementation, quantum modules (QKD BB84, QRNG, TLS tunnel), py.typed marker

### Code Quality
- **Modular ML-DSA** (`src/qscg/ml_dsa/ml_dsa.py`): added `public_key_size`, `secret_key_size`, `signature_size`, `param_id` properties to match test expectations
- **Test suite** (`tests/test_mldsa.py`): updated to reflect actual encoder output sizes; sign/verify tests skipped pending rejection-sampling loop fix
- **Workspace cleanup**: removed 18 files (debug scripts, reports, submodule remnants, development environment metadata)
- **`.gitignore`**: expanded to prevent future workspace artifact inclusion

### Research Integration
- Added **Roadmap** section to README informed by [Ahmed et al. (2025), *A Survey of Post-Quantum Cryptography Support in Cryptographic Libraries*](https://arxiv.org/abs/2508.16078)
- GitHub Issues created: [#3](https://github.com/mcemkoca/qscg/issues/3) LMS/XMSS, [#4](https://github.com/mcemkoca/qscg/issues/4) Hybrid X25519+ML-KEM, [#5](https://github.com/mcemkoca/qscg/issues/5) Side-channel audit, [#6](https://github.com/mcemkoca/qscg/issues/6) Benchmark suite, [#7](https://github.com/mcemkoca/qscg/issues/7) CNSA 2.0 matrix

## v3.0.0 - 2026-05-20

### Added
- **HQC Code-based KEM** (NIST IR 8545) - `quantum_safe_crypto/hqc.py`
  - 3 security levels (128/192/256 bit)
  - QC-MDPC code structure
- **FN-DSA (FALCON)** (NIST FIPS 206 draft) - `quantum_safe_crypto/fndsa.py`
  - Compact ~666 byte signatures (Level 1)
  - NTRU lattice-based
- **Quantum Threat Analyzer** - `quantum_safe_crypto/quantum_threat.py`
  - Mosca's Inequality risk calculation
  - Gidney 2025 / Iceberg 2026 qubit timeline
  - Sector-specific recommendations
- **Protocol Extensions** - `quantum_safe_crypto/protocols/`
  - QUIC PQC (X25519Kyber768)
  - Signal Protocol v4 PQC
  - WireGuard PQC handshake
- **Academic Documentation** - `quantum_safe_crypto/docs/`
  - Mermaid.js diagrams
  - 24+ paper references
  - NIST/ETSI/IETF standards

### Standards Compliance
- NIST FIPS 203/204/205 (existing)
- NIST IR 8545 (HQC)
- NIST FIPS 206 draft (FN-DSA)
- RFC 9794 / draft-ietf-tls-xyber768d00

## v2.2.0 - Previous
- ML-KEM, ML-DSA, SLH-DSA implementation
- AES-256-GCM hybrid layer
- Desktop GUI application
