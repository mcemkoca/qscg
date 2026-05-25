# Changelog

## v3.0.1 - 2026-05-25

### Repository & Documentation
- **README.md** completely rewritten — clearer hierarchy, honest status labels, accurate project structure, reduced badge noise
- **GitHub Ruleset** activated on `main` — PR + 1 review + 7 required status checks + force-push/deletion protection
- Fixed project structure docs to match actual file tree (`src/qscg/`, `quantum_safe_crypto/`, `diagrams/`)
- Added "What's New" summary table with stability indicators (Stable / Experimental / WIP)
- Merged upstream: SLH-DSA full implementation, quantum modules (QKD BB84, QRNG, TLS tunnel), py.typed marker

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
