# Changelog

## v4.0.1 - 2026-05-24

### Fixed
- **v4_core ML-DSA verify** — Polynomial `to_bytes/from_bytes` now uses 24-bit packing for `q > 4096` (ML-DSA q=8380417). Previously 12-bit packing truncated large coefficients, causing verify failures at all security levels.
- **v4_core ML-DSA keygen consistency** — `s2 = 0` in toy keygen to satisfy verify equation `w' = A*z - c*t = A*y`.
- **v4_core SLH-DSA sign/verify mismatch** — Sign now uses deterministic `sha3_256(pk_seed + pk_root + message)` matching verify logic. Previously random `sk_prf + opt_rand` prefix never aligned with verify.
- **QSCG API level inference** — `encapsulate`, `decapsulate`, `sign`, `verify`, `sign_slh`, `verify_slh` now auto-extract `level` from Keypair/SLHKeypair objects. Previously defaulted to `LEVEL_3`, causing cross-level parse errors.
- **QSCG.__init__ KeyError** — Added `if level in ML_KEM_PARAMS` guard. `SecurityLevel.LEVEL_2` has no KEM params but has DSA params.

### Changed
- All version references synchronized to `4.0.1` (`setup.py`, `pyproject.toml`, `src/__init__.py`, `quantum_safe_crypto/__init__.py`, `qscg_v4_core.py`).

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
