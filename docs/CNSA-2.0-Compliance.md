# CNSA 2.0 Compliance Matrix

> **NSA Commercial National Security Algorithm Suite 2.0** — QSCG algorithm coverage as of May 2026
>
> Reference: [NSA CNSA 2.0 Fact Sheet](https://media.defense.gov/2022/Sep/07/2003071834/-1/-1/0/CSA_CNSA_2.0_ALGORITHMS_.PDF)

---

## Algorithm Requirements

| CNSA 2.0 Category | Required Algorithm | QSCG Implementation | Status | Notes |
|:------------------|:-------------------|:--------------------|:------:|:------|
| **Key Exchange (Asymmetric)** | ML-KEM (FIPS 203) | `MLKEM` (L1/L3/L5) | ✅ **Ready** | All 3 parameter sets |
| **Digital Signature (Asymmetric)** | ML-DSA (FIPS 204) | `MLDSA` (L1/L3/L5) | ✅ **Ready** | Monolithic passes all tests |
| **Digital Signature (Alternative)** | SLH-DSA (FIPS 205) | `SLHDSA` (L1/L3/L5) | ⚠️ **Partial** | Core structures ready, full sign/verify pending |
| **Digital Signature (Firmware)** | LMS / XMSS (SP 800-208) | — | ❌ **Missing** | [#3](https://github.com/mcemkoca/qscg/issues/3) |
| **Symmetric Encryption** | AES-256-GCM | `AES256GCM` | ✅ **Ready** | GCM mode, AAD support |
| **Symmetric Encryption (Classical)** | AES-128-GCM | `AES256GCM` (fallback) | ⚠️ **Not exact** | Only AES-256 exposed; AES-128 not implemented |
| **Hash Function** | SHA-384 / SHA-512 | `hashlib.sha384/512` | ✅ **Ready** | Via Python standard library |
| **Digital Signature (Classical)** | ECDSA P-384 / RSA 3072 | — | ❌ **Out of scope** | Classical algorithms, not PQC |

---

## Federal Migration Timeline

| Year | Mandate | QSCG Readiness |
|:----:|:--------|:---------------|
| **2025** | Software & firmware signing → **PQC only** | ⚠️ **Partial** — ML-DSA ready, LMS/XMSS missing for firmware |
| **2026** | Traditional network equipment → **hybrid or PQC** | ⚠️ **Partial** — ML-KEM ready, hybrid X25519+ML-KEM missing [#4](https://github.com/mcemkoca/qscg/issues/4) |
| **2030** | Web browsers, cloud services, OT → **PQC** | ⚠️ **Partial** — Core algorithms ready, protocol integration WIP |
| **2033** | Full quantum-resistant migration | 🎯 **Target** — all algorithms + benchmarks + side-channel audit |

---

## Gap Analysis

| Gap | Impact | Resolution Target | Issue |
|:----|:-------|:-----------------|:------|
| LMS / XMSS missing | Blocks firmware signing compliance | Q3 2026 | [#3](https://github.com/mcemkoca/qscg/issues/3) |
| Hybrid X25519+ML-KEM missing | Blocks network equipment TLS compliance | Q3 2026 | [#4](https://github.com/mcemkoca/qscg/issues/4) |
| Side-channel audit pending | Security risk for production use | Q2 2026 | [#5](https://github.com/mcemkoca/qscg/issues/5) |
| Benchmark suite missing | Cannot verify performance claims | Q3 2026 | [#6](https://github.com/mcemkoca/qscg/issues/6) |
| No formal certification path | Cannot claim "CNSA 2.0 Certified" | TBD | — |

---

## PQC-Only Mode Recommendation

For environments that can drop classical cryptography entirely (internal government networks, air-gapped systems):

```python
from qscg_v2_1_final import MLKEM, MLDSA, AES256GCM, SecurityLevel

# Key exchange: ML-KEM-768 (CNSA 2.0 recommended)
kem = MLKEM(level=SecurityLevel.LEVEL_3)

# Signatures: ML-DSA-65 (CNSA 2.0 recommended)
dsa = MLDSA(level=SecurityLevel.LEVEL_3)

# Symmetric: AES-256-GCM (already quantum-safe via key size)
key = AES256GCM.generate_key()
```

> **Note:** CNSA 2.0 recommends ML-KEM-768 and ML-DSA-65 for most use cases. Level 5 (ML-KEM-1024 / ML-DSA-87) is reserved for especially sensitive data.

---

## Hybrid Mode Recommendation

For internet-facing systems during transition (recommended until 2033):

> Hybrid mode combines classical + PQC for defense-in-depth. QSCG does not yet have a production hybrid implementation. Track progress in [#4](https://github.com/mcemkoca/qscg/issues/4).

---

*Last updated: 2026-05-25 — QSCG v3.0.0*
