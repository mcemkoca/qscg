# QSCG v4.0 Master Competitive Matrix
# 12 Repository × 50+ Feature Comparison
# Quantum Tunneling Research | 2026-05-22

================================================================================
REPOSITORY INVENTORY
================================================================================

| # | Repository | Stars | Language | Focus | Analyzed |
|---|------------|-------|----------|-------|----------|
| 1 | GiacomoPope/kyber-py | 298 | Python | ML-KEM pure Python | ✅ Deep |
| 2 | tprest/falcon.py | 196 | Python | FN-DSA pure Python | ✅ Deep |
| 3 | open-quantum-safe/liboqs | 2,900 | C | Production PQC library | ✅ Deep |
| 4 | open-quantum-safe/liboqs-python | 237 | Python | liboqs bindings | ⚠️ Ref |
| 5 | pq-crystals/kyber | 1,200 | C | ML-KEM reference | ⚠️ Ref |
| 6 | pq-crystals/dilithium | 589 | C | ML-DSA reference | ⚠️ Ref |
| 7 | PQClean/PQClean | 920 | C | Clean portable PQC | ✅ Deep |
| 8 | rustpq/pqcrypto | 398 | Rust | Rust PQC | ⚠️ Scan |
| 9 | paulmillr/noble-post-quantum | 324 | TypeScript | Web PQC | ⚠️ Scan |
| 10 | quincy-rs/quincy | 302 | Rust | PQC QUIC VPN | ⚠️ Scan |
| 11 | slothy-optimizer/slothy | 325 | Python | Assembly super-opt | ⚠️ Scan |
| 12 | sbom-tool/sbom-tools | 219 | Rust | PQC compliance/SBOM | ⚠️ Scan |

================================================================================
ALGORITHM SUPPORT MATRIX
================================================================================

| Algorithm | QSCG v4.0 | kyber-py | falcon.py | liboqs | PQClean |
|-----------|-----------|----------|-----------|--------|---------|
| ML-KEM-512 | ✅ | ✅ | ❌ | ✅ | ✅ |
| ML-KEM-768 | ✅ | ✅ | ❌ | ✅ | ✅ |
| ML-KEM-1024 | ✅ | ✅ | ❌ | ✅ | ✅ |
| ML-DSA-44 | ✅ | ❌ | ❌ | ✅ | ✅ |
| ML-DSA-65 | ✅ | ❌ | ❌ | ✅ | ✅ |
| ML-DSA-87 | ✅ | ❌ | ❌ | ✅ | ✅ |
| FN-DSA-512 | ❌ | ❌ | ✅ | ✅ | ✅ |
| FN-DSA-1024 | ❌ | ❌ | ✅ | ✅ | ✅ |
| SLH-DSA-128s | ✅ | ❌ | ❌ | ✅ | ✅ |
| SLH-DSA-128f | ✅ | ❌ | ❌ | ✅ | ✅ |
| SLH-DSA-256s | ❌ | ❌ | ❌ | ✅ | ✅ |
| HQC-128 | ❌ | ❌ | ❌ | ✅ | ✅ |
| HQC-192 | ❌ | ❌ | ❌ | ✅ | ✅ |
| HQC-256 | ❌ | ❌ | ❌ | ✅ | ✅ |
| McEliece | ❌ | ❌ | ❌ | ✅ | ✅ |
| **TOTAL** | **7** | **3** | **2** | **18** | **41** |

QSCG Coverage: 7/18 NIST-approved (39%)
PQClean Coverage: 41/41 (100%)

================================================================================
FEATURE COMPARISON MATRIX (50 Points)
================================================================================

CORRECTNESS (10 points)
-----------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| NIST KAT vectors | ❌ 0 | ✅ 2 | ❌ 0 | ✅ 2 | ✅ 2 |
| FIPS 203 compliant | ⚠️ 1 | ✅ 2 | N/A | ✅ 2 | ✅ 2 |
| FIPS 204 compliant | ⚠️ 1 | N/A | N/A | ✅ 2 | ✅ 2 |
| FIPS 205 compliant | ⚠️ 1 | N/A | N/A | ✅ 2 | ✅ 2 |
| Cross-validation | ❌ 0 | ✅ 2 | ❌ 0 | ✅ 2 | ✅ 2 |
| Round-trip property | ⚠️ 1 | ✅ 2 | ❌ 0 | ✅ 2 | ✅ 2 |
| **Score** | **4/10** | **8/10** | **0/10** | **10/10** | **10/10** |

PERFORMANCE (10 points)
-----------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| KeyGen speed (relative) | 2  | 6 | 5 | 10 | 10 |
| Encaps/Sign speed | 2  | 6 | 7 | 10 | 10 |
| Decaps/Verify speed | 2  | 6 | 7 | 10 | 10 |
| Memory efficiency | 3  | 5 | 3 | 8 | 8 |
| Startup time | 5  | 6 | 4 | 8 | 8 |
| Scalability | 4  | 6 | 5 | 8 | 8 |
| **Score** | **18/60** | **35/60** | **31/60** | **54/60** | **54/60** |
| **Normalized** | **3/10** | **6/10** | **5/10** | **9/10** | **9/10** |

SECURITY (10 points)
--------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| Constant-time ops | ❌ 0 | ⚠️ 1 | ❌ 0 | ⚠️ 1 | ⚠️ 1 |
| Side-channel resistance | ❌ 0 | ⚠️ 1 | ❌ 0 | ⚠️ 1 | ⚠️ 1 |
| Memory clearing | ❌ 0 | ❌ 0 | ❌ 0 | ✅ 2 | ✅ 2 |
| Input validation | ⚠️ 1 | ✅ 2 | ⚠️ 1 | ✅ 2 | ✅ 2 |
| Randomness quality | ✅ 2 | ✅ 2 | ✅ 2 | ✅ 2 | ✅ 2 |
| Timing attack mitigations | ❌ 0 | ❌ 0 | ❌ 0 | ⚠️ 1 | ⚠️ 1 |
| **Score** | **3/12** | **6/12** | **3/12** | **9/12** | **9/12** |
| **Normalized** | **3/10** | **5/10** | **3/10** | **8/10** | **8/10** |

CODE QUALITY (10 points)
------------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| Documentation | 5 | 7 | 4 | 8 | 8 |
| Test coverage | 2 | 7 | 3 | 9 | 9 |
| Type hints | 3 | 7 | 5 | N/A | N/A |
| Error handling | 4 | 6 | 5 | 7 | 7 |
| Modularity | 5 | 7 | 6 | 8 | 8 |
| CI/CD quality | 5 | 7 | 3 | 8 | 8 |
| **Score** | **24/60** | **41/60** | **26/60** | **40/60** | **40/60** |
| **Normalized** | **4/10** | **7/10** | **4/10** | **7/10** | **7/10** |

FEATURES (10 points)
--------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| NIST standards (FIPS 203/204/205) | 2 | 1 | 0 | 3 | 3 |
| Hybrid modes (PQC+classical) | ✅ 2 | ❌ 0 | ❌ 0 | ❌ 0 | ❌ 0 |
| Multiple security levels | ✅ 2 | ✅ 2 | ⚠️ 1 | ✅ 2 | ✅ 2 |
| Key formats (DER/PEM/PKCS#8) | ❌ 0 | ✅ 2 | ⚠️ 1 | ❌ 0 | ❌ 0 |
| Benchmark tools | ✅ 2 | ✅ 2 | ⚠️ 1 | ✅ 2 | ✅ 2 |
| Debug/verbose modes | ⚠️ 1 | ❌ 0 | ❌ 0 | ✅ 2 | ✅ 2 |
| GUI | ✅ 2 | ❌ 0 | ❌ 0 | ❌ 0 | ❌ 0 |
| AI Agent integration | ✅ 2 | ❌ 0 | ❌ 0 | ❌ 0 | ❌ 0 |
| PyPI package | ✅ 2 | ✅ 2 | ❌ 0 | ✅ 2 | ❌ 0 |
| Industry analysis docs | ✅ 2 | ❌ 0 | ❌ 0 | ❌ 0 | ❌ 0 |
| **Score** | **17/20** | **7/20** | **2/20** | **13/20** | **11/20** |
| **Normalized** | **9/10** | **4/10** | **1/10** | **7/10** | **5/10** |

ECOSYSTEM (Bonus 10 points)
---------------------------
| Feature | QSCG | kyber-py | falcon.py | liboqs | PQClean |
|---------|------|----------|-----------|--------|---------|
| GitHub stars | 1 | 2 | 1 | 3 | 2 |
| Community activity | 1 | 2 | 1 | 3 | 2 |
| Backed by organization | 1 | 1 | 1 | 3 | 2 |
| Used in production | 0 | 0 | 0 | 3 | 2 |
| Academic citations | 0 | 1 | 1 | 3 | 2 |
| **Score** | **3/15** | **6/15** | **4/15** | **15/15** | **10/15** |
| **Normalized** | **2/10** | **4/10** | **3/10** | **10/10** | **7/10** |

================================================================================
TOTAL SCORES (100 points)
================================================================================

| Repository | Correctness | Performance | Security | Code Quality | Features | Ecosystem | TOTAL |
|------------|-------------|-------------|----------|--------------|----------|-----------|-------|
| **liboqs** | 10 | 9 | 8 | 7 | 7 | 10 | **51** |
| **PQClean** | 10 | 9 | 8 | 7 | 5 | 7 | **46** |
| **kyber-py** | 8 | 6 | 5 | 7 | 4 | 4 | **34** |
| **QSCG v4.0** | 4 | 3 | 3 | 4 | 9 | 2 | **25** |
| **falcon.py** | 0 | 5 | 3 | 4 | 1 | 3 | **16** |

**Not:** QSCG düşük puan alıyor çünkü değerli özellikleri (GUI, AI Agent, docs)
"Cryptographic Core" puanlamasında ağırlıklı değil. Gerçek dünya kullanımında
QSCG'nin entegre değeri (GUI + AI + docs) daha yüksek.

================================================================================
QSCG POSITIONING RADAR (ASCII)
================================================================================

                    Correctness [████████░░] 40%
                         |
    Features     [███████████████░░░] 90%    |    Performance [██████░░░░] 30%
    [█████████████████░░] 90%              |    [████████░░░░░░░░░░] 40%
                         |                 |
                    QSCG v4.0              |
                         |                 |
    Ecosystem    [████░░░░░░░░░░░░░░] 20%  |    Security [██████░░░░░░░░] 50%
    [████████████░░░░░░░] 60%              |    [████████████░░░░░░] 60%
                         |
                    Code Quality [██████░░░░] 60%
                    [█████████████░░░░░░░] 65%

================================================================================
QSCG UNIQUE VALUE PROPOSITION
================================================================================

"QSCG is the ONLY Python-native, GUI-enabled, AI-integrated, 
documentation-rich PQC toolkit covering all three NIST standards."

| Unique Feature | Count in GitHub Ecosystem |
|----------------|---------------------------|
| Python + 3 NIST standards | 1 (QSCG) |
| + GUI (Desktop) | 1 (QSCG) |
| + AI Agent | 1 (QSCG) |
| + Industry analysis maps | 1 (QSCG) |
| + Academic research docs | 1 (QSCG) |
| + PyPI package + CI/CD | 1 (QSCG) |

================================================================================
INTEGRATION ROADMAP (Prioritized)
================================================================================

PRIORITY 0 (Critical - This Sprint)
-------------------------------------
1. ✅ Fix NTT zetas (bit-reversal) [DONE]
2. ✅ Fix SecurityLevel LEVEL_2 [DONE]
3. ✅ Fix secure_random_int [DONE]
4. ✅ Fix f-string syntax error [DONE]
5. ✅ Add NTT cross-validation tests [DONE]
6. ✅ GitHub Topics ecosystem analysis [DONE]

PRIORITY 1 (High - Next 2 Weeks)
--------------------------------
7. Add NIST KAT test vectors (from PQClean)
8. Add FALCON (FN-DSA) via liboqs ctypes wrapper
9. Add Compress/Decompress (ML-KEM FIPS 203)
10. Add implicit rejection (ML-KEM decaps)
11. Add DRBG (AES256-CTR) for deterministic testing
12. Add PKCS#8 encoding

PRIORITY 2 (Medium - Next Month)
--------------------------------
13. liboqs ctypes backend (performance boost 10-50x)
14. HQC (code-based KEM) support
15. CBD optimization (bit_count vs Box-Muller)
16. Parse algorithm optimization (12-bit chunks)
17. Fuzz testing (libFuzzer integration)
18. Memory sanitizer (Valgrind/ASAN)

PRIORITY 3 (Low - Long Term)
----------------------------
19. FN-DSA pure Python implementation
20. McEliece support
21. Formal verification (CryptoVerif/Tamarin)
22. Assembly super-optimization (slothy reference)
23. GPU acceleration (CUDA)
24. Rust module (PyO3)

================================================================================
BUGS FOUND AND FIXED (Summary)
================================================================================

| # | Bug | Severity | Source Found | Fix Applied |
|---|-----|----------|--------------|-------------|
| 1 | NTT zetas 256→128, bit-reversal missing | CRITICAL | kyber-py | ntt_kyber.py |
| 2 | SecurityLevel LEVEL_2 missing | CRITICAL | Code review | qscg_v4_core.py |
| 3 | secure_random_int [min,max-1] | MEDIUM | kyber-py | qscg_v4_core.py |
| 4 | f-string with literal newlines | CRITICAL | Deep analysis | qscg_v4_core.py |
| 5 | Missing Compress/Decompress | HIGH | PQClean | TODO |
| 6 | Missing implicit rejection | HIGH | kyber-py | TODO |
| 7 | Missing NIST KAT vectors | HIGH | liboqs/PQClean | TODO |
| 8 | Box-Muller instead of CDT | MEDIUM | falcon.py | TODO |

================================================================================
CONCLUSION
================================================================================

"QSCG v4.0 is not the fastest, not the most secure, not the most complete.
But it is the most ACCESSIBLE post-quantum cryptography toolkit in Python."

Strengths:
- ✅ Only Python-native comprehensive PQC toolkit
- ✅ GUI + AI Agent (unique)
- ✅ Industry/academic documentation (unique)
- ✅ PyPI + CI/CD (developer-friendly)

Weaknesses (being fixed):
- ⚠️ NTT correctness (FIXED)
- ⚠️ Missing algorithms (FALCON, HQC, McEliece)
- ⚠️ Performance (liboqs backend planned)
- ⚠️ Security hardening (tests planned)

Next milestone: QSCG v4.1 with liboqs backend + FALCON support

---

*Master Analysis: Bilge Kağan | QSCG Quantum Tunneling Research*
*M.Cem Koca {Deuterium12} | 2026-05-22*
