# Side-Channel Security Audit

> **QSCG v3.0.0 — Post-Quantum Cryptography Implementation Review**
> 
> Focus: Timing attacks, secret-dependent branches, and non-constant-time operations
> 
> Reference: [Ahmed et al. (2025), Section 3.4](https://arxiv.org/abs/2508.16078)

---

## Executive Summary

| Risk Level | Count | Description |
|:-----------|------:|:------------|
| 🔴 **Critical** | 2 | Secret-dependent branches in decapsulation and signing |
| 🟡 **High** | 3 | Python integer comparison, conditional indexing, mod operations |
| 🟢 **Low** | 4 | Information leakage via exception messages, memory patterns |

**Verdict:** QSCG is **NOT safe for production** against timing attacks. The pure-Python implementation is inherently vulnerable due to Python's dynamic typing and garbage collection. This audit documents all findings and provides a mitigation roadmap.

---

## 🔴 Critical Findings

### 1. Secret-Dependent Branch in ML-KEM Decapsulation

**File:** `src/qscg/ml_kem/ml_kem.py` (lines 1456-1461)

```python
# VULNERABLE: secret-dependent branch
if result == decapsulated_shared_secret:
    return decapsulated_shared_secret
else:
    return shared_secret  # Failure path
```

**Risk:** The equality comparison `==` on secret bytes creates a timing difference between success and failure paths. An attacker measuring decapsulation time can determine whether the ciphertext was valid — this is the **KyberSlash** class of attack.

**Attack scenario:**
1. Attacker sends malicious ciphertexts
2. Measures decapsulation time
3. Statistically distinguishes valid vs invalid ciphertexts
4. Recovers private key material over many queries

**CVSS:** 7.5 (High) — timing side-channel leading to key recovery

---

### 2. Secret-Dependent Rejection Sampling in ML-DSA Signing

**File:** `src/qscg/ml_dsa/ml_dsa.py` (signing loop)

```python
# VULNERABLE: while loop branches on secret coefficients
while retry_count < MAX_RETRIES:
    y = sample_random_vector(...)
    w = A @ y
    w1 = high_bits(w)
    # ...
    if hint_ok:  # <-- secret-dependent condition
        break
```

**Risk:** The number of loop iterations leaks information about the secret key's structure. An attacker counting iterations (via timing or power analysis) gains information about the secret vector.

**Note:** The monolithic implementation in `qscg_v2_1_final.py` has a similar pattern but appears to terminate. The modular implementation hangs — possibly an infinite loop bug rather than an intentional side-channel, but the risk remains.

**CVSS:** 6.8 (Medium-High)

---

## 🟡 High Findings

### 3. Python Integer Comparison is Not Constant-Time

**File:** `src/qscg/common/polynomial.py` and throughout

Python's `int.__eq__()` is implemented in C but **not guaranteed constant-time**. For large integers (256+ bit), Python may short-circuit on the first differing limb, creating timing variation.

**Affected operations:**
- Polynomial coefficient comparison
- NTT element comparison
- Hash output comparison

**Mitigation:** Use `hmac.compare_digest()` or `secrets.compare_digest()` for all secret comparisons.

---

### 4. Conditional Array Indexing in NTT

**File:** `src/qscg/common/ntt.py`

```python
# POTENTIALLY VULNERABLE: index depends on secret data
if a[i] < 0:
    a[i] += MOD
```

**Risk:** Branch predictor behavior leaks whether coefficients were negative. In a tight NTT loop, this creates measurable timing variation.

**Mitigation:** Use constant-time modular reduction (addition with conditional mask instead of branch).

---

### 5. Modulo Operation on Secrets

**File:** Throughout polynomial arithmetic

```python
# VULNERABLE: Python's % operator is not constant-time
result = (a * b) % Q
```

Python's `%` on large integers has variable execution time depending on operand sizes. When one operand is secret, this leaks information about its magnitude.

---

## 🟢 Low Findings

### 6. Exception Messages May Leak Information

**File:** Various

Error messages like `"Invalid ML-DSA secret key size: expected 4224, got {len(secret_key)}"` leak the actual received size, which could be useful in a padding oracle-style attack.

**Mitigation:** Use generic error messages for all cryptographic failures.

### 7. Memory Copying of Secret Keys

Python's immutable `bytes` and garbage collection mean secret keys may persist in memory longer than necessary. There is no `memset_s` equivalent in Python to securely wipe memory.

### 8. `hashlib.sha3_256` vs `shake_128` Timing Differences

Different hash functions have different execution times. If the choice of hash function depends on secret parameters, this leaks information.

---

## Mitigation Roadmap

### Short-term (This PR)

- [x] Document all findings (this file)
- [ ] Replace secret-dependent branches with constant-time selects
- [ ] Add `hmac.compare_digest()` for all secret comparisons
- [ ] Add timing test harness (statistical timing tests)

### Medium-term (Q2 2026)

- [ ] Implement constant-time polynomial operations (mask-based, no branches)
- [ ] Add `valgrind` / `dudect` style statistical testing to CI
- [ ] Create `qscg-secure` submodule with Cython / Rust optimized constant-time backend

### Long-term (2027)

- [ ] Full rewrite of hot paths in Rust (via PyO3)
- [ ] FIPS 140-2 / Common Criteria evaluation path
- [ ] Formal verification of constant-time properties

---

## Constant-Time Patterns for Python

### Pattern 1: Constant-Time Select (replace if/else)

```python
# VULNERABLE
if secret_bit:
    result = a
else:
    result = b

# SECURE: constant-time select
mask = -secret_bit  # 0 or -1 (all bits set)
result = (a & mask) | (b & ~mask)
```

### Pattern 2: Constant-Time Comparison

```python
# VULNERABLE
if x == y:
    return True

# SECURE
import hmac
return hmac.compare_digest(x, y)  # constant-time in C
```

### Pattern 3: Constant-Time Modular Reduction

```python
# VULNERABLE
if a < 0:
    a += MOD

# SECURE
mask = (a >> 31) & MOD  # assumes MOD fits in sign bit logic
a += mask
```

### Pattern 4: Constant-Time Conditional Swap

```python
def cswap(condition, a, b):
    """Swap a and b if condition is 1, in constant time."""
    mask = -condition
    diff = (a ^ b) & mask
    return a ^ diff, b ^ diff
```

---

## Testing for Side-Channels

### Manual Timing Test

```bash
# Run many iterations and measure variance
python -c "
import time, statistics
from qscg_v2_1_final import MLKEM, SecurityLevel

times = []
for _ in range(1000):
    kem = MLKEM(SecurityLevel.LEVEL_3)
    kp = kem.keygen()
    ct, _ = kem.encapsulate(kp.public_key)
    t0 = time.perf_counter()
    kem.decapsulate(ct, kp.secret_key)
    t1 = time.perf_counter()
    times.append((t1 - t0) * 1000)

print(f'Mean: {statistics.mean(times):.3f} ms')
print(f'Std:  {statistics.stdev(times):.3f} ms')
print(f'Min:  {min(times):.3f} ms')
print(f'Max:  {max(times):.3f} ms')
"
```

### Statistical Test (dudect-style)

Use the `dudect` tool or implement Welch's t-test to compare timing distributions between two classes of inputs (e.g., valid vs invalid ciphertexts).

---

## References

- Bernstein et al. (2025): "KyberSlash: Exploiting secret-dependent division timings" — [IACR TCHES 2025](https://eprint.iacr.org/2024/1049)
- Ahmed et al. (2025): Section 3.4 — Security Analysis of Implementations
- NIST SP 800-90B: Entropy Requirements for Cryptographic Applications
- `constant-time` coding guidelines: [ BearSSL documentation](https://www.bearssl.org/ctoptim.html)

---

*Last updated: 2026-05-25 — QSCG v3.0.0*
