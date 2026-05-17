# Algorithms and Standards

> **NIST Post-Quantum Cryptography Standards**
>
> This page provides a comprehensive technical overview of the NIST-standardized post-quantum cryptographic algorithms implemented in QSCG. It covers the mathematical foundations, security parameters, implementation details, and comparative analysis.

---

## Table of Contents

1. [Overview](#overview)
2. [ML-KEM (FIPS 203)](#ml-kem-fips-203)
3. [ML-DSA (FIPS 204)](#ml-dsa-fips-204)
4. [SLH-DSA (FIPS 205)](#slh-dsa-fips-205)
5. [AES-256-GCM Hybrid Encryption](#aes-256-gcm-hybrid-encryption)
6. [Mathematical Foundations](#mathematical-foundations)
7. [Security Levels Comparison](#security-levels-comparison)
8. [Algorithm Comparison Table](#algorithm-comparison-table)
9. [Implementation Notes](#implementation-notes)
10. [References](#references)

---

## Overview

In 2024, NIST published the first three finalized post-quantum cryptography standards:

| Standard | Algorithm | Purpose | Publication |
|----------|-----------|---------|-------------|
| FIPS 203 | ML-KEM | Key Encapsulation Mechanism | August 2024 |
| FIPS 204 | ML-DSA | Digital Signature Algorithm | August 2024 |
| FIPS 205 | SLH-DSA | Stateless Hash-based Digital Signature | August 2024 |

These algorithms are designed to resist attacks from both classical and quantum computers. They are based on mathematical problems that are believed to be hard even for quantum computers to solve efficiently.

### Security Levels

NIST defines five security levels, each corresponding to the hardness of breaking a specific symmetric-key equivalent:

| Level | Symmetric Equivalent | Classical Security | Quantum Security |
|-------|---------------------|-------------------|------------------|
| 1 | AES-128 | 128 bits | ~64 bits (Grover) |
| 2 | SHA-256/SHA-3-256 | 128 bits | ~64 bits (Grover) |
| 3 | AES-192 | 192 bits | ~96 bits (Grover) |
| 4 | SHA-384/SHA-3-384 | 192 bits | ~96 bits (Grover) |
| 5 | AES-256 | 256 bits | ~128 bits (Grover) |

---

## ML-KEM (FIPS 203)

**Module-Lattice-Based Key Encapsulation Mechanism**

ML-KEM (formerly CRYSTALS-Kyber) is a lattice-based key encapsulation mechanism that derives its security from the hardness of the Module Learning With Errors (MLWE) problem.

### How It Works

ML-KEM operates over polynomial rings and uses the Learning With Errors (LWE) problem to provide security:

```
1. Key Generation:
   - Sample random polynomials
   - Compute public key from secret key with small errors
   - Security relies on inability to distinguish LWE samples from uniform

2. Encapsulation:
   - Generate random shared secret
   - Encrypt shared secret using recipient's public key
   - Output: (ciphertext, shared_secret)

3. Decapsulation:
   - Decrypt ciphertext using private key
   - Recover shared secret
   - Output: shared_secret
```

### Mathematical Structure

ML-KEM operates over the ring:

```
R_q = Z_q[X] / (X^n + 1)

Where:
- n = 256 (polynomial degree)
- q = 3329 (prime modulus)
- All arithmetic is modulo q
```

The key equation:

```
t = A * s + e  (mod q)

Where:
- A: Public random matrix (k x k)
- s: Secret vector with small coefficients
- e: Error vector with small coefficients
- t: Public key component
```

### Parameter Sets

| Parameter | ML-KEM-512 (Level 1) | ML-KEM-768 (Level 3) | ML-KEM-1024 (Level 5) |
|-----------|---------------------|---------------------|----------------------|
| **NIST Level** | 1 | 3 | 5 |
| **k (module rank)** | 2 | 3 | 4 |
| **n (poly degree)** | 256 | 256 | 256 |
| **q (modulus)** | 3329 | 3329 | 3329 |
| **eta1 (error dist)** | 3 | 2 | 2 |
| **eta2 (error dist)** | 2 | 2 | 2 |
| **d_u (compress)** | 10 | 10 | 11 |
| **d_v (compress)** | 4 | 4 | 5 |
| **Public Key Size** | 800 bytes | 1,184 bytes | 1,568 bytes |
| **Private Key Size** | 1,632 bytes | 2,400 bytes | 3,168 bytes |
| **Ciphertext Size** | 768 bytes | 1,088 bytes | 1,568 bytes |
| **Shared Secret Size** | 32 bytes | 32 bytes | 32 bytes |

### Security Foundations

ML-KEM's security is based on the following hard problems:

- **Decision-MLWE**: Distinguishing `(A, A*s + e)` from uniform random is computationally hard
- **Search-MLWE**: Recovering secret `s` from `(A, A*s + e)` is computationally hard
- **Reduction**: Proven reduction to worst-case lattice problems (Module-SVP)

---

## ML-DSA (FIPS 204)

**Module-Lattice-Based Digital Signature Algorithm**

ML-DSA (formerly CRYSTALS-Dilithium) is a lattice-based digital signature scheme based on the hardness of the Module Short Integer Solution (MSIS) and MLWE problems.

### How It Works

```
1. Key Generation:
   - Generate secret key (s1, s2)
   - Compute public key: A, t = A*s1 + s2
   - Precompute parts of the signing key for efficiency

2. Signing:
   - Generate random masking vector y
   - Compute w = A*y
   - Compute challenge c = H(mu || w1)
   - Compute z = y + c*s1
   - Rejection sampling: restart if z is too large
   - Output signature: (c_tilde, z, h)

3. Verification:
   - Reconstruct w' = A*z - c*t
   - Verify c = H(mu || w'1)
   - Accept if equations hold and bounds are satisfied
```

### Key Mathematical Components

**Public Key Generation:**
```
t = A * s1 + s2  (mod q)
```

**Signature Generation:**
```
w = A * y
w1 = HighBits(w)
c = H(mu || w1)
z = y + c * s1

Rejection sampling: ||z||_inf < gamma1 - beta
Hint: h = MakeHint(-c * t0, w - c * s2 + c * t0, 2*gamma2)
```

**Verification:**
```
w' = A*z - c*t * 2^d
w1' = UseHint(h, w', 2*gamma2)
Verify: c == H(mu || w1')
```

### Parameter Sets

| Parameter | ML-DSA-44 (L1) | ML-DSA-65 (L3) | ML-DSA-87 (L5) |
|-----------|---------------|---------------|---------------|
| **NIST Level** | 2 | 3 | 5 |
| **k** | 4 | 6 | 8 |
| **l** | 4 | 5 | 7 |
| **d** | 13 | 13 | 13 |
| **gamma1** | 2^17 | 2^19 | 2^19 |
| **gamma2** | 95232 | 261888 | 261888 |
| **tau** | 39 | 49 | 60 |
| **eta** | 2 | 4 | 2 |
| **omega** | 80 | 80 | 80 |
| **beta** | 78 | 196 | 120 |
| **Public Key Size** | 1,312 bytes | 1,952 bytes | 2,592 bytes |
| **Private Key Size** | 2,528 bytes | 4,032 bytes | 4,896 bytes |
| **Signature Size** | 2,420 bytes | 3,293 bytes | 4,595 bytes |

### Security Notes

ML-DSA achieves existential unforgeability under chosen-message attack (EUF-CMA) through:

- ** Fiat-Shamir Transform**: Converts interactive identification to non-interactive signature
- **Rejection Sampling**: Ensures signature distribution independent of secret key
- **Hint Mechanism**: Enables efficient verification without storing full information

---

## SLH-DSA (FIPS 205)

**Stateless Hash-Based Digital Signature Algorithm**

SLH-DSA (formerly SPHINCS+) is a hash-based signature scheme that relies entirely on the security of cryptographic hash functions (SHA-2 or SHAKE). It is considered the most conservative post-quantum choice since its security reduces directly to well-understood hash function properties.

### Architecture Overview

SLH-DSA uses a multi-layer Merkle tree structure:

```
FOROTS (Few-Time Signature) at the bottom:
  - Signs message digests
  - Uses WOTS+ (Winternitz One-Time Signature)

XMSS Trees:
  - Layer 0 (bottom): Signs FOROTS public keys
  - Layer 1 to d-1: Signs lower-layer XMSS public keys

Hyper Tree:
  - Total height: h
  33        XMSS tree (layer d-1)
  22        XMSS tree (layer 2)
  11        XMSS tree (layer 1)
  00        FOROTS (layer 0, bottom)
```

### How It Works

```
1. Key Generation:
   - Generate two secret seeds (SK.seed, PRF.seed)
   - Generate public seed PK.seed
   - Build hyper-tree from PK.seed
   - Public key = (PK.seed, PK.root)
   - Secret key = (SK.seed, PRF.seed, PK.seed, PK.root)

2. Signing:
   - Derive randomizer R from PRF and message
   - Compute message digest = H(R || PK.seed || PK.root || message)
   - Select FOROTS key pair from digest
   - Sign with FOROTS
   - Build authentication path through XMSS trees
   - Output: (R, SIG_FORS, SIG_HT)

3. Verification:
   - Recompute message digest
   - Verify FOROTS signature
   - Verify XMSS authentication path
   - Accept if root matches PK.root
```

### Security Foundations

SLH-DSA security relies solely on:

- **Preimage Resistance**: Finding M' such that H(M') = H(M) is hard
- **Second Preimage Resistance**: Finding M' != M with H(M') = H(M) is hard
- **Collision Resistance**: Finding M1 != M2 with H(M1) = H(M2) is hard
- **Pseudorandomness**: The PRF generates indistinguishable-from-random outputs

### Parameter Sets

| Parameter | SLH-DSA-SHA2-128s | SLH-DSA-SHA2-192s | SLH-DSA-SHA2-256s | SLH-DSA-SHAKE-128s | SLH-DSA-SHAKE-192s | SLH-DSA-SHAKE-256s |
|-----------|------------------|------------------|------------------|-------------------|-------------------|-------------------|
| **NIST Level** | 1 | 3 | 5 | 1 | 3 | 5 |
| **Hash** | SHA2-256 | SHA2-512 | SHA2-512 | SHAKE-128 | SHAKE-256 | SHAKE-256 |
| **n** | 16 | 24 | 32 | 16 | 24 | 32 |
| **h** | 66 | 66 | 68 | 66 | 66 | 68 |
| **d** | 22 | 22 | 17 | 22 | 22 | 17 |
| **a** | 6 | 8 | 9 | 6 | 8 | 9 |
| **k** | 33 | 33 | 35 | 33 | 33 | 35 |
| **w (Winternitz)** | 16 | 16 | 16 | 16 | 16 | 16 |
| **Public Key Size** | 32 bytes | 48 bytes | 64 bytes | 32 bytes | 48 bytes | 64 bytes |
| **Private Key Size** | 64 bytes | 96 bytes | 128 bytes | 64 bytes | 96 bytes | 128 bytes |
| **Signature Size** | 7,856 bytes | 16,224 bytes | 29,792 bytes | 7,856 bytes | 16,224 bytes | 29,792 bytes |

### Trade-offs

SLH-DSA offers a security-vs-size tradeoff:

| Variant | Security Emphasis | Signature Size | Speed | Use Case |
|---------|-------------------|----------------|-------|----------|
| **s (small)** | Faster verification | Smaller (~7.8KB L1) | Slower signing | Most use cases |
| **f (fast)** | Faster signing | Larger (~17KB L1) | Faster signing | High-throughput |

---

## AES-256-GCM Hybrid Encryption

While AES-256-GCM is a classical symmetric cipher (not post-quantum itself), QSCG integrates it with ML-KEM to provide **hybrid encryption** that is secure against both classical and quantum adversaries.

### Hybrid Construction

```
1. Key Encapsulation:
   - Encapsulate a shared secret using ML-KEM
   - Derive AES-256 key from shared secret using KDF

2. Symmetric Encryption:
   - Encrypt plaintext using AES-256-GCM
   - Output: (ML-KEM ciphertext, AES ciphertext, AES nonce, AES tag)

3. Decryption:
   - Decapsulate ML-KEM ciphertext to recover shared secret
   - Derive AES-256 key
   - Decrypt AES ciphertext
```

### Why Hybrid?

| Threat Model | Classical Only | Quantum | Defense |
|-------------|---------------|---------|---------|
| Classical attacker | AES-256 secure | AES-256 secure | AES alone sufficient |
| Quantum attacker | AES-256 secure | AES-256 reduced to ~128 bits | ML-KEM provides PQ security |
| Unknown future attack | AES-256 secure | Unknown | Defense-in-depth |

### Parameters

| Parameter | Value |
|-----------|-------|
| **Algorithm** | AES-256-GCM |
| **Key Size** | 256 bits |
| **Nonce Size** | 96 bits (IV) |
| **Tag Size** | 128 bits (authentication) |
| **Block Size** | 128 bits |
| **Quantum Security** | ~128 bits (Grover's limit) |
| **PQ Security** | Provided by ML-KEM encapsulation |

---

## Mathematical Foundations

### Module-LWE (Learning With Errors over Modules)

The Module-LWE problem is the foundation of both ML-KEM and ML-DSA:

**Definition**: Given `(A, t)` where either:
- (a) `t = A*s + e` (LWE instance), or
- (b) `t` is uniformly random

Distinguishing between (a) and (b) is computationally hard.

**Parameters**:
```
- A in R_q^(k x k): uniformly random matrix
- s in R_q^k: secret vector, coefficients from centered binomial distribution
- e in R_q^k: error vector, coefficients from centered binomial distribution
- R_q = Z_q[X]/(X^n + 1)
```

### Module-SIS (Short Integer Solution)

The Module-SIS problem provides additional security for ML-DSA:

**Definition**: Given a random matrix `A`, find a short vector `z` such that:
```
A * z = 0 (mod q),  ||z|| <= beta
```

Finding such a short vector is computationally hard.

### Number Theoretic Transform (NTT)

NTT is the polynomial equivalent of FFT, used for efficient polynomial multiplication in ML-KEM and ML-DSA:

```python
# Standard polynomial multiplication: O(n^2)
# NTT-based multiplication: O(n log n)

import numpy as np

def ntt_transform(a, q, root_of_unity):
    """
    Number Theoretic Transform
    Converts polynomial to NTT domain for fast multiplication.
    """
    n = len(a)
    if n == 1:
        return a
    
    # Split into even and odd coefficients
    a_even = ntt_transform(a[0::2], q, pow(root_of_unity, 2, q))
    a_odd = ntt_transform(a[1::2], q, pow(root_of_unity, 2, q))
    
    result = [0] * n
    w = 1
    for k in range(n // 2):
        t = (w * a_odd[k]) % q
        result[k] = (a_even[k] + t) % q
        result[k + n // 2] = (a_even[k] - t) % q
        w = (w * root_of_unity) % q
    
    return result

# Usage:
# c = INTT(NTT(a) * NTT(b))  # O(n log n) vs O(n^2)
```

**Key Properties**:
- NTT requires `q = 1 (mod 2n)` for primitive 2n-th root of unity
- ML-KEM's q = 3329 satisfies this with `3329 = 256 * 13 + 1`
- Polynomial multiplication becomes coefficient-wise in NTT domain
- Reduces O(n^2) convolution to O(n log n) operations

---

## Security Levels Comparison

### Quantum Attack Complexity

| Algorithm | Security Level | Classical Security | Quantum Resistance | Best Known Quantum Attack |
|-----------|---------------|-------------------|-------------------|--------------------------|
| **ML-KEM-512** | NIST Level 1 | 128 bits | 128 bits | Grover + lattice sieving |
| **ML-KEM-768** | NIST Level 3 | 192 bits | 192 bits | Grover + lattice sieving |
| **ML-KEM-1024** | NIST Level 5 | 256 bits | 256 bits | Grover + lattice sieving |
| **ML-DSA-44** | NIST Level 2 | 128 bits | 128 bits | Grover + lattice reduction |
| **ML-DSA-65** | NIST Level 3 | 192 bits | 192 bits | Grover + lattice reduction |
| **ML-DSA-87** | NIST Level 5 | 256 bits | 256 bits | Grover + lattice reduction |
| **SLH-DSA-128s** | NIST Level 1 | 128 bits | 128 bits | Grover on hash |
| **SLH-DSA-192s** | NIST Level 3 | 192 bits | 192 bits | Grover on hash |
| **SLH-DSA-256s** | NIST Level 5 | 256 bits | 256 bits | Grover on hash |

### Resistance to Known Attacks

| Attack Type | ML-KEM | ML-DSA | SLH-DSA |
|-------------|--------|--------|---------|
| Shor's Algorithm | ✅ Resistant | ✅ Resistant | ✅ Resistant |
| Grover's Algorithm | ✅ Resistant | ✅ Resistant | ✅ Reduced security |
| Lattice Reduction | ✅ Secure at params | ✅ Secure at params | N/A (hash-based) |
| Birthday Attack | N/A | N/A | ✅ Secure |
| Side-Channel Attacks | ⚠️ Needs protection | ⚠️ Needs protection | ✅ Naturally resistant |

---

## Algorithm Comparison Table

| Feature | ML-KEM | ML-DSA | SLH-DSA |
|---------|--------|--------|---------|
| **Primary Use** | Key Encapsulation | Digital Signatures | Digital Signatures |
| **Mathematical Basis** | Module-LWE | MLWE + MSIS | Hash functions |
| **Key Sizes** | Small (0.8-1.6 KB) | Small (1.3-2.6 KB) | Tiny (32-64 B public) |
| **Signature Size** | N/A | Medium (2.4-4.6 KB) | Large (7.8-29.8 KB) |
| **Speed** | Very Fast | Fast | Moderate |
| **Security Assumption** | Lattice | Lattice | Hash function |
| **Conservative?** | Moderate | Moderate | Very High |
| **Side-Channel Resistant** | Requires care | Requires care | Yes (naturally) |
| **Quantum Security** | Full | Full | Full (hash-based) |

---

## Implementation Notes

### Memory Considerations

| Algorithm | Level | Stack Usage | Heap Usage | Notes |
|-----------|-------|------------|------------|-------|
| ML-KEM | 1 | ~4 KB | ~3 KB | Low memory footprint |
| ML-KEM | 3 | ~6 KB | ~4 KB | Low memory footprint |
| ML-KEM | 5 | ~8 KB | ~5 KB | Low memory footprint |
| ML-DSA | 1 | ~8 KB | ~6 KB | Moderate stack |
| ML-DSA | 3 | ~12 KB | ~8 KB | Moderate stack |
| ML-DSA | 5 | ~16 KB | ~10 KB | Moderate stack |
| SLH-DSA | 1 | ~20 KB | ~40 KB | Higher stack for tree traversal |
| SLH-DSA | 3 | ~30 KB | ~60 KB | Higher stack for tree traversal |
| SLH-DSA | 5 | ~40 KB | ~80 KB | Higher stack for tree traversal |

### Performance Characteristics (Approximate, Intel x86_64)

| Operation | ML-KEM-768 | ML-DSA-65 | SLH-DSA-128s |
|-----------|-----------|-----------|--------------|
| **Key Generation** | ~100,000 cycles | ~300,000 cycles | ~1,000,000 cycles |
| **Encapsulation/Signing** | ~120,000 cycles | ~400,000 cycles | ~2,500,000 cycles |
| **Decapsulation/Verification** | ~120,000 cycles | ~130,000 cycles | ~100,000 cycles |

---

## References

1. NIST FIPS 203: *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (August 2024)
2. NIST FIPS 204: *Module-Lattice-Based Digital Signature Standard* (August 2024)
3. NIST FIPS 205: *Stateless Hash-Based Digital Signature Standard* (August 2024)
4. Avanzi, R. et al.: *CRYSTALS-Kyber Algorithm Specifications and Supporting Documentation*
5. Bai, S. and Galbraith, S.: *Lattice Decoding: Challenges and New Strategies*
6. Bernstein, D.J. and Lange, T.: *Post-Quantum Cryptography* (Nature, 2017)
7. CSRC.NIST.gov: *Post-Quantum Cryptography Standardization* https://csrc.nist.gov/projects/post-quantum-cryptography
8. NIST IR 8547: *Transition to Post-Quantum Cryptography Standards*

---

> **Last Updated**: 2025-01-15 | QSCG v2.2.0
>
> For corrections or additions to this documentation, please open an issue on [GitHub](https://github.com/mcemkoca/qscg/issues).
