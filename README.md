# QSCG v2.1 - Quantum-Safe Cryptography GitHub Repository

## Overview

Quantum-Safe Cryptography Educational Implementation based on NIST FIPS 203/204/205 Standards.

**Author:** Dante (mcemkoca)  
**Repository:** https://github.com/mcemkoca/qscg  
**License:** MIT

## Implemented Algorithms

### ✓ Working Components

1. **Educational NTT** - Number Theoretic Transform
   - Standard integer arithmetic (no Montgomery optimization)
   - Complete NTT (8 layers) for mathematical transparency
   - Verified round-trip correctness

2. **Polynomial Arithmetic** - R_q = Z_q[X]/(X^n + 1)
   - Addition, subtraction, multiplication using NTT
   - Center reduction and byte serialization

3. **Hybrid Encryption** - Quantum-Safe KEM + AES-256-GCM
   - Deterministic hash-based key derivation
   - Working encrypt/decrypt with test validation
   - Falls back to SHAKE256 stream cipher if cryptography library unavailable

### Educational/Simplified Components

4. **ML-DSA** (Dilithium) - Module Lattice-based Digital Signature
   - Based on NIST FIPS 204
   - Fiat-Shamir with aborts structure
   - Simplified norm checks and hint generation

5. **SLH-DSA** (SPHINCS+) - Stateless Hash-Based Digital Signature
   - Based on NIST FIPS 205
   - Simplified hypertree and FORS structures

## Key Design Decisions

### NTT Simplification
Real Kyber/ML-KEM uses:
- Montgomery form for efficient modular multiplication
- Incomplete NTT (7 layers, 128 degree-2 polynomials)
- Barrett reduction

This educational version uses:
- Standard integer arithmetic for clarity
- Complete NTT (8 layers, full decomposition)
- Simple modular reduction

**Trade-off:** Slower but mathematically transparent and correct.

### KEM Simplification
Real ML-KEM uses:
- Complex MLWE-based key encapsulation
- Noise-based message recovery
- Implicit rejection mechanism

This version uses:
- Hash-based deterministic key derivation
- Simplified but working key agreement
- Educational clarity over full complexity

## Usage

```python
from qscg_v2_1 import HybridCryptoSystem, SecurityLevel

# Initialize hybrid encryption
hybrid = HybridCryptoSystem(SecurityLevel.LEVEL_1)

# Generate key pair
encapsulation_key, decapsulation_key = hybrid.keygen()

# Encrypt message
plaintext = b"Hello, Quantum-Safe World!"
ciphertext = hybrid.encrypt(encapsulation_key, plaintext)

# Decrypt message
decrypted = hybrid.decrypt(decapsulation_key, ciphertext)
print(decrypted.decode())  # Hello, Quantum-Safe World!
```

## Testing

Run the built-in test suite:

```bash
python qscg_v2_1.py
```

Expected output:
- NTT Round-Trip: ✓ PASS
- Polynomial Arithmetic: ✓ PASS  
- Hybrid Encryption: ✓ PASS

## Security Notice

**This is an EDUCATIONAL implementation.**

For production use, consider:
- [liboqs](https://github.com/open-quantum-safe/liboqs) (Open Quantum Safe)
- [pq-crystals](https://pq-crystals.org/) reference implementations
- Hardware acceleration (AVX2, NEON)

## Mathematical Background

### Module Learning With Errors (MLWE)
The security of ML-KEM is based on the hardness of the MLWE problem:

Given: A (public matrix), t = A·s + e (public vector)  
Find: s (secret vector)

where s and e are small-norm vectors, and all operations are in R_q.

### Number Theoretic Transform (NTT)
NTT enables O(n log n) polynomial multiplication in R_q:

1. Forward NTT: Convert coefficient representation to evaluation representation
2. Pointwise multiply in NTT domain
3. Inverse NTT: Convert back to coefficient representation

### Fiat-Shamir with Aborts (ML-DSA)
Signature scheme using rejection sampling:
1. Prover commits to random masking vector y
2. Challenge c = H(message || commitment)
3. Response z = y + c·s (rejected if norm too large)
4. Verification checks z and recomputes challenge

## File Structure

```
qscg/
├── qscg_v2_1.py          # Main implementation
├── README.md             # This file
├── LICENSE               # MIT License
└── tests/
    └── test_qscg.py      # Additional tests
```

## References

- NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
- NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
- NIST FIPS 205: Stateless Hash-Based Digital Signature Standard
- CRYSTALS-Kyber: https://pq-crystals.org/kyber/
- CRYSTALS-Dilithium: https://pq-crystals.org/dilithium/

## Changelog

### v2.1
- Fixed NTT round-trip correctness
- Simplified KEM with deterministic key derivation
- Working hybrid encryption (KEM + AES-256-GCM)
- Educational ML-DSA and SLH-DSA structures
- Comprehensive documentation

### v2.0
- Initial lattice-based structure
- Academic foundation with MLWE/SIS mathematics
- Productization policy framework

## Contact

For questions or contributions, please open an issue on GitHub.
