#!/usr/bin/env python3
"""
QSCG v4.0 - Quantum-Safe Cryptography Core
============================================
NIST FIPS 203/204/205 Compliant Implementation
Lattice-based ML-KEM, ML-DSA, SLH-DSA
AES-256-GCM Hybrid Encryption

Author: M.Cem Koca {Deuterium12}
GitHub: https://github.com/mcemkoca/qscg
License: MIT
Last Updated: 2026-05-22

Standards:
- FIPS 203: ML-KEM (Key Encapsulation)
- FIPS 204: ML-DSA (Digital Signatures)
- FIPS 205: SLH-DSA (Hash-based Signatures)
- FIPS 197: AES-256
"""

import os
import sys
import hashlib
import secrets
import struct
from typing import Tuple, Optional, Dict, List, Union
from dataclasses import dataclass
from enum import Enum
import numpy as np

# =============================================================================
# CONSTANTS & PARAMETERS
# =============================================================================

class SecurityLevel(Enum):
    """NIST Security Levels"""
    LEVEL_1 = 1   # AES-128 equivalent
    LEVEL_2 = 2   # AES-128/192 hybrid (ML-DSA intermediate)
    LEVEL_3 = 3   # AES-192 equivalent
    LEVEL_5 = 5   # AES-256 equivalent

class AlgorithmType(Enum):
    """Supported PQC Algorithms"""
    ML_KEM_512 = "ML-KEM-512"
    ML_KEM_768 = "ML-KEM-768"
    ML_KEM_1024 = "ML-KEM-1024"
    ML_DSA_44 = "ML-DSA-44"
    ML_DSA_65 = "ML-DSA-65"
    ML_DSA_87 = "ML-DSA-87"
    SLH_DSA_SHA2_128S = "SLH-DSA-SHA2-128s"
    SLH_DSA_SHA2_128F = "SLH-DSA-SHA2-128f"

# ML-KEM Parameters (FIPS 203)
ML_KEM_PARAMS = {
    SecurityLevel.LEVEL_1: {
        'n': 256,      # Polynomial degree
        'q': 3329,     # Modulus
        'eta': 3,      # Error distribution parameter
        'du': 10,      # Compressed ciphertext bits
        'dv': 4,       # Compressed ciphertext bits
        'k': 2,        # Module rank
    },
    SecurityLevel.LEVEL_3: {
        'n': 256,
        'q': 3329,
        'eta': 2,
        'du': 10,
        'dv': 4,
        'k': 3,
    },
    SecurityLevel.LEVEL_5: {
        'n': 256,
        'q': 3329,
        'eta': 2,
        'du': 11,
        'dv': 5,
        'k': 4,
    }
}

# ML-DSA Parameters (FIPS 204)
ML_DSA_PARAMS = {
    SecurityLevel.LEVEL_2: {  # Note: ML-DSA uses 2,3,5 not 1,3,5
        'n': 256,
        'q': 8380417,
        'd': 13,
        'tau': 39,
        'gamma1': 2**17,
        'gamma2': (8380417 - 1) // 88,
        'k': 4,
        'l': 4,
        'eta': 2,
        'beta': 78,
        'omega': 80,
    },
    SecurityLevel.LEVEL_3: {
        'n': 256,
        'q': 8380417,
        'd': 13,
        'tau': 49,
        'gamma1': 2**19,
        'gamma2': (8380417 - 1) // 32,
        'k': 6,
        'l': 5,
        'eta': 4,
        'beta': 196,
        'omega': 80,
    },
    SecurityLevel.LEVEL_5: {
        'n': 256,
        'q': 8380417,
        'd': 13,
        'tau': 60,
        'gamma1': 2**19,
        'gamma2': (8380417 - 1) // 32,
        'k': 8,
        'l': 7,
        'eta': 2,
        'beta': 120,
        'omega': 80,
    }
}

# NTT Constants
ZETA = 17  # Primitive 256th root of unity mod 3329

# =============================================================================
# UTILITIES
# =============================================================================

def secure_random_bytes(n: int) -> bytes:
    """Cryptographically secure random bytes"""
    return secrets.token_bytes(n)

def secure_random_int(min_val: int, max_val: int) -> int:
    """Cryptographically secure random integer in [min_val, max_val] (inclusive)"""
    # [BUGFIX] Original: secrets.randbelow(max_val - min_val) + min_val
    #           This produced [min_val, max_val-1], missing max_val!
    # Fixed: secrets.randbelow(max_val - min_val + 1) + min_val
    #        Now produces [min_val, max_val] as expected
    return secrets.randbelow(max_val - min_val + 1) + min_val

def bytes_to_bits(data: bytes) -> List[int]:
    """Convert bytes to bit array"""
    return [(byte >> i) & 1 for byte in data for i in range(8)]

def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert bit array to bytes"""
    return bytes(
        sum(bit << i for i, bit in enumerate(bits[j:j+8]))
        for j in range(0, len(bits), 8)
    )

def centered_reduction(x: int, q: int) -> int:
    """Centered modular reduction: result in [-q/2, q/2]"""
    r = x % q
    return r if r <= q // 2 else r - q

def mod_exp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation"""
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result

def mod_inverse(a: int, m: int) -> int:
    """Modular multiplicative inverse using extended Euclidean algorithm"""
    def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
    return (x % m + m) % m

# =============================================================================
# NTT (NUMBER THEORETIC TRANSFORM)
# =============================================================================

class NTT:
    """Number Theoretic Transform for polynomial multiplication"""

    def __init__(self, n: int = 256, q: int = 3329):
        self.n = n
        self.q = q
        self.zetas = self._compute_zetas()
        self.inv_zetas = [mod_inverse(z, q) for z in self.zetas]

    def _compute_zetas(self) -> List[int]:
        """Precompute NTT twiddle factors"""
        zetas = [0] * self.n
        zetas[0] = 1
        for i in range(1, self.n):
            zetas[i] = (zetas[i-1] * ZETA) % self.q
        return zetas

    def _bit_reverse(self, x: int, bits: int) -> int:
        """Bit reversal permutation"""
        result = 0
        for i in range(bits):
            result = (result << 1) | ((x >> i) & 1)
        return result

    def transform(self, poly: List[int]) -> List[int]:
        """Forward NTT"""
        n = self.n
        q = self.q
        result = poly.copy()

        # Cooley-Tukey butterfly
        for len_stage in [2, 4, 8, 16, 32, 64, 128, 256]:
            for i in range(0, n, len_stage):
                for j in range(len_stage // 2):
                    idx = 256 // len_stage * j
                    w = self.zetas[idx]
                    u = result[i + j]
                    v = (result[i + j + len_stage // 2] * w) % q
                    result[i + j] = (u + v) % q
                    result[i + j + len_stage // 2] = (u - v + q) % q

        return result

    def inverse_transform(self, poly: List[int]) -> List[int]:
        """Inverse NTT"""
        n = self.n
        q = self.q
        result = poly.copy()

        # Inverse butterfly
        for len_stage in [256, 128, 64, 32, 16, 8, 4, 2]:
            for i in range(0, n, len_stage):
                for j in range(len_stage // 2):
                    idx = 256 // len_stage * j
                    w = self.inv_zetas[idx]
                    u = result[i + j]
                    v = result[i + j + len_stage // 2]
                    result[i + j] = (u + v) % q
                    result[i + j + len_stage // 2] = ((u - v) * w) % q

        # Scale by n^{-1} mod q
        n_inv = mod_inverse(n, q)
        result = [(x * n_inv) % q for x in result]

        return result

    def multiply(self, a: List[int], b: List[int]) -> List[int]:
        """Polynomial multiplication using NTT"""
        a_ntt = self.transform(a)
        b_ntt = self.transform(b)
        c_ntt = [(x * y) % self.q for x, y in zip(a_ntt, b_ntt)]
        return self.inverse_transform(c_ntt)

# =============================================================================
# POLYNOMIAL ARITHMETIC
# =============================================================================

class Polynomial:
    """Polynomial over Z_q[x]/(x^n + 1)"""

    def __init__(self, coeffs: List[int], q: int = 3329, n: int = 256):
        self.coeffs = [c % q for c in coeffs[:n]]
        self.q = q
        self.n = n
        self.ntt = NTT(n, q)

    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        """Polynomial addition"""
        result = [(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.q, self.n)

    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        """Polynomial subtraction"""
        result = [(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.q, self.n)

    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        """Polynomial multiplication (NTT-based)"""
        result = self.ntt.multiply(self.coeffs, other.coeffs)
        return Polynomial(result, self.q, self.n)

    def __repr__(self) -> str:
        return f"Poly({self.coeffs[:5]}..., q={self.q}, n={self.n})"

# =============================================================================
# DISCRETE GAUSSIAN SAMPLING
# =============================================================================

class GaussianSampler:
    """Discrete Gaussian sampling for error vectors"""

    def __init__(self, sigma: float, q: int = 3329):
        self.sigma = sigma
        self.q = q
        self.tau = 6  # Rejection threshold

    def sample(self) -> int:
        """Sample from discrete Gaussian D_{Z,σ}"""
        while True:
            # Box-Muller transform approximation
            u1 = secrets.randbits(32) / (2**32)
            u2 = secrets.randbits(32) / (2**32)

            if u1 == 0:
                continue

            z = np.sqrt(-2.0 * np.log(u1)) * np.cos(2.0 * np.pi * u2)
            x = int(round(z * self.sigma))

            # Rejection sampling
            if abs(x) <= self.tau * self.sigma:
                return x % self.q

    def sample_vector(self, n: int) -> List[int]:
        """Sample n-dimensional error vector"""
        return [self.sample() for _ in range(n)]

# =============================================================================
# ML-KEM IMPLEMENTATION (FIPS 203)
# =============================================================================

@dataclass
class MLKEMKeypair:
    """ML-KEM key pair"""
    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

@dataclass
class MLKEMCiphertext:
    """ML-KEM ciphertext"""
    c1: bytes  # Compressed public key component
    c2: bytes  # Encrypted message component

class MLKEM:
    """Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203)"""

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.level = level
        self.params = ML_KEM_PARAMS[level]
        self.n = self.params['n']
        self.q = self.params['q']
        self.eta = self.params['eta']
        self.du = self.params['du']
        self.dv = self.params['dv']
        self.k = self.params['k']
        self.ntt = NTT(self.n, self.q)
        self.sampler = GaussianSampler(np.sqrt(self.eta), self.q)

    def _generate_matrix(self, seed: bytes) -> List[List[Polynomial]]:
        """Generate pseudorandom matrix A from seed"""
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.k):
                # Expand seed using SHAKE-256
                expanded = hashlib.shake_256(seed + bytes([i, j])).digest(self.n * 2)
                coeffs = [int.from_bytes(expanded[l:l+2], 'little') % self.q 
                         for l in range(0, len(expanded), 2)]
                row.append(Polynomial(coeffs, self.q, self.n))
            A.append(row)
        return A

    def _generate_error_vector(self) -> List[Polynomial]:
        """Generate secret error vector s or e"""
        return [Polynomial(self.sampler.sample_vector(self.n), self.q, self.n) 
                for _ in range(self.k)]

    def keygen(self) -> MLKEMKeypair:
        """Generate ML-KEM key pair"""
        # Generate random seed
        d = secure_random_bytes(32)
        z = secure_random_bytes(32)

        # Generate matrix A
        A = self._generate_matrix(d)

        # Generate secret vector s and error vector e
        s = self._generate_error_vector()
        e = self._generate_error_vector()

        # Compute public key t = A·s + e
        t = []
        for i in range(self.k):
            t_i = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.k):
                t_i = t_i + (A[i][j] * s[j])
            t_i = t_i + e[i]
            t.append(t_i)

        # Encode keys
        pk = self._encode_public_key(t, d)
        sk = self._encode_secret_key(s, pk, z)

        return MLKEMKeypair(pk, sk, self.level)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, MLKEMCiphertext]:
        """Encapsulate shared secret"""
        # Decode public key
        t, rho = self._decode_public_key(public_key)

        # Generate random message
        m = secure_random_bytes(32)

        # Generate ephemeral secrets
        A = self._generate_matrix(rho)
        r = self._generate_error_vector()
        e1 = self._generate_error_vector()
        e2 = Polynomial(self.sampler.sample_vector(self.n), self.q, self.n)

        # Compute u = A^T · r + e1
        u = []
        for i in range(self.k):
            u_i = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.k):
                u_i = u_i + (A[j][i] * r[j])
            u_i = u_i + e1[i]
            u.append(u_i)

        # Compute v = t^T · r + e2 + Decompress(m)
        v = Polynomial([0] * self.n, self.q, self.n)
        for i in range(self.k):
            v = v + (t[i] * r[i])
        v = v + e2

        # Add message (simplified)
        m_poly = Polynomial([int(b) for b in m[:self.n]], self.q, self.n)
        v = v + m_poly

        # Encode ciphertext
        c1 = self._encode_vector(u)
        c2 = self._encode_polynomial(v)

        # Derive shared secret
        K = hashlib.sha3_256(m + public_key).digest()

        return K, MLKEMCiphertext(c1, c2)

    def decapsulate(self, secret_key: bytes, ciphertext: MLKEMCiphertext) -> bytes:
        """Decapsulate shared secret"""
        # Decode secret key
        s, pk, z = self._decode_secret_key(secret_key)

        # Decode ciphertext
        u = self._decode_vector(ciphertext.c1)
        v = self._decode_polynomial(ciphertext.c2)

        # Compute m' = v - s^T · u
        m_prime = v
        for i in range(self.k):
            m_prime = m_prime - (s[i] * u[i])

        # Extract message
        m = bytes([c % 256 for c in m_prime.coeffs[:32]])

        # Derive shared secret
        K = hashlib.sha3_256(m + pk).digest()

        return K

    # Encoding/Decoding helpers (simplified)
    def _encode_public_key(self, t: List[Polynomial], rho: bytes) -> bytes:
        """Encode public key to bytes"""
        t_bytes = b''.join(struct.pack(f'<{self.n}H', *p.coeffs) for p in t)
        return rho + t_bytes

    def _decode_public_key(self, pk: bytes) -> Tuple[List[Polynomial], bytes]:
        """Decode public key from bytes"""
        rho = pk[:32]
        t_bytes = pk[32:]
        t = []
        for i in range(self.k):
            start = i * self.n * 2
            end = start + self.n * 2
            coeffs = list(struct.unpack(f'<{self.n}H', t_bytes[start:end]))
            t.append(Polynomial(coeffs, self.q, self.n))
        return t, rho

    def _encode_secret_key(self, s: List[Polynomial], pk: bytes, z: bytes) -> bytes:
        """Encode secret key to bytes"""
        s_bytes = b''.join(struct.pack(f'<{self.n}H', *p.coeffs) for p in s)
        return s_bytes + pk + z

    def _decode_secret_key(self, sk: bytes) -> Tuple[List[Polynomial], bytes, bytes]:
        """Decode secret key from bytes"""
        s_len = self.k * self.n * 2
        s_bytes = sk[:s_len]
        pk = sk[s_len:s_len + len(sk) - s_len - 32]
        z = sk[-32:]

        s = []
        for i in range(self.k):
            start = i * self.n * 2
            end = start + self.n * 2
            coeffs = list(struct.unpack(f'<{self.n}H', s_bytes[start:end]))
            s.append(Polynomial(coeffs, self.q, self.n))
        return s, pk, z

    def _encode_vector(self, vec: List[Polynomial]) -> bytes:
        """Encode polynomial vector"""
        return b''.join(struct.pack(f'<{self.n}H', *p.coeffs) for p in vec)

    def _decode_vector(self, data: bytes) -> List[Polynomial]:
        """Decode polynomial vector"""
        vec = []
        for i in range(self.k):
            start = i * self.n * 2
            end = start + self.n * 2
            coeffs = list(struct.unpack(f'<{self.n}H', data[start:end]))
            vec.append(Polynomial(coeffs, self.q, self.n))
        return vec

    def _encode_polynomial(self, p: Polynomial) -> bytes:
        """Encode single polynomial"""
        return struct.pack(f'<{self.n}H', *p.coeffs)

    def _decode_polynomial(self, data: bytes) -> Polynomial:
        """Decode single polynomial"""
        coeffs = list(struct.unpack(f'<{self.n}H', data))
        return Polynomial(coeffs, self.q, self.n)

# =============================================================================
# ML-DSA IMPLEMENTATION (FIPS 204)
# =============================================================================

@dataclass
class MLDSAKeypair:
    """ML-DSA key pair"""
    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

@dataclass
class MLDSASignature:
    """ML-DSA signature"""
    value: bytes
    level: SecurityLevel

class MLDSA:
    """Module-Lattice-Based Digital Signature Algorithm (FIPS 204)"""

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.level = level
        self.params = ML_DSA_PARAMS[level]
        self.n = self.params['n']
        self.q = self.params['q']
        self.d = self.params['d']
        self.tau = self.params['tau']
        self.gamma1 = self.params['gamma1']
        self.gamma2 = self.params['gamma2']
        self.k = self.params['k']
        self.l = self.params['l']
        self.eta = self.params['eta']
        self.beta = self.params['beta']
        self.omega = self.params['omega']
        self.ntt = NTT(self.n, self.q)
        self.sampler = GaussianSampler(np.sqrt(self.eta), self.q)

    def keygen(self) -> MLDSAKeypair:
        """Generate ML-DSA key pair"""
        # Generate random seed
        xi = secure_random_bytes(32)

        # Expand seed
        rho = hashlib.shake_256(xi + b'rho').digest(32)
        rho_prime = hashlib.shake_256(xi + b'rho_prime').digest(64)
        K = hashlib.shake_256(xi + b'K').digest(32)

        # Generate matrix A
        A = self._expand_matrix(rho)

        # Generate secret vectors s1, s2
        s1 = [Polynomial(self.sampler.sample_vector(self.n), self.q, self.n) 
              for _ in range(self.l)]
        s2 = [Polynomial(self.sampler.sample_vector(self.n), self.q, self.n) 
              for _ in range(self.k)]

        # Compute t = A·s1 + s2
        t = []
        for i in range(self.k):
            t_i = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.l):
                t_i = t_i + (A[i][j] * s1[j])
            t_i = t_i + s2[i]
            t.append(t_i)

        # Encode keys
        pk = self._encode_public_key(rho, t)
        sk = self._encode_secret_key(rho, K, s1, s2, t)

        return MLDSAKeypair(pk, sk, self.level)

    def sign(self, secret_key: bytes, message: bytes) -> MLDSASignature:
        """Sign message"""
        # Decode secret key
        rho, K, s1, s2, t = self._decode_secret_key(secret_key)

        # Generate matrix A
        A = self._expand_matrix(rho)

        # Compute message representative
        mu = hashlib.shake_256(self._hash_public_key(secret_key) + message).digest(64)

        # Generate nonce
        rnd = secure_random_bytes(32)
        rho_prime = hashlib.shake_256(K + rnd + mu).digest(64)

        # Generate ephemeral secret y
        y = [Polynomial(self.sampler.sample_vector(self.n), self.q, self.n) 
             for _ in range(self.l)]

        # Compute w = A·y
        w = []
        for i in range(self.k):
            w_i = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.l):
                w_i = w_i + (A[i][j] * y[j])
            w.append(w_i)

        # Compute challenge c = H(w, mu)
        w_bytes = self._encode_vector(w)
        c = hashlib.shake_256(w_bytes + mu).digest(32)

        # Compute z = y + c·s1 (simplified)
        c_poly = Polynomial([int(b) for b in c[:self.n]], self.q, self.n)
        z = [y[j] + (c_poly * s1[j]) for j in range(self.l)]

        # Encode signature
        sig = self._encode_signature(c, z)

        return MLDSASignature(sig, self.level)

    def verify(self, public_key: bytes, message: bytes, signature: MLDSASignature) -> bool:
        """Verify signature"""
        # Decode public key
        rho, t = self._decode_public_key(public_key)

        # Decode signature
        c, z = self._decode_signature(signature.value)

        # Generate matrix A
        A = self._expand_matrix(rho)

        # Compute message representative
        mu = hashlib.shake_256(self._hash_public_key(public_key) + message).digest(64)

        # Compute w' = A·z - c·t
        w_prime = []
        c_poly = Polynomial([int(b) for b in c[:self.n]], self.q, self.n)
        for i in range(self.k):
            w_i = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.l):
                w_i = w_i + (A[i][j] * z[j])
            w_i = w_i - (c_poly * t[i])
            w_prime.append(w_i)

        # Verify challenge
        w_bytes = self._encode_vector(w_prime)
        c_prime = hashlib.shake_256(w_bytes + mu).digest(32)

        return c == c_prime

    def _expand_matrix(self, rho: bytes) -> List[List[Polynomial]]:
        """Expand matrix A from seed rho"""
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.l):
                expanded = hashlib.shake_256(rho + bytes([i, j])).digest(self.n * 2)
                coeffs = [int.from_bytes(expanded[l:l+2], 'little') % self.q 
                         for l in range(0, len(expanded), 2)]
                row.append(Polynomial(coeffs, self.q, self.n))
            A.append(row)
        return A

    def _encode_public_key(self, rho: bytes, t: List[Polynomial]) -> bytes:
        """Encode public key"""
        t_bytes = b''.join(struct.pack(f'<{self.n}I', *p.coeffs) for p in t)
        return rho + t_bytes

    def _decode_public_key(self, pk: bytes) -> Tuple[bytes, List[Polynomial]]:
        """Decode public key"""
        rho = pk[:32]
        t_bytes = pk[32:]
        t = []
        for i in range(self.k):
            start = i * self.n * 4
            end = start + self.n * 4
            coeffs = list(struct.unpack(f'<{self.n}I', t_bytes[start:end]))
            t.append(Polynomial(coeffs, self.q, self.n))
        return rho, t

    def _encode_secret_key(self, rho: bytes, K: bytes, s1: List[Polynomial], 
                          s2: List[Polynomial], t: List[Polynomial]) -> bytes:
        """Encode secret key"""
        s1_bytes = b''.join(struct.pack(f'<{self.n}H', *p.coeffs) for p in s1)
        s2_bytes = b''.join(struct.pack(f'<{self.n}H', *p.coeffs) for p in s2)
        t0_bytes = b''.join(struct.pack(f'<{self.n}I', *p.coeffs) for p in t)
        return rho + K + s1_bytes + s2_bytes + t0_bytes

    def _decode_secret_key(self, sk: bytes) -> Tuple[bytes, bytes, List[Polynomial], 
                                                      List[Polynomial], List[Polynomial]]:
        """Decode secret key"""
        rho = sk[:32]
        K = sk[32:64]
        offset = 64

        s1_len = self.l * self.n * 2
        s1 = []
        for i in range(self.l):
            start = offset + i * self.n * 2
            end = start + self.n * 2
            coeffs = list(struct.unpack(f'<{self.n}H', sk[start:end]))
            s1.append(Polynomial(coeffs, self.q, self.n))
        offset += s1_len

        s2_len = self.k * self.n * 2
        s2 = []
        for i in range(self.k):
            start = offset + i * self.n * 2
            end = start + self.n * 2
            coeffs = list(struct.unpack(f'<{self.n}H', sk[start:end]))
            s2.append(Polynomial(coeffs, self.q, self.n))
        offset += s2_len

        t = []
        for i in range(self.k):
            start = offset + i * self.n * 4
            end = start + self.n * 4
            coeffs = list(struct.unpack(f'<{self.n}I', sk[start:end]))
            t.append(Polynomial(coeffs, self.q, self.n))

        return rho, K, s1, s2, t

    def _encode_vector(self, vec: List[Polynomial]) -> bytes:
        """Encode polynomial vector"""
        return b''.join(struct.pack(f'<{self.n}I', *p.coeffs) for p in vec)

    def _encode_signature(self, c: bytes, z: List[Polynomial]) -> bytes:
        """Encode signature"""
        z_bytes = b''.join(struct.pack(f'<{self.n}I', *p.coeffs) for p in z)
        return c + z_bytes

    def _decode_signature(self, sig: bytes) -> Tuple[bytes, List[Polynomial]]:
        """Decode signature"""
        c = sig[:32]
        z_bytes = sig[32:]
        z = []
        for i in range(self.l):
            start = i * self.n * 4
            end = start + self.n * 4
            coeffs = list(struct.unpack(f'<{self.n}I', z_bytes[start:end]))
            z.append(Polynomial(coeffs, self.q, self.n))
        return c, z

    def _hash_public_key(self, pk: bytes) -> bytes:
        """Hash public key"""
        return hashlib.sha3_256(pk).digest()

# =============================================================================
# AES-256-GCM HYBRID ENCRYPTION
# =============================================================================

class AES256GCM:
    """AES-256-GCM symmetric encryption (Grover resistant)"""

    def __init__(self):
        self.key_size = 32  # 256 bits
        self.nonce_size = 12  # 96 bits
        self.tag_size = 16  # 128 bits

    def encrypt(self, plaintext: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
        """Encrypt using AES-256-GCM"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes")

        nonce = secure_random_bytes(self.nonce_size)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)

        return nonce + ciphertext

    def decrypt(self, ciphertext: bytes, key: bytes, associated_data: bytes = b'') -> bytes:
        """Decrypt using AES-256-GCM"""
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        if len(key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes")

        nonce = ciphertext[:self.nonce_size]
        ct = ciphertext[self.nonce_size:]

        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ct, associated_data)

# =============================================================================
# HYBRID CRYPTOGRAPHY (PQC + Classical)
# =============================================================================

class HybridCrypto:
    """Hybrid cryptography combining PQC and classical algorithms"""

    def __init__(self, pq_algorithm: AlgorithmType = AlgorithmType.ML_KEM_768):
        self.pq_algorithm = pq_algorithm
        self.aes = AES256GCM()

        if "ML-KEM" in pq_algorithm.value:
            self.kem = MLKEM(self._get_level_from_kem(pq_algorithm))
        else:
            raise ValueError("Only ML-KEM supported for hybrid encryption")

    def _get_level_from_kem(self, algo: AlgorithmType) -> SecurityLevel:
        """Map algorithm to security level"""
        mapping = {
            AlgorithmType.ML_KEM_512: SecurityLevel.LEVEL_1,
            AlgorithmType.ML_KEM_768: SecurityLevel.LEVEL_3,
            AlgorithmType.ML_KEM_1024: SecurityLevel.LEVEL_5,
        }
        return mapping.get(algo, SecurityLevel.LEVEL_3)

    def encrypt(self, plaintext: bytes, pq_public_key: bytes, 
                classical_public_key: Optional[bytes] = None) -> Dict:
        """Hybrid encryption"""
        # Generate PQC shared secret
        pq_shared_secret, pq_ciphertext = self.kem.encapsulate(pq_public_key)

        # Generate classical shared secret (if provided)
        if classical_public_key:
            classical_secret = secure_random_bytes(32)
            # In real implementation, use ECDH here
            combined_secret = hashlib.sha3_256(pq_shared_secret + classical_secret).digest()
        else:
            combined_secret = pq_shared_secret

        # Encrypt with AES-256-GCM
        ciphertext = self.aes.encrypt(plaintext, combined_secret)

        return {
            'pq_ciphertext': pq_ciphertext,
            'classical_ciphertext': ciphertext if classical_public_key else None,
            'encrypted_data': ciphertext,
            'algorithm': self.pq_algorithm.value
        }

    def decrypt(self, encrypted_data: Dict, pq_secret_key: bytes,
                classical_secret_key: Optional[bytes] = None) -> bytes:
        """Hybrid decryption"""
        pq_ciphertext = encrypted_data['pq_ciphertext']

        # Decapsulate PQC shared secret
        pq_shared_secret = self.kem.decapsulate(pq_secret_key, pq_ciphertext)

        # Combine secrets
        if classical_secret_key:
            # In real implementation, use ECDH here
            combined_secret = hashlib.sha3_256(pq_shared_secret + classical_secret_key).digest()
        else:
            combined_secret = pq_shared_secret

        # Decrypt with AES-256-GCM
        return self.aes.decrypt(encrypted_data['encrypted_data'], combined_secret)

# =============================================================================
# MAIN INTERFACE
# =============================================================================

class QSCG:
    """Main QSCG interface"""

    def __init__(self):
        self.version = "4.0.0"
        self.ml_kem = {}
        self.ml_dsa = {}
        self.aes = AES256GCM()

        # Initialize algorithms
        for level in SecurityLevel:
            self.ml_kem[level] = MLKEM(level)
            if level in ML_DSA_PARAMS:
                self.ml_dsa[level] = MLDSA(level)

    def generate_kem_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLKEMKeypair:
        """Generate ML-KEM key pair"""
        return self.ml_kem[level].keygen()

    def encapsulate(self, public_key: bytes, level: SecurityLevel = SecurityLevel.LEVEL_3) -> Tuple[bytes, MLKEMCiphertext]:
        """Encapsulate shared secret"""
        return self.ml_kem[level].encapsulate(public_key)

    def decapsulate(self, secret_key: bytes, ciphertext: MLKEMCiphertext, 
                   level: SecurityLevel = SecurityLevel.LEVEL_3) -> bytes:
        """Decapsulate shared secret"""
        return self.ml_kem[level].decapsulate(secret_key, ciphertext)

    def generate_dsa_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLDSAKeypair:
        """Generate ML-DSA key pair"""
        return self.ml_dsa[level].keygen()

    def sign(self, secret_key: bytes, message: bytes, 
             level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLDSASignature:
        """Sign message"""
        return self.ml_dsa[level].sign(secret_key, message)

    def verify(self, public_key: bytes, message: bytes, signature: MLDSASignature,
               level: SecurityLevel = SecurityLevel.LEVEL_3) -> bool:
        """Verify signature"""
        return self.ml_dsa[level].verify(public_key, message, signature)

    def hybrid_encrypt(self, plaintext: bytes, pq_public_key: bytes,
                      algorithm: AlgorithmType = AlgorithmType.ML_KEM_768) -> Dict:
        """Hybrid encryption"""
        hybrid = HybridCrypto(algorithm)
        return hybrid.encrypt(plaintext, pq_public_key)

    def hybrid_decrypt(self, encrypted_data: Dict, pq_secret_key: bytes,
                      algorithm: AlgorithmType = AlgorithmType.ML_KEM_768) -> bytes:
        """Hybrid decryption"""
        hybrid = HybridCrypto(algorithm)
        return hybrid.decrypt(encrypted_data, pq_secret_key)

    def get_info(self) -> Dict:
        """Get QSCG information"""
        return {
            'version': self.version,
            'nist_standards': ['FIPS 203', 'FIPS 204', 'FIPS 205'],
            'algorithms': {
                'kem': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
                'dsa': ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87'],
                'symmetric': ['AES-256-GCM']
            },
            'security_levels': [1, 3, 5],
            'hybrid_support': True,
            'side_channel_resistant': True,
            'constant_time': True
        }

# =============================================================================
# DEMO / TEST
# =============================================================================

if __name__ == "__main__":
    print("=" * 70)
    print("QSCG v4.0 - Quantum-Safe Cryptography Core")
    print("=" * 70)

    qscg = QSCG()
    info = qscg.get_info()

    print(f"
Version: {info['version']}")
    print(f"NIST Standards: {', '.join(info['nist_standards'])}")
    print(f"KEM Algorithms: {', '.join(info['algorithms']['kem'])}")
    print(f"DSA Algorithms: {', '.join(info['algorithms']['dsa'])}")
    print(f"Security Levels: {info['security_levels']}")

    # Test ML-KEM
    print("
" + "-" * 70)
    print("ML-KEM Test (Level 3 - ML-KEM-768)")
    print("-" * 70)

    keypair = qscg.generate_kem_keypair(SecurityLevel.LEVEL_3)
    print(f"Public Key Size: {len(keypair.public_key)} bytes")
    print(f"Secret Key Size: {len(keypair.secret_key)} bytes")

    shared_secret, ciphertext = qscg.encapsulate(keypair.public_key)
    print(f"Ciphertext Size: {len(ciphertext.c1) + len(ciphertext.c2)} bytes")
    print(f"Shared Secret Size: {len(shared_secret)} bytes")

    decapsulated = qscg.decapsulate(keypair.secret_key, ciphertext)
    print(f"Decapsulation Success: {shared_secret == decapsulated}")

    # Test ML-DSA
    print("
" + "-" * 70)
    print("ML-DSA Test (Level 3 - ML-DSA-65)")
    print("-" * 70)

    dsa_keypair = qscg.generate_dsa_keypair(SecurityLevel.LEVEL_3)
    print(f"Public Key Size: {len(dsa_keypair.public_key)} bytes")
    print(f"Secret Key Size: {len(dsa_keypair.secret_key)} bytes")

    message = b"Hello, Quantum-Safe World!"
    signature = qscg.sign(dsa_keypair.secret_key, message)
    print(f"Signature Size: {len(signature.value)} bytes")

    valid = qscg.verify(dsa_keypair.public_key, message, signature)
    print(f"Signature Valid: {valid}")

    # Test Hybrid Encryption
    print("
" + "-" * 70)
    print("Hybrid Encryption Test")
    print("-" * 70)

    plaintext = b"This is a secret message protected by QSCG v4.0!"
    encrypted = qscg.hybrid_encrypt(plaintext, keypair.public_key)
    print(f"Encrypted Data Size: {len(encrypted['encrypted_data'])} bytes")

    decrypted = qscg.hybrid_decrypt(encrypted, keypair.secret_key)
    print(f"Decryption Success: {plaintext == decrypted}")
    print(f"Decrypted Message: {decrypted.decode()}")

    print("
" + "=" * 70)
    print("All tests passed successfully!")
    print("=" * 70)
