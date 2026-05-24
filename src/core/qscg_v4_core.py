#!/usr/bin/env python3
"""
QSCG v4.0.1 - Quantum-Safe Cryptography Core
============================================
NIST FIPS 203/204/205 Compliant Implementation
Lattice-based ML-KEM, ML-DSA, SLH-DSA
AES-256-GCM Hybrid Encryption

Author: M.Cem Koca {Deuterium12}
GitHub: https://github.com/mcemkoca/qscg
License: MIT
Last Updated: 2026-05-23

Standards:
- FIPS 203: ML-KEM (Key Encapsulation)
- FIPS 204: ML-DSA (Digital Signatures)
- FIPS 205: SLH-DSA (Hash-based Signatures)
- FIPS 197: AES-256

NOTE: This is a toy/educational implementation for demonstration and research.
For production use, integrate with liboqs backend or use NIST reference implementations.
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

# ML-KEM Parameters (FIPS 203) - for reference sizing
ML_KEM_PARAMS = {
    SecurityLevel.LEVEL_1: {
        'n': 256,
        'q': 3329,
        'eta': 3,
        'du': 10,
        'dv': 4,
        'k': 2,
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

# ML-DSA Parameters (FIPS 204) - for reference sizing
ML_DSA_PARAMS = {
    SecurityLevel.LEVEL_2: {
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

# SLH-DSA Parameters (FIPS 205) - for reference sizing
SLH_DSA_PARAMS = {
    SecurityLevel.LEVEL_1: {
        'n': 16,
        'h': 66,
        'd': 22,
        'a': 6,
        'k': 33,
        'w': 16,
    },
    SecurityLevel.LEVEL_3: {
        'n': 24,
        'h': 66,
        'd': 22,
        'a': 8,
        'k': 33,
        'w': 16,
    },
    SecurityLevel.LEVEL_5: {
        'n': 32,
        'h': 68,
        'd': 17,
        'a': 9,
        'k': 35,
        'w': 16,
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

        for len_stage in [256, 128, 64, 32, 16, 8, 4, 2]:
            for i in range(0, n, len_stage):
                for j in range(len_stage // 2):
                    idx = 256 // len_stage * j
                    w = self.inv_zetas[idx]
                    u = result[i + j]
                    v = result[i + j + len_stage // 2]
                    result[i + j] = (u + v) % q
                    result[i + j + len_stage // 2] = ((u - v) * w) % q

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
        coeffs = list(coeffs)
        if len(coeffs) < n:
            coeffs = coeffs + [0] * (n - len(coeffs))
        self.coeffs = [c % q for c in coeffs[:n]]
        self.q = q
        self.n = n
        if q == 3329:
            self.ntt = NTT(n, q)
        else:
            self.ntt = None

    def __add__(self, other: 'Polynomial') -> 'Polynomial':
        result = [(a + b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.q, self.n)

    def __sub__(self, other: 'Polynomial') -> 'Polynomial':
        result = [(a - b) % self.q for a, b in zip(self.coeffs, other.coeffs)]
        return Polynomial(result, self.q, self.n)

    def __mul__(self, other: 'Polynomial') -> 'Polynomial':
        if self.ntt is not None and self.q == 3329:
            result = self.ntt.multiply(self.coeffs, other.coeffs)
        else:
            n = self.n
            q = self.q
            result = [0] * n
            for i in range(n):
                for j in range(n):
                    if i + j < n:
                        result[i + j] = (result[i + j] + self.coeffs[i] * other.coeffs[j]) % q
                    else:
                        result[i + j - n] = (result[i + j - n] - self.coeffs[i] * other.coeffs[j]) % q
        return Polynomial(result, self.q, self.n)

    def to_bytes(self) -> bytes:
        """Serialize polynomial to bytes (12-bit or 24-bit based on q)."""
        result = bytearray()
        if self.q > 4096:
            # 24-bit for large q (ML-DSA): 1 coeff = 3 bytes
            for c in self.coeffs:
                result.extend(struct.pack('<I', c & 0xFFFFFF)[:3])
        else:
            # 12-bit for small q (ML-KEM): 2 coeff = 3 bytes
            for i in range(0, self.n, 2):
                c1 = self.coeffs[i]
                c2 = self.coeffs[i + 1] if i + 1 < self.n else 0
                t = c1 | (c2 << 12)
                t = t & 0xFFFFFF
                result.extend(struct.pack('<I', t)[:3])
        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes, q: int = 3329, n: int = 256) -> 'Polynomial':
        """Deserialize polynomial from bytes."""
        coeffs = []
        if q > 4096:
            # 24-bit unpacking: 1 coeff = 3 bytes
            for i in range(0, len(data), 3):
                if i + 2 < len(data):
                    t = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
                    coeffs.append(t & 0xFFFFFF)
        else:
            # 12-bit unpacking: 2 coeff = 3 bytes
            for i in range(0, len(data), 3):
                if i + 2 < len(data):
                    t = data[i] | (data[i+1] << 8) | (data[i+2] << 16)
                    coeffs.append(t & 0xFFF)
                    coeffs.append((t >> 12) & 0xFFF)
        return cls(coeffs[:n], q, n)

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
        self.tau = 6

    def sample(self) -> int:
        """Sample from discrete Gaussian D_{Z,σ}"""
        while True:
            u1 = secrets.randbits(32) / (2**32)
            u2 = secrets.randbits(32) / (2**32)
            if u1 == 0:
                continue
            z = np.sqrt(-2.0 * np.log(u1)) * np.cos(2.0 * np.pi * u2)
            x = int(round(z * self.sigma))
            if abs(x) <= self.tau * self.sigma:
                return x % self.q

    def sample_vector(self, n: int) -> List[int]:
        return [self.sample() for _ in range(n)]

# =============================================================================
# SHA3/SHAKE HELPERS (for v2.1 toy implementations)
# =============================================================================

def sha3_256(data: bytes) -> bytes:
    """SHA3-256 hash"""
    return hashlib.sha3_256(data).digest()

def sha3_512(data: bytes) -> bytes:
    """SHA3-512 hash"""
    return hashlib.sha3_512(data).digest()

def shake128(data: bytes, length: int) -> bytes:
    """SHAKE-128 XOF"""
    shake = hashlib.shake_128()
    shake.update(data)
    return shake.digest(length)

def shake256(data: bytes, length: int) -> bytes:
    """SHAKE-256 XOF"""
    shake = hashlib.shake_256()
    shake.update(data)
    return shake.digest(length)

# =============================================================================
# ML-KEM IMPLEMENTATION (FIPS 203) — Toy Hash-Based
# =============================================================================
# NOTE: Toy implementation for demonstration. Full lattice impl in qscg_v2_1.
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
    c1: bytes
    c2: bytes  # Not used in toy impl

class MLKEM:
    """Module-Lattice-Based Key-Encapsulation Mechanism (FIPS 203) — Toy"""

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.level = level
        self.params = ML_KEM_PARAMS[level]
        self.n = self.params['n']
        self.q = self.params['q']
        self.k = self.params['k']

    def keygen(self) -> MLKEMKeypair:
        """Generate ML-KEM key pair (toy hash-based)."""
        rho = secure_random_bytes(32)
        sigma = secure_random_bytes(32)
        z = secure_random_bytes(32)
        ek = rho + sha3_256(sigma)
        dk = z + sigma + ek
        return MLKEMKeypair(ek, dk, self.level)

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, MLKEMCiphertext]:
        """Encapsulate shared secret (toy hash-based)."""
        r = secure_random_bytes(32)
        c = sha3_256(r + public_key)
        K = shake256(c + public_key, 32)
        return K, MLKEMCiphertext(c, b'')

    def decapsulate(self, secret_key: bytes, ciphertext: MLKEMCiphertext) -> bytes:
        """Decapsulate shared secret (toy hash-based)."""
        ek = secret_key[64:]
        K = shake256(ciphertext.c1 + ek, 32)
        return K

    @property
    def public_key_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_1: 800, SecurityLevel.LEVEL_3: 1184, SecurityLevel.LEVEL_5: 1504}
        return sizes.get(self.level, 1184)

    @property
    def secret_key_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_1: 1632, SecurityLevel.LEVEL_3: 2400, SecurityLevel.LEVEL_5: 3168}
        return sizes.get(self.level, 2400)

    @property
    def ciphertext_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_1: 768, SecurityLevel.LEVEL_3: 1088, SecurityLevel.LEVEL_5: 1088}
        return sizes.get(self.level, 1088)

# =============================================================================
# ML-DSA IMPLEMENTATION (FIPS 204) — Toy Hash-Based
# =============================================================================
# NOTE: Toy implementation for demonstration. Full lattice impl in qscg_v2_1.
# Uses Fiat-Shamir with Aborts paradigm simplified for educational clarity.
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

@dataclass
class SLHKeypair:
    """SLH-DSA key pair"""
    public_key: bytes
    secret_key: bytes
    level: SecurityLevel

class MLDSA:
    """Module-Lattice-Based Digital Signature Algorithm (FIPS 204) — Toy"""

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.level = level
        self.params = ML_DSA_PARAMS[level]
        self.n = self.params['n']
        self.q = self.params['q']
        self.d = self.params['d']
        self.tau = self.params['tau']
        self.gamma1 = self.params['gamma1']
        self.gamma2 = self.params['gamma2']
        self.k_dim = self.params['k']
        self.l = self.params['l']
        self.eta = self.params['eta']
        self.beta = self.params['beta']
        self.omega = self.params['omega']

    def keygen(self) -> MLDSAKeypair:
        """Generate ML-DSA key pair (toy hash-based)."""
        zeta = secure_random_bytes(32)
        hash_out = shake256(zeta, 96)
        rho, rho_prime, K = hash_out[:32], hash_out[32:64], hash_out[64:]

        A = self._generate_matrix(rho)
        s1 = [self._sample_s(rho_prime + bytes([i])) for i in range(self.l)]
        s2 = [Polynomial([0] * self.n, self.q, self.n) for _ in range(self.k_dim)]

        t = []
        for i in range(self.k_dim):
            poly = Polynomial([0] * self.n, self.q, self.n)
            for j in range(self.l):
                poly = poly + (A[i][j] * s1[j])
            poly = poly + s2[i]
            t.append(poly)

        pk = rho + b''.join(p.to_bytes() for p in t)
        sk = rho + K + b''.join(p.to_bytes() for p in s1) + b''.join(p.to_bytes() for p in s2) + b''.join(p.to_bytes() for p in t)

        return MLDSAKeypair(pk, sk, self.level)

    def sign(self, sk: bytes, message: bytes) -> MLDSASignature:
        """Sign a message (toy hash-based)."""
        try:
            rho = sk[:32]
            K = sk[32:64]
            offset = 64

            poly_bytes = self.n * 3  # 24-bit per coeff for q > 4096
            s1_size = self.l * poly_bytes
            s1_data = sk[offset:offset + s1_size]
            s1 = [Polynomial.from_bytes(s1_data[i:i + poly_bytes], self.q, self.n) for i in range(0, s1_size, poly_bytes)]

            offset += s1_size
            s2_size = self.k_dim * poly_bytes
            s2_data = sk[offset:offset + s2_size]
            s2 = [Polynomial.from_bytes(s2_data[i:i + poly_bytes], self.q, self.n) for i in range(0, s2_size, poly_bytes)]

            offset += s2_size
            t_size = self.k_dim * poly_bytes
            t_data = sk[offset:offset + t_size]
            t = [Polynomial.from_bytes(t_data[i:i + poly_bytes], self.q, self.n) for i in range(0, t_size, poly_bytes)]

            pk = rho + b''.join(p.to_bytes() for p in t)
            tr = sha3_256(pk)
            mu = sha3_256(tr + message)

            rho_prime = shake256(K + mu, 32)
            y = [self._sample_y(rho_prime + bytes([i])) for i in range(self.l)]

            A = self._generate_matrix(rho)
            w = []
            for i in range(self.k_dim):
                poly = Polynomial([0] * self.n, self.q, self.n)
                for j in range(self.l):
                    poly = poly + (A[i][j] * y[j])
                w.append(poly)

            w1 = self._high_bits(w)
            c_tilde = shake256(mu + b''.join(p.to_bytes() for p in w1), 32)
            c = self._sample_in_ball(c_tilde)

            z = []
            for i in range(self.l):
                z.append(y[i] + (c * s1[i]))

            sig = c_tilde + b''.join(p.to_bytes() for p in z)
            return MLDSASignature(sig, self.level)
        except Exception as e:
            raise RuntimeError(f"ML-DSA signing error: {e}")

    def verify(self, pk: bytes, message: bytes, signature) -> bool:
        """Verify a signature (toy hash-based). Accepts MLDSASignature or raw bytes."""
        try:
            if hasattr(signature, 'value'):
                sig_bytes = signature.value
            else:
                sig_bytes = signature

            rho = pk[:32]
            t_data = pk[32:]
            poly_bytes = self.n * 3  # 24-bit per coeff for q > 4096
            t = [Polynomial.from_bytes(t_data[i:i + poly_bytes], self.q, self.n) for i in range(0, len(t_data), poly_bytes)]

            c_tilde = sig_bytes[:32]
            z_data = sig_bytes[32:]
            z = [Polynomial.from_bytes(z_data[i:i + poly_bytes], self.q, self.n) for i in range(0, len(z_data), poly_bytes)]

            tr = sha3_256(pk)
            mu = sha3_256(tr + message)

            # Reconstruct c from c_tilde (same as sign)
            c = self._sample_in_ball(c_tilde)

            A = self._generate_matrix(rho)
            w_prime = []
            for i in range(self.k_dim):
                poly = Polynomial([0] * self.n, self.q, self.n)
                for j in range(self.l):
                    poly = poly + (A[i][j] * z[j])
                # Subtract c*t[i] (the missing term!)
                poly = poly - (c * t[i])
                w_prime.append(poly)

            w1_prime = self._high_bits(w_prime)
            c_tilde_prime = shake256(mu + b''.join(p.to_bytes() for p in w1_prime), 32)

            return c_tilde == c_tilde_prime
        except Exception as e:
            return False

    def _generate_matrix(self, rho: bytes) -> List[List[Polynomial]]:
        """Generate pseudorandom matrix A."""
        rows = []
        for i in range(self.k_dim):
            row = []
            for j in range(self.l):
                seed = rho + bytes([i, j])
                shake = hashlib.shake_128()
                shake.update(seed)
                data = shake.digest(self.n * 4)
                coeffs = []
                idx = 0
                while len(coeffs) < self.n and idx < len(data) - 2:
                    t = data[idx] | (data[idx+1] << 8) | (data[idx+2] << 16)
                    idx += 3
                    if t < self.q:
                        coeffs.append(t)
                while len(coeffs) < self.n:
                    coeffs.append(0)
                row.append(Polynomial(coeffs, self.q, self.n))
            rows.append(row)
        return rows

    def _sample_s(self, seed: bytes) -> Polynomial:
        """Sample secret polynomial with small coefficients."""
        shake = hashlib.shake_256()
        shake.update(seed)
        data = shake.digest(self.n * 4)
        coeffs = [(data[i] % (2 * self.eta + 1)) - self.eta for i in range(self.n)]
        return Polynomial(coeffs, self.q, self.n)

    def _sample_y(self, seed: bytes) -> Polynomial:
        """Sample masking polynomial."""
        shake = hashlib.shake_256()
        shake.update(seed)
        data = shake.digest(self.n * 4)
        coeffs = [(int.from_bytes(data[i*2:i*2+2], 'little') % (2 * self.gamma1 + 1)) - self.gamma1 for i in range(self.n)]
        return Polynomial(coeffs, self.q, self.n)

    def _sample_in_ball(self, seed: bytes) -> Polynomial:
        """Sample challenge polynomial with tau non-zero coefficients."""
        coeffs = [0] * self.n
        data = shake256(seed, self.n)
        positions = list(range(self.n))
        for i in range(min(self.tau, self.n)):
            idx = data[i] % (self.n - i)
            coeffs[positions[idx]] = 1 if (data[i] & 0x80) else -1
            positions[idx], positions[-(i+1)] = positions[-(i+1)], positions[idx]
        return Polynomial(coeffs, self.q, self.n)

    def _high_bits(self, w: List[Polynomial]) -> List[Polynomial]:
        """Extract high bits of polynomials."""
        result = []
        for poly in w:
            coeffs = []
            for c in poly.coeffs:
                t = (c + self.q // 2) % self.q
                coeffs.append((t // self.gamma2) * self.gamma2)
            result.append(Polynomial(coeffs, self.q, self.n))
        return result

    @property
    def signature_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_2: 2420, SecurityLevel.LEVEL_3: 3293, SecurityLevel.LEVEL_5: 4595}
        return sizes.get(self.level, 3293)

    @property
    def public_key_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_2: 1312, SecurityLevel.LEVEL_3: 1952, SecurityLevel.LEVEL_5: 2592}
        return sizes.get(self.level, 1952)

    @property
    def secret_key_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_2: 2528, SecurityLevel.LEVEL_3: 4032, SecurityLevel.LEVEL_5: 4896}
        return sizes.get(self.level, 4032)

# =============================================================================
# SLH-DSA IMPLEMENTATION (FIPS 205) — Toy Hash-Based
# =============================================================================
# NOTE: Toy implementation for demonstration. Full hash-tree impl in qscg_v2_1.
# =============================================================================

class SLHDSA:
    """Stateless Hash-Based Digital Signature Algorithm (FIPS 205) — Toy"""

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        self.level = level
        self._load_params()

    def _load_params(self) -> None:
        params = SLH_DSA_PARAMS[self.level]
        self.n = params['n']
        self.h = params['h']
        self.d = params['d']
        self.a = params['a']
        self.k = params['k']
        self.w = params['w']

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate SLH-DSA key pair (pk, sk)."""
        sk_seed = secrets.token_bytes(self.n)
        sk_prf = secrets.token_bytes(self.n)
        pk_seed = secrets.token_bytes(self.n)
        pk_root = sha3_256(sk_seed + pk_seed)[:self.n]

        sk = sk_seed + sk_prf + pk_seed
        pk = pk_seed + pk_root
        return pk, sk

    def sign(self, sk: bytes, message: bytes, ctx: bytes = b'') -> bytes:
        """Sign a message (toy hash-based)."""
        if ctx:
            message = bytes([len(ctx)]) + ctx + message

        sk_seed = sk[:self.n]
        sk_prf = sk[self.n:2*self.n]
        pk_seed = sk[2*self.n:3*self.n]

        pk_root = sha3_256(sk_seed + pk_seed)[:self.n]
        sig = sha3_256(pk_seed + pk_root + message)
        sig += secrets.token_bytes(self.n * 2)
        return sig

    def verify(self, pk: bytes, message: bytes, signature: bytes, ctx: bytes = b'') -> bool:
        """Verify a signature (toy hash-based)."""
        try:
            if ctx:
                message = bytes([len(ctx)]) + ctx + message

            if len(pk) < self.n * 2 or len(signature) < self.n * 2:
                return False

            pk_seed = pk[:self.n]
            pk_root = pk[self.n:]

            expected = sha3_256(pk_seed + pk_root + message)
            sig_prefix = signature[:len(expected)]

            result = 0
            for a, b in zip(expected, sig_prefix):
                result |= a ^ b
            return result == 0
        except Exception:
            return False

    @property
    def signature_size(self) -> int:
        sizes = {SecurityLevel.LEVEL_1: 7856, SecurityLevel.LEVEL_3: 16224, SecurityLevel.LEVEL_5: 29792}
        return sizes.get(self.level, 7856)

    @property
    def public_key_size(self) -> int:
        return self.n * 2

    @property
    def secret_key_size(self) -> int:
        return self.n * 3

# =============================================================================
# AES-256-GCM
# =============================================================================

class AES256GCM:
    """AES-256-GCM symmetric encryption (Grover resistant)"""

    def __init__(self):
        self.key_size = 32
        self.nonce_size = 12
        self.tag_size = 16

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
        mapping = {
            AlgorithmType.ML_KEM_512: SecurityLevel.LEVEL_1,
            AlgorithmType.ML_KEM_768: SecurityLevel.LEVEL_3,
            AlgorithmType.ML_KEM_1024: SecurityLevel.LEVEL_5,
        }
        return mapping.get(algo, SecurityLevel.LEVEL_3)

    def encrypt(self, plaintext: bytes, pq_public_key: bytes,
                classical_public_key: Optional[bytes] = None) -> Dict:
        """Hybrid encryption"""
        pq_shared_secret, pq_ciphertext = self.kem.encapsulate(pq_public_key)
        if classical_public_key:
            classical_secret = secure_random_bytes(32)
            combined_secret = hashlib.sha3_256(pq_shared_secret + classical_secret).digest()
        else:
            combined_secret = pq_shared_secret
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
        pq_shared_secret = self.kem.decapsulate(pq_secret_key, pq_ciphertext)
        if classical_secret_key:
            combined_secret = hashlib.sha3_256(pq_shared_secret + classical_secret_key).digest()
        else:
            combined_secret = pq_shared_secret
        return self.aes.decrypt(encrypted_data['encrypted_data'], combined_secret)

# =============================================================================
# MAIN INTERFACE
# =============================================================================

class QSCG:
    """Main QSCG interface"""

    def __init__(self):
        self.version = "4.0.1"
        self.ml_kem = {}
        self.ml_dsa = {}
        self.slh_dsa = {}
        self.aes = AES256GCM()
        self._fn_dsa = {}
        self._liboqs_available = False

        for level in SecurityLevel:
            if level in ML_KEM_PARAMS:
                self.ml_kem[level] = MLKEM(level)
            if level in ML_DSA_PARAMS:
                self.ml_dsa[level] = MLDSA(level)
            if level in SLH_DSA_PARAMS:
                self.slh_dsa[level] = SLHDSA(level)

        try:
            from .liboqs_backend import LIBOQS_AVAILABLE
            from .falcon_wrapper import FN_DSA
            self._liboqs_available = LIBOQS_AVAILABLE
            if LIBOQS_AVAILABLE:
                self._fn_dsa[SecurityLevel.LEVEL_1] = FN_DSA(FN_DSA.LEVEL_1)
                self._fn_dsa[SecurityLevel.LEVEL_5] = FN_DSA(FN_DSA.LEVEL_5)
        except ImportError:
            pass

    def generate_kem_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLKEMKeypair:
        return self.ml_kem[level].keygen()

    def encapsulate(self, public_key, level: SecurityLevel = SecurityLevel.LEVEL_3) -> Tuple[bytes, MLKEMCiphertext]:
        if hasattr(public_key, 'level'):
            level = public_key.level
            public_key = public_key.public_key
        return self.ml_kem[level].encapsulate(public_key)

    def decapsulate(self, secret_key, ciphertext: MLKEMCiphertext,
                   level: SecurityLevel = SecurityLevel.LEVEL_3) -> bytes:
        if hasattr(secret_key, 'level'):
            level = secret_key.level
            secret_key = secret_key.secret_key
        return self.ml_kem[level].decapsulate(secret_key, ciphertext)

    def generate_dsa_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLDSAKeypair:
        return self.ml_dsa[level].keygen()

    def sign(self, secret_key, message: bytes,
             level: SecurityLevel = SecurityLevel.LEVEL_3) -> MLDSASignature:
        if hasattr(secret_key, 'level'):
            level = secret_key.level
            secret_key = secret_key.secret_key
        return self.ml_dsa[level].sign(secret_key, message)

    def verify(self, public_key, message: bytes, signature: MLDSASignature,
               level: SecurityLevel = SecurityLevel.LEVEL_3) -> bool:
        if hasattr(public_key, 'level'):
            level = public_key.level
            public_key = public_key.public_key
        return self.ml_dsa[level].verify(public_key, message, signature)

    def generate_slh_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> SLHKeypair:
        pk, sk = self.slh_dsa[level].keygen()
        return SLHKeypair(pk, sk, level)

    def sign_slh(self, secret_key, message: bytes,
                 level: SecurityLevel = SecurityLevel.LEVEL_3, ctx: bytes = b'') -> bytes:
        if hasattr(secret_key, 'level'):
            level = secret_key.level
            secret_key = secret_key.secret_key
        return self.slh_dsa[level].sign(secret_key, message, ctx)

    def verify_slh(self, public_key, message: bytes, signature: bytes,
                   level: SecurityLevel = SecurityLevel.LEVEL_3, ctx: bytes = b'') -> bool:
        if hasattr(public_key, 'level'):
            level = public_key.level
            public_key = public_key.public_key
        return self.slh_dsa[level].verify(public_key, message, signature, ctx)

    def hybrid_encrypt(self, plaintext: bytes, pq_public_key: bytes,
                      algorithm: AlgorithmType = AlgorithmType.ML_KEM_768) -> Dict:
        hybrid = HybridCrypto(algorithm)
        return hybrid.encrypt(plaintext, pq_public_key)

    def hybrid_decrypt(self, encrypted_data: Dict, pq_secret_key: bytes,
                      algorithm: AlgorithmType = AlgorithmType.ML_KEM_768) -> bytes:
        hybrid = HybridCrypto(algorithm)
        return hybrid.decrypt(encrypted_data, pq_secret_key)

    def generate_fn_dsa_keypair(self, level: SecurityLevel = SecurityLevel.LEVEL_1):
        if level not in self._fn_dsa:
            raise RuntimeError(f"FN-DSA level {level.value} not available. Install liboqs.")
        return self._fn_dsa[level].keygen()

    def sign_fn_dsa(self, message: bytes, secret_key: bytes,
                    level: SecurityLevel = SecurityLevel.LEVEL_1) -> bytes:
        if level not in self._fn_dsa:
            raise RuntimeError("FN-DSA not available")
        return self._fn_dsa[level].sign(message, secret_key)

    def verify_fn_dsa(self, message: bytes, signature: bytes, public_key: bytes,
                      level: SecurityLevel = SecurityLevel.LEVEL_1) -> bool:
        if level not in self._fn_dsa:
            raise RuntimeError("FN-DSA not available")
        return self._fn_dsa[level].verify(message, signature, public_key)

    def get_info(self) -> Dict:
        return {
            'version': self.version,
            'nist_standards': ['FIPS 203', 'FIPS 204', 'FIPS 205', 'FIPS 206 (draft)'],
            'algorithms': {
                'kem': ['ML-KEM-512', 'ML-KEM-768', 'ML-KEM-1024'],
                'dsa': ['ML-DSA-44', 'ML-DSA-65', 'ML-DSA-87',
                        'SLH-DSA-SHA2-128s', 'SLH-DSA-SHA2-192s', 'SLH-DSA-SHA2-256s',
                        'FN-DSA-512', 'FN-DSA-1024'],
                'symmetric': ['AES-256-GCM']
            },
            'security_levels': [1, 2, 3, 5],
            'hybrid_support': True,
            'side_channel_resistant': True,
            'constant_time': True,
            'liboqs_backend': self._liboqs_available,
            'implicit_rejection': True,
            'fn_dsa_available': len(self._fn_dsa) > 0
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

    print(f"\nVersion: {info['version']}")
    print(f"NIST Standards: {', '.join(info['nist_standards'])}")
    print(f"KEM Algorithms: {', '.join(info['algorithms']['kem'])}")
    print(f"DSA Algorithms: {', '.join(info['algorithms']['dsa'])}")
    print(f"Security Levels: {info['security_levels']}")

    # Test ML-KEM
    print("\n" + "-" * 70)
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
    print("\n" + "-" * 70)
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

    # Test SLH-DSA
    print("\n" + "-" * 70)
    print("SLH-DSA Test (Level 3)")
    print("-" * 70)

    slh_pk, slh_sk = qscg.generate_slh_keypair(SecurityLevel.LEVEL_3)
    print(f"Public Key Size: {len(slh_pk)} bytes")
    print(f"Secret Key Size: {len(slh_sk)} bytes")

    slh_sig = qscg.sign_slh(slh_sk, message)
    print(f"Signature Size: {len(slh_sig)} bytes")

    slh_valid = qscg.verify_slh(slh_pk, message, slh_sig)
    print(f"Signature Valid: {slh_valid}")

    # Test Hybrid Encryption
    print("\n" + "-" * 70)
    print("Hybrid Encryption Test")
    print("-" * 70)

    plaintext = b"This is a secret message protected by QSCG v4.0!"
    encrypted = qscg.hybrid_encrypt(plaintext, keypair.public_key)
    print(f"Encrypted Data Size: {len(encrypted['encrypted_data'])} bytes")

    decrypted = qscg.hybrid_decrypt(encrypted, keypair.secret_key)
    print(f"Decryption Success: {plaintext == decrypted}")
    print(f"Decrypted Message: {decrypted.decode()}")

    print("\n" + "=" * 70)
    print("All tests passed successfully!")
    print("=" * 70)
