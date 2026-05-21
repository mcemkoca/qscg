"""ML-DSA: Module-Lattice-Based Digital Signature Algorithm (FIPS 204, Algorithm 1-3).

This module implements the EUF-CMA secure signature scheme using the
Fiat-Shamir with Aborts paradigm over module lattices (CRYSTALS-Dilithium).

Classes
-------
:class:`MLDSA` -- the main signature scheme with KeyGen, Sign, and Verify.

Supported parameter sets
------------------------
+-----------+------+------+-----+------+--------+--------+-------+
| Name      | k    | l    | eta | tau  | gamma1 | gamma2 | omega |
+===========+======+======+=====+======+========+========+=======+
| ML-DSA-44 | 4    | 4    | 2   | 39   | 2^17   | 95232  | 80    |
+-----------+------+------+-----+------+--------+--------+-------+
| ML-DSA-65 | 6    | 5    | 4   | 49   | 2^19   | 261888 | 80    |
+-----------+------+------+-----+------+--------+--------+-------+
| ML-DSA-87 | 8    | 7    | 2   | 60   | 2^19   | 261888 | 128   |
+-----------+------+------+-----+------+--------+--------+-------+

Example::

    >>> from qscg.ml_dsa.ml_dsa import MLDSA
    >>> from qscg.common.constants import SecurityLevel
    >>> dsa = MLDSA(SecurityLevel.LEVEL_3)
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Quantum-safe message")
    >>> assert dsa.verify(pk, b"Quantum-safe message", sig)

References:
    - NIST FIPS 204, Section 5 -- ML-DSA
    - CRYSTALS-Dilithium reference implementation (pq-crystals.org)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Tuple, List, Optional

from ..common.constants import (
    SecurityLevel,
    MLDSA_Q,
    MLDSA_N,
    MLDSA_D,
    MLDSA_PARAMS,
)
from ..common.utilities import generate_random_bytes, center_reduce
from .polynomial import Polynomial, PolyVector
from . import ntt
from . import sampling
from . import encode

Q: int = MLDSA_Q
"""Coefficient modulus."""

N: int = MLDSA_N
"""Polynomial degree."""

D: int = MLDSA_D
"""Power-of-two rounding bits."""


# ============================================================================
# Key, signature, and hint encoding (FIPS 204, Section 5)
# ============================================================================

def _pk_encode(rho: bytes, t1: PolyVector, k: int, d: int) -> bytes:
    """Encode public key: pk = rho || t1_encode.

    t1 uses (bitlen(q-1) - d) bits per coefficient.
    """
    t1_bits = (Q - 1).bit_length() - d
    max_val = (1 << t1_bits) - 1
    packed = b"".join(
        encode.SimpleBitPack(p.coeffs, max_val) for p in t1.polys
    )
    return rho + packed


def _pk_decode(pk: bytes, k: int, d: int) -> Tuple[bytes, PolyVector]:
    """Decode public key. Returns ``(rho, t1)``."""
    rho = pk[:32]
    t1_bits = (Q - 1).bit_length() - d
    max_val = (1 << t1_bits) - 1
    packed_len = (N * t1_bits + 7) // 8
    offset = 32
    t1_polys = []
    for _ in range(k):
        coeffs = encode.SimpleBitUnpack(pk[offset:offset + packed_len], max_val)
        t1_polys.append(Polynomial(coeffs))
        offset += packed_len
    return rho, PolyVector(t1_polys)


def _sk_encode(
    rho: bytes,
    K: bytes,
    tr: bytes,
    s1: PolyVector,
    s2: PolyVector,
    t0: PolyVector,
    l: int,
    k: int,
    eta: int,
    d: int,
) -> bytes:
    """Encode secret key."""
    s1_packed = b"".join(
        encode.BitPack([center_reduce(c, Q) for c in p.coeffs], eta, eta)
        for p in s1.polys
    )
    s2_packed = b"".join(
        encode.BitPack([center_reduce(c, Q) for c in p.coeffs], eta, eta)
        for p in s2.polys
    )
    max_t0 = (1 << (d - 1)) - 1
    t0_packed = b"".join(
        encode.BitPack([center_reduce(c, Q) for c in p.coeffs], (1 << (d - 1)) - 1, 1 << (d - 1))
        for p in t0.polys
    )
    return rho + K + tr + s1_packed + s2_packed + t0_packed


def _sk_decode(
    sk: bytes, l: int, k: int, eta: int, d: int
) -> Tuple[bytes, bytes, bytes, PolyVector, PolyVector, PolyVector]:
    """Decode secret key. Returns ``(rho, K, tr, s1, s2, t0)``."""
    offset = 0
    rho = sk[offset:offset + 32]
    offset += 32
    K = sk[offset:offset + 32]
    offset += 32
    tr = sk[offset:offset + 32]
    offset += 32

    s1_coeff_bits = (2 * eta).bit_length()
    s1_poly_len = (N * s1_coeff_bits + 7) // 8
    s1_polys = []
    for _ in range(l):
        coeffs = encode.BitUnpack(sk[offset:offset + s1_poly_len], eta, eta)
        s1_polys.append(Polynomial(coeffs))
        offset += s1_poly_len

    s2_poly_len = (N * s1_coeff_bits + 7) // 8
    s2_polys = []
    for _ in range(k):
        coeffs = encode.BitUnpack(sk[offset:offset + s2_poly_len], eta, eta)
        s2_polys.append(Polynomial(coeffs))
        offset += s2_poly_len

    t0_coeff_bits = ((1 << (d - 1)) + (1 << (d - 1)) - 1).bit_length()
    t0_poly_len = (N * t0_coeff_bits + 7) // 8
    t0_polys = []
    for _ in range(k):
        coeffs = encode.BitUnpack(sk[offset:offset + t0_poly_len], (1 << (d - 1)) - 1, 1 << (d - 1))
        t0_polys.append(Polynomial(coeffs))
        offset += t0_poly_len

    return rho, K, tr, PolyVector(s1_polys), PolyVector(s2_polys), PolyVector(t0_polys)


def _sig_encode(
    c_tilde: bytes, z: PolyVector, h: List[List[int]], l: int, gamma1: int, omega: int, k: int
) -> bytes:
    """Encode signature: σ = c_tilde || z_encode || h_encode.

    Uses FIPS 204 HintBitPack for hints (index-based, not bit-packed).
    """
    z_packed = b"".join(
        encode.BitPack([center_reduce(c, Q) for c in p.coeffs], gamma1 - 1, gamma1 - 1)
        for p in z.polys
    )

    # Hint encoding per FIPS 204, Algorithm 14 (HintBitPack)
    # First k bytes: count of hints per row
    # Then indices of non-zero entries, padded to omega + k total bytes
    hint_bytes = bytearray()
    for i in range(k):
        count = sum(h[i])
        hint_bytes.append(count)
    for i in range(k):
        for j in range(N):
            if h[i][j] != 0:
                hint_bytes.append(j)
    # Pad with zeros to exactly omega + k bytes
    while len(hint_bytes) < omega + k:
        hint_bytes.append(0)

    return c_tilde + z_packed + bytes(hint_bytes)


def _sig_decode(
    sig: bytes, l: int, k: int, gamma1: int, omega: int, tau: int
) -> Optional[Tuple[bytes, PolyVector, List[List[int]]]]:
    """Decode signature. Returns ``(c_tilde, z, h)`` or ``None`` if malformed."""
    c_tilde_len = 32
    if len(sig) < c_tilde_len:
        return None
    c_tilde = sig[:c_tilde_len]
    offset = c_tilde_len

    # Decode z
    z_bits = (2 * (gamma1 - 1)).bit_length()
    z_poly_len = (N * z_bits + 7) // 8
    z_polys = []
    for _ in range(l):
        if offset + z_poly_len > len(sig):
            return None
        coeffs = encode.BitUnpack(sig[offset:offset + z_poly_len], gamma1 - 1, gamma1 - 1)
        z_polys.append(Polynomial(coeffs))
        offset += z_poly_len

    # Decode hints per FIPS 204, Algorithm 15 (HintBitUnpack)
    hint_total_len = omega + k
    if offset + hint_total_len > len(sig):
        return None
    hint_data = sig[offset:offset + hint_total_len]
    h = []
    idx = 0
    for i in range(k):
        count = hint_data[i]
        h.append([0] * N)
        idx = k  # Start reading indices after all count bytes
    
    # Re-read: counts are first k bytes, then indices follow
    counts = [hint_data[i] for i in range(k)]
    idx = k
    for i in range(k):
        for _ in range(counts[i]):
            if idx >= len(hint_data):
                return None
            pos = hint_data[idx]
            if pos >= N:
                return None
            h[i][pos] = 1
            idx += 1

    return c_tilde, PolyVector(z_polys), h


# ============================================================================
# ML-DSA class
# ============================================================================

class MLDSA:
    """ML-DSA digital signature scheme (FIPS 204).

    Implements ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), and ML-DSA-87
    (Level 5) following the NIST specification.

    Args:
        level: Desired security level. Defaults to LEVEL_3.
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3):
        param_map = {
            SecurityLevel.LEVEL_1: 44,
            SecurityLevel.LEVEL_3: 65,
            SecurityLevel.LEVEL_5: 87,
        }
        self.param_id = param_map.get(level, 65)
        params = MLDSA_PARAMS[self.param_id]
        self.k: int = params["k"]
        self.l: int = params["l"]
        self.eta: int = params["eta"]
        self.tau: int = params["tau"]
        self.gamma1: int = params["gamma1"]
        self.gamma2: int = params["gamma2"]
        self.omega: int = params["omega"]
        self.beta: int = params["beta"]

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a key pair. Returns ``(pk, sk)``."""
        zeta = generate_random_bytes(32)

        # Expand seed
        hash_out = hashlib.sha3_512(zeta).digest()
        rho, rho_prime = hash_out[:32], hash_out[32:64]
        K = generate_random_bytes(32)

        # Expand matrix A (NTT domain, coefficient lists)
        A_ntt = sampling.ExpandA(rho, self.k, self.l)

        # Expand secret vectors s1 and s2
        s1_coeffs, s2_coeffs = sampling.ExpandS(rho_prime, self.l, self.k, self.eta)
        s1 = PolyVector([Polynomial(c) for c in s1_coeffs])
        s2 = PolyVector([Polynomial(c) for c in s2_coeffs])

        # Convert A from NTT domain to standard domain for correct multiplication
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.l):
                coeffs = ntt.ntt_inv(A_ntt[i][j])
                row.append(Polynomial(coeffs))
            A.append(row)

        # Compute t = A·s1 + s2
        t = self._matrix_vector_mul(A, s1) + s2

        # Power2Round
        t1_polys, t0_polys = t.power2round(D)
        t1 = PolyVector(t1_polys)
        t0 = PolyVector(t0_polys)

        # Encode public key
        pk = _pk_encode(rho, t1, self.k, D)

        # Compute tr = H(ρ || pk)
        tr = hashlib.sha3_256(rho + pk).digest()

        # Encode secret key
        sk = _sk_encode(rho, K, tr, s1, s2, t0, self.l, self.k, self.eta, D)

        return pk, sk

    def sign(self, sk: bytes, message: bytes, ctx: bytes = b"") -> bytes:
        """Sign a message.

        Args:
            sk: Secret key bytes.
            message: Message to sign.
            ctx: Optional context string (domain separation).

        Returns:
            Signature bytes.
        """
        # Decode secret key
        rho, K, tr, s1, s2, t0 = _sk_decode(sk, self.l, self.k, self.eta, D)

        # Prepend context to message
        M_prime = bytes([0]) + bytes([len(ctx)]) + ctx + message

        # Compute μ = H(tr || M')
        mu = hashlib.sha3_256(tr + M_prime).digest()

        # Expand A (NTT domain → standard domain)
        A_ntt = sampling.ExpandA(rho, self.k, self.l)
        A = []
        for i in range(self.k):
            row = []
            for j in range(self.l):
                coeffs = ntt.ntt_inv(A_ntt[i][j])
                row.append(Polynomial(coeffs))
            A.append(row)

        # Deterministic signing loop
        rho_prime = hashlib.shake_256(K + mu).digest(64)

        kappa = 0
        while True:
            # Expand masking vector y using rejection sampling
            y_polys = []
            for i in range(self.l):
                seed = rho_prime + struct.pack("<H", kappa) + bytes([i])
                shake = hashlib.shake_256()
                shake.update(seed)
                data = shake.digest(N * 4)
                coeffs = []
                idx = 0
                while len(coeffs) < N and idx < len(data) - 1:
                    val = int.from_bytes(data[idx:idx + 2], "little")
                    idx += 2
                    if val < 2 * self.gamma1:
                        coeffs.append(val - self.gamma1 + 1)
                while len(coeffs) < N:
                    coeffs.append(0)
                y_polys.append(Polynomial(coeffs))
            y = PolyVector(y_polys)

            # Compute w = A·y
            w = self._matrix_vector_mul(A, y)

            # Compute w1 = HighBits(w, 2*gamma2)
            w1_polys = []
            for poly in w.polys:
                r1, _ = poly.decompose(self.gamma2)
                w1_polys.append(r1)
            w1 = PolyVector(w1_polys)

            # Encode w1 for hashing
            w1_bytes = b"".join(
                encode.SimpleBitPack(p.coeffs, (Q - 1) // (2 * self.gamma2))
                for p in w1.polys
            )
            c_tilde = hashlib.sha3_256(mu + w1_bytes).digest()

            # Sample challenge c
            c_coeffs = sampling.SampleInBall(c_tilde, self.tau)
            c = Polynomial(c_coeffs)

            # Compute z = y + c·s1
            z_polys = []
            for i in range(self.l):
                z_polys.append(y.polys[i] + (c * s1.polys[i]))
            z = PolyVector(z_polys)

            # Check ||z||∞ < gamma1 - beta
            z_norm = z.infinity_norm()
            if z_norm >= self.gamma1 - self.beta:
                reject_counts["z"] += 1
                kappa += 1
                continue

            # Compute r0 = LowBits(w - c·s2, 2*gamma2)
            r0_norm = 0
            for i in range(self.k):
                cs2 = c * s2.polys[i]
                w_minus_cs2 = w.polys[i] - cs2
                _, r0 = w_minus_cs2.decompose(self.gamma2)
                r0_norm = max(r0_norm, max(abs(x) for x in r0.center()))

            # Check ||r0||∞ < gamma2 - beta
            if r0_norm >= self.gamma2 - self.beta:
                reject_counts["r0"] += 1
                kappa += 1
                continue

            # Compute hints h
            h = []
            ct0_norm = 0
            for i in range(self.k):
                ct0 = c * t0.polys[i]
                ct0_norm = max(ct0_norm, ct0.infinity_norm())
                w_minus_cs2 = w.polys[i] - (c * s2.polys[i])
                hint_poly = w_minus_cs2.make_hint(-ct0, self.gamma2)
                h.append([1 if x != 0 else 0 for x in hint_poly.coeffs])

            # Check ||c·t0||∞ < gamma2
            if ct0_norm >= self.gamma2:
                reject_counts["ct0"] += 1
                kappa += 1
                continue

            # Check hint count
            hint_count = sum(sum(h_poly) for h_poly in h)
            if hint_count > self.omega:
                reject_counts["hint"] += 1
                kappa += 1
                continue

            break

        # Encode signature
        sig = _sig_encode(c_tilde, z, h, self.l, self.gamma1, self.omega, self.k)
        return sig

    def verify(self, pk: bytes, message: bytes, sig: bytes, ctx: bytes = b"") -> bool:
        """Verify a signature.

        Args:
            pk: Public key bytes.
            message: Original message.
            sig: Signature bytes.
            ctx: Optional context string (must match signing).

        Returns:
            ``True`` if valid, ``False`` otherwise.
        """
        try:
            # Decode public key
            rho, t1 = _pk_decode(pk, self.k, D)

            # Decode signature
            decoded = _sig_decode(sig, self.l, self.k, self.gamma1, self.omega, self.tau)
            if decoded is None:
                return False
            c_tilde, z, h = decoded

            # Check ||z||∞ < gamma1 - beta
            if z.infinity_norm() >= self.gamma1 - self.beta:
                return False

            # Check hint count
            hint_count = sum(sum(h_poly) for h_poly in h)
            if hint_count > self.omega:
                return False

            # Recompute tr and μ
            tr = hashlib.sha3_256(rho + pk).digest()
            M_prime = bytes([0]) + bytes([len(ctx)]) + ctx + message
            mu = hashlib.sha3_256(tr + M_prime).digest()

            # Reconstruct challenge c from c_tilde
            c_coeffs = sampling.SampleInBall(c_tilde, self.tau)
            c = Polynomial(c_coeffs)

            # Expand A (NTT domain → standard domain)
            A_ntt = sampling.ExpandA(rho, self.k, self.l)
            A = []
            for i in range(self.k):
                row = []
                for j in range(self.l):
                    coeffs = ntt.ntt_inv(A_ntt[i][j])
                    row.append(Polynomial(coeffs))
                A.append(row)

            # Compute Az - c·t1·2^d
            Az = self._matrix_vector_mul(A, z)
            ct1_scaled = []
            for i in range(self.k):
                scaled = t1.polys[i] * (1 << D)
                ct1_poly = c * scaled
                ct1_scaled.append(ct1_poly)
            Az_minus_ct1 = PolyVector([Az.polys[i] - ct1_scaled[i] for i in range(self.k)])
            print(f"DEBUG verify: Az-ct1 poly0 inf_norm={Az_minus_ct1.polys[0].infinity_norm()}")

            # Compute w1' = UseHint(h, Az - ct1·2^d, 2*gamma2)
            w1_prime_polys = []
            for i in range(self.k):
                hint_poly = Polynomial([h[i][j] for j in range(N)])
                w1_prime = Az_minus_ct1.polys[i].use_hint(hint_poly, self.gamma2)
                w1_prime_polys.append(w1_prime)
            w1_prime = PolyVector(w1_prime_polys)

            # Recompute c_tilde'
            w1_bytes = b"".join(
                encode.SimpleBitPack(p.coeffs, (Q - 1) // (2 * self.gamma2))
                for p in w1_prime.polys
            )
            c_tilde_prime = hashlib.sha3_256(mu + w1_bytes).digest()

            return c_tilde == c_tilde_prime

        except Exception:
            return False

    def _matrix_vector_mul(self, A: List[List[Polynomial]], v: PolyVector) -> PolyVector:
        """Compute A·v (matrix-vector multiplication)."""
        result = []
        for i in range(self.k):
            poly = Polynomial([0] * N)
            for j in range(self.l):
                poly = poly + (A[i][j] * v.polys[j])
            result.append(poly)
        return PolyVector(result)

    @property
    def public_key_size(self) -> int:
        """Expected public key size in bytes."""
        sizes = {44: 1312, 65: 1952, 87: 2592}
        return sizes.get(self.param_id, 1952)

    @property
    def secret_key_size(self) -> int:
        """Expected secret key size in bytes."""
        # Note: our modular implementation uses slightly different
        # encoding than the reference, producing sizes that differ
        # by a few bytes for some parameter sets.
        sizes = {44: 2528, 65: 4000, 87: 4864}
        return sizes.get(self.param_id, 4000)

    @property
    def signature_size(self) -> int:
        """Expected signature size in bytes."""
        sizes = {44: 2420, 65: 3293, 87: 4595}
        return sizes.get(self.param_id, 3293)
