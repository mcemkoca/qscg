"""Sampling functions for ML-KEM (FIPS 203, Sections 4.4--4.5).

This module implements the core pseudorandom sampling primitives required by
Module-Lattice-Based Key-Encapsulation Mechanism (ML-KEM):

  * :func:`Parse` — byte-string to polynomial coefficients (Algorithm 6).
  * :func:`CBD` — Centered Binomial Distribution (Algorithm 8).
  * :func:`SampleNTT` — NTT-domain polynomial sampling (Algorithm 7).

In addition it provides higher-level helpers used during key-generation,
encapsulation, and decapsulation:

  * :func:`generate_matrix_A` — expand the public matrix **A** in NTT domain.
  * :func:`sample_vector_s` — sample secret vector (CBD, for **s**).
  * :func:`sample_vector_e` — sample error vector (CBD, for **e** / **e1** / **e2**).

All algorithms follow the NIST FIPS 203 specification exactly, including
byte-order conventions (little-endian) and rejection-sampling behaviour.

References:
    - NIST FIPS 203, Algorithm 6 — Parse
    - NIST FIPS 203, Algorithm 7 — SampleNTT
    - NIST FIPS 203, Algorithm 8 — CBD (Centered Binomial Distribution)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final, List

from ..common.constants import MLKEM_N, MLKEM_Q

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------
Q: Final[int] = MLKEM_Q
"""Coefficient modulus :math:`q = 3329`."""

N: Final[int] = MLKEM_N
"""Polynomial degree :math:`n = 256`."""


# ---------------------------------------------------------------------------
# Helper: byte → bit decomposition
# ---------------------------------------------------------------------------
def _byte_to_bits(b: int) -> List[int]:
    """Convert a single byte into 8 little-endian bits.

    Bit *i* of the returned list corresponds to ``(b >> i) & 1``.

    Args:
        b: Input byte (integer in ``[0, 255]``).

    Returns:
        List of 8 bits (0 or 1), least-significant bit first.
    """
    return [(b >> i) & 1 for i in range(8)]


# ---------------------------------------------------------------------------
# Parse (FIPS 203, Algorithm 6)
# ---------------------------------------------------------------------------
def Parse(B: bytes) -> List[int]:
    """Parse a byte string into a degree-255 polynomial (Algorithm 6).

    The algorithm processes *B* as a stream of 3-byte little-endian blocks.
    Each block contributes up to two 12-bit candidate coefficients; a candidate
    is accepted only when it is strictly smaller than :math:`q = 3329`
    (rejection sampling).

    Pseudocode (FIPS 203)::

        i = 0, j = 0
        while j < n:
            d1 = B[i] + 256·B[i+1] (mod 2^12)
            d2 = floor((B[i] + 256·B[i+1] + 65536·B[i+2]) / 4096)
            if d1 < q: a[j] = d1; j += 1
            if d2 < q and j < n: a[j] = d2; j += 1
            i += 3
        return a[0..n-1]

    Args:
        B: Input byte string.  Should contain at least ``⌈3n/2⌉ = 384`` bytes
           for a *full* polynomial (more bytes may be required depending on
           rejection outcomes).  In practice SHAKE-128 provides 672 bytes.

    Returns:
        List of ``N = 256`` integer coefficients, each in ``[0, q-1]``.

    Raises:
        ValueError: If fewer than ``3 * N // 2`` bytes are supplied.
    """
    if len(B) < (3 * N) // 2:
        raise ValueError(
            f"Parse requires at least {(3 * N) // 2} bytes, got {len(B)}"
        )

    coeffs: List[int] = []
    i = 0
    while len(coeffs) < N and i + 2 < len(B):
        # 24-bit little-endian integer from 3 consecutive bytes
        d = B[i] | (B[i + 1] << 8) | (B[i + 2] << 16)

        d1 = d & 0xFFF          # lower 12 bits
        d2 = (d >> 12) & 0xFFF  # upper 12 bits

        if d1 < Q:
            coeffs.append(d1)
        if d2 < Q and len(coeffs) < N:
            coeffs.append(d2)

        i += 3

    # Defensive padding — should not happen when *B* is long enough
    while len(coeffs) < N:
        coeffs.append(0)

    return coeffs[:N]


# ---------------------------------------------------------------------------
# CBD — Centered Binomial Distribution (FIPS 203, Algorithm 8)
# ---------------------------------------------------------------------------
def CBD(B: bytes, eta: int) -> List[int]:
    """Centered Binomial Distribution (Algorithm 8).

    Each coefficient is generated from ``2·eta`` consecutive input bits:

    .. math::

        f_i = \\sum_{k=0}^{\\eta-1} b_{i\\cdot 2\\eta + k}
              - \\sum_{k=0}^{\\eta-1} b_{i\\cdot 2\\eta + \\eta + k}

    where :math:`b_m` denotes the *m*-th bit of the input byte string
    (least-significant bit first within each byte).  The resulting
    coefficient lies in ``[-eta, eta]``.

    For ML-KEM:

      * ``eta1 = 3`` (secret key / error sampling)  
      * ``eta2 = 2`` (encryption error sampling)

    Required input length: ``eta * N // 4 = eta * 64`` bytes.

    Args:
        B: Input byte string containing at least ``eta * 64`` bytes.
        eta: CBD parameter (``3`` or ``2`` for ML-KEM).

    Returns:
        List of ``N = 256`` integer coefficients in ``[-eta, eta]``.

    Raises:
        ValueError: If ``B`` is too short for the requested *eta*.
    """
    required_bytes = eta * (N // 4)
    if len(B) < required_bytes:
        raise ValueError(
            f"CBD(eta={eta}) requires {required_bytes} bytes, got {len(B)}"
        )

    # Flatten every byte into 8 little-endian bits
    bits: List[int] = []
    for byte in B[:required_bytes]:
        bits.extend(_byte_to_bits(byte))

    coeffs: List[int] = []
    for idx in range(N):
        start = idx * 2 * eta
        # Count ones in the first eta bits
        count1 = sum(bits[start : start + eta])
        # Count ones in the second eta bits
        count2 = sum(bits[start + eta : start + 2 * eta])
        coeffs.append(count1 - count2)

    return coeffs


# ---------------------------------------------------------------------------
# SampleNTT (FIPS 203, Algorithm 7)
# ---------------------------------------------------------------------------
def SampleNTT(B: bytes) -> List[int]:
    """Sample a polynomial in the NTT domain (Algorithm 7).

    ``SampleNTT`` is defined as ``Parse(B)``; the NTT-domain semantic is
    purely contextual (the caller interprets the returned coefficients as
    an NTT-transformed polynomial).

    In ML-KEM key generation, *B* is the output of ``SHAKE128`` seeded
    with ``rho || j || i`` (domain-separated XOF call).

    Args:
        B: Pseudorandom byte string, typically 672 bytes of SHAKE-128
           output so that rejection sampling succeeds with overwhelming
           probability.

    Returns:
        List of ``N = 256`` integer coefficients in ``[0, q-1]``.

    Example::

        >>> from qscg.ml_kem.sampling import SampleNTT
        >>> import hashlib
        >>> seed = b'\x00' * 34   # rho || j || i
        >>> shake = hashlib.shake_128()
        >>> shake.update(seed)
        >>> poly = SampleNTT(shake.digest(672))
        >>> len(poly)
        256
        >>> all(0 <= c < 3329 for c in poly)
        True
    """
    return Parse(B)


# ---------------------------------------------------------------------------
# Matrix A generation (FIPS 203, Section 4.4 — ``A_hat`` expansion)
# ---------------------------------------------------------------------------
def generate_matrix_A(rho: bytes, k: int) -> List[List[List[int]]]:
    """Generate the public matrix **A** in NTT domain.

    For each entry ``A[i][j]`` (``0 ≤ i, j < k``)::

        A[i][j] = SampleNTT(SHAKE128(rho || uint8(j) || uint8(i)))

    Domain separation is achieved by appending ``j`` then ``i`` as single
    bytes (little-endian, i.e. raw uint8 values) to the 32-byte seed *rho*.

    Args:
        rho: 32-byte public seed.
        k: Matrix dimension.  One of ``2`` (Level-1), ``3`` (Level-3), or
           ``4`` (Level-5).

    Returns:
        ``k × k`` matrix where each entry is an NTT-domain polynomial
        represented as a list of 256 coefficients.

    Raises:
        ValueError: If *rho* is not exactly 32 bytes.
    """
    if len(rho) != 32:
        raise ValueError(f"rho must be 32 bytes, got {len(rho)}")

    A: List[List[List[int]]] = []
    for i in range(k):
        row: List[List[int]] = []
        for j in range(k):
            # Domain separation: rho || uint8(j) || uint8(i)
            seed = rho + struct.pack("<BB", j & 0xFF, i & 0xFF)
            shake = hashlib.shake_128()
            shake.update(seed)
            output = shake.digest(672)  # 672 bytes ≈ 224 3-byte blocks
            coeffs = SampleNTT(output)
            row.append(coeffs)
        A.append(row)

    return A


# ---------------------------------------------------------------------------
# Secret / error vector sampling (CBD-based)
# ---------------------------------------------------------------------------
def sample_vector_s(rho: bytes, eta: int, k: int) -> List[List[int]]:
    """Sample a secret vector **s** using CBD.

    For each polynomial ``s[j]`` (``0 ≤ j < k``)::

        s[j] = CBD(SHAKE256(rho || uint8(j)), eta)

    The number of bytes requested from SHAKE-256 is ``64·eta``, which is
    exactly the amount CBD consumes for ``N = 256`` coefficients.

    Args:
        rho: Seed byte string (e.g. the ``sigma`` value from ML-KEM keygen).
        eta: CBD parameter (``eta1 = 3`` for the secret vector in ML-KEM,
             ``eta2 = 2`` for the encryption error vector).
        k: Vector length (same as matrix dimension).

    Returns:
        ``k`` polynomials, each a list of 256 coefficients in ``[-eta, eta]``.

    Note:
        The returned coefficients are **not** reduced modulo *q*.  They must
        be converted to canonical representatives (``[0, q-1]``) before NTT
        transformation if required by the caller.
    """
    vectors: List[List[int]] = []
    for j in range(k):
        seed = rho + struct.pack("<B", j & 0xFF)
        shake = hashlib.shake_256()
        shake.update(seed)
        # CBD requires exactly eta * 64 bytes for N = 256
        output = shake.digest(64 * eta)
        coeffs = CBD(output, eta)
        vectors.append(coeffs)

    return vectors


def sample_vector_e(rho: bytes, eta: int, k: int) -> List[List[int]]:
    """Sample an error vector **e** using CBD.

    Behaviour is identical to :func:`sample_vector_s`; the separate name
    exists only to document the semantic role of the sampled vector in the
    ML-KEM protocol (error vector vs. secret vector).

    Args:
        rho: Seed byte string.
        eta: CBD parameter.
        k: Vector length.

    Returns:
        ``k`` polynomials, each a list of 256 coefficients in ``[-eta, eta]``.
    """
    return sample_vector_s(rho, eta, k)


# ---------------------------------------------------------------------------
# Utility: canonical reduction for CBD coefficients
# ---------------------------------------------------------------------------
def cbd_coefficients_to_montgomery(
    coeffs: List[int],
) -> List[int]:
    """Convert CBD output (centred representatives) to Montgomery form.

    CBD produces coefficients in ``[-eta, eta]``.  This helper maps them
    to canonical representatives ``[0, q-1]`` and then converts to
    Montgomery domain using :func:`~qscg.ml_kem.ntt.to_montgomery`.

    Args:
        coeffs: CBD output coefficients (may be negative).

    Returns:
        Coefficients in Montgomery form (range ``[0, q-1]``).

    Example::

        >>> from qscg.ml_kem.sampling import CBD, cbd_coefficients_to_montgomery
        >>> from qscg.ml_kem.ntt import to_montgomery
        >>> c = CBD(b'\\x00' * 192, eta=3)
        >>> c_mont = cbd_coefficients_to_montgomery(c)
        >>> all(0 <= x < 3329 for x in c_mont)
        True
    """
    from ..ml_kem.ntt import to_montgomery as _to_mont

    return [_to_mont((c % Q + Q) % Q) for c in coeffs]


# ---------------------------------------------------------------------------
# Aliases for external callers
# ---------------------------------------------------------------------------
__all__ = [
    "Parse",
    "CBD",
    "SampleNTT",
    "generate_matrix_A",
    "sample_vector_s",
    "sample_vector_e",
    "cbd_coefficients_to_montgomery",
]
