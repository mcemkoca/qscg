"""Sampling functions for ML-DSA (FIPS 204, Sections 4.4--4.5).

This module implements the core pseudorandom sampling primitives required by
the Module-Lattice-Based Digital Signature Algorithm (ML-DSA):

  * :func:`SampleInBall` — challenge polynomial with exactly ``tau`` non-zero
    :math:`\\pm 1` coefficients (Algorithm 5).
  * :func:`RejNTTPoly` — rejection-sampling of an NTT-domain polynomial
    (implicit in FIPS 204, explicit in the reference implementation).
  * :func:`ExpandA` — expand public matrix **A** from seed ``rho`` (Algorithm 6).
  * :func:`ExpandS` — expand secret vectors **s1**, **s2** (Algorithm 7).
  * :func:`ExpandMask` — expand mask vector **y** (Algorithm 8).

All algorithms follow the NIST FIPS 204 specification and the CRYSTALS-Dilithium
reference implementation conventions, including little-endian byte ordering,
Montgomery-domain arithmetic, and exact bit-width requirements.

References:
    - NIST FIPS 204, Algorithm  5 — SampleInBall
    - NIST FIPS 204, Algorithm  6 — ExpandA
    - NIST FIPS 204, Algorithm  7 — ExpandS
    - NIST FIPS 204, Algorithm  8 — ExpandMask
    - CRYSTALS-Dilithium reference (pq-crystals.org)
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final, List, Tuple

from ..common.constants import MLDSA_N, MLDSA_Q

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------
Q: Final[int] = MLDSA_Q
"""Coefficient modulus :math:`q = 8380417 = 2^{23} - 2^{13} + 1`."""

N: Final[int] = MLDSA_N
"""Polynomial degree :math:`n = 256`."""

# For q = 8380417 (23 bits), each 3-byte block yields one candidate.
# Rejection rate ≈ (2^23 - q) / 2^23 ≈ 0.024%.
_BYTES_PER_REJ_SAMPLE: Final[int] = 3
"""Number of input bytes consumed per rejection-sampling attempt."""

# Barrett reduction from the local NTT module (avoid circular import at runtime)
def _barrett_reduce(a: int) -> int:
    """Fast ``a mod q`` using Barrett reduction.

    Uses :math:`v = \\lfloor 2^{46} / q \\rfloor = 7026922` with a 46-bit
    right shift.  One conditional correction yields :math:`r \\in [0, q-1]`.

    Args:
        a: Input integer (may be negative or larger than *q*).

    Returns:
        ``a mod q`` in ``[0, q-1]``.
    """
    v = 7026922  # floor(2**46 / 8380417)
    t = (a * v) >> 46
    r = a - t * Q
    if r < 0:
        r += Q
    elif r >= Q:
        r -= Q
    return r


# ---------------------------------------------------------------------------
# SampleInBall (FIPS 204, Algorithm 5)
# ---------------------------------------------------------------------------
def SampleInBall(c_tilde: bytes, tau: int) -> List[int]:
    """Sample the challenge polynomial *c* with ``tau`` non-zero :math:`\\pm 1`.

    Algorithm (FIPS 204)::

        c[0..N-1] = 0
        signs = H(c_tilde)   # 8 bytes as little-endian integer
        for i = N-tau .. N-1:
            while True:
                j = next random byte from SHAKE256(c_tilde)
                if j <= i: break
            c[i] = c[j]
            c[j] = (-1)^{signs & 1}
            signs >>= 1
        return c

    The resulting polynomial has exactly *tau* coefficients equal to
    :math:`\\pm 1` and the remaining ``N - tau`` coefficients equal to ``0``.

    Args:
        c_tilde: 64-byte hash output (``c_tilde`` from the signing process).
        tau: Number of non-zero coefficients.  One of ``39`` (Level-1),
             ``49`` (Level-3), or ``60`` (Level-5).

    Returns:
        List of ``N = 256`` integer coefficients; exactly *tau* entries are
        ``+1`` or ``-1``, the rest are ``0``.

    Raises:
        ValueError: If *tau* exceeds *N*.
    """
    if tau > N:
        raise ValueError(f"tau={tau} cannot exceed N={N}")

    coeffs = [0] * N

    # Initialise a SHAKE-256 stream from c_tilde
    shake = hashlib.shake_256()
    shake.update(c_tilde)

    # signs: 8 bytes interpreted as a little-endian integer
    sign_bytes = shake.digest(8)
    signs = int.from_bytes(sign_bytes, "little", signed=False)

    # Place tau non-zero entries
    for i in range(N - tau, N):
        # Rejection sample j in [0, i]
        while True:
            j_byte = shake.digest(1)
            j = j_byte[0]
            if j <= i:
                break

        coeffs[i] = coeffs[j]
        # c[j] = (-1)^{signs & 1}
        coeffs[j] = 1 if (signs & 1) == 0 else -1
        signs >>= 1

    return coeffs


# ---------------------------------------------------------------------------
# RejNTTPoly — rejection sampling for ML-DSA NTT-domain polynomials
# ---------------------------------------------------------------------------
def RejNTTPoly(B: bytes) -> List[int]:
    """Rejection-sampling of an NTT-domain polynomial for ML-DSA.

    Since :math:`q = 8380417` fits in 23 bits, each 3-byte block contributes
    one 23-bit candidate coefficient.  A candidate is accepted iff it is
    strictly smaller than *q*.

    Pseudocode::

        coeffs = []
        pos = 0
        while len(coeffs) < N and pos + 3 <= len(B):
            d = B[pos] | (B[pos+1] << 8) | (B[pos+2] << 16)
            d = d & 0x7FFFFF          # keep lower 23 bits
            if d < q:
                coeffs.append(d)
            pos += 3

    With :math:`q = 2^{23} - 2^{13} + 1`, the rejection rate is only
    ``(2^23 - q) / 2^23 ≈ 0.024%``, so 840 bytes are more than sufficient
    in practice.

    Args:
        B: Input byte string (typically SHAKE-128 output).  Must contain at
           least ``3 * N = 768`` bytes for guaranteed success with
           overwhelming probability.

    Returns:
        List of ``N = 256`` integer coefficients in ``[0, q-1]``.

    Raises:
        ValueError: If fewer than ``3 * N`` bytes are supplied.
    """
    if len(B) < 3 * N:
        raise ValueError(
            f"RejNTTPoly requires at least {3 * N} bytes, got {len(B)}"
        )

    coeffs: List[int] = []
    pos = 0
    while len(coeffs) < N and pos + _BYTES_PER_REJ_SAMPLE <= len(B):
        # 24-bit little-endian integer, keep lower 23 bits
        d = B[pos] | (B[pos + 1] << 8) | (B[pos + 2] << 16)
        d &= 0x7FFFFF  # mask to 23 bits

        if d < Q:
            coeffs.append(d)

        pos += _BYTES_PER_REJ_SAMPLE

    # Defensive padding — should not trigger for well-formed input
    while len(coeffs) < N:
        coeffs.append(0)

    return coeffs[:N]


# ---------------------------------------------------------------------------
# ExpandA (FIPS 204, Algorithm 6)
# ---------------------------------------------------------------------------
def ExpandA(rho: bytes, k: int, l: int) -> List[List[List[int]]]:
    """Expand the public matrix **A** in NTT domain.

    For each entry ``A[i][j]`` (``0 ≤ i < k``, ``0 ≤ j < l``)::

        A[i][j] = RejNTTPoly(SHAKE128(rho || uint16(j) || uint16(i), 672))

    Domain separation encodes ``j`` (column) first, then ``i`` (row), each as
    a 16-bit little-endian unsigned integer.

    Args:
        rho: 32-byte seed.
        k: Number of rows.  One of ``4`` (Level-1), ``6`` (Level-3), or
           ``8`` (Level-5).
        l: Number of columns.  One of ``4`` (Level-1), ``5`` (Level-3), or
           ``7`` (Level-5).

    Returns:
        ``k × l`` matrix where each entry is an NTT-domain polynomial
        represented as a list of 256 coefficients in ``[0, q-1]``.

    Raises:
        ValueError: If *rho* is not exactly 32 bytes.
    """
    if len(rho) != 32:
        raise ValueError(f"rho must be 32 bytes, got {len(rho)}")

    A: List[List[List[int]]] = []
    for i in range(k):
        row: List[List[int]] = []
        for j in range(l):
            # Domain separation: rho || uint16(j) || uint16(i)  (little-endian)
            seed = rho + struct.pack("<HH", j & 0xFFFF, i & 0xFFFF)
            shake = hashlib.shake_128()
            shake.update(seed)
            output = shake.digest(840)  # 840 bytes > 3·256=768 (very low rejection)
            coeffs = RejNTTPoly(output)
            row.append(coeffs)
        A.append(row)

    return A


# ---------------------------------------------------------------------------
# ExpandS (FIPS 204, Algorithm 7)
# ---------------------------------------------------------------------------
def ExpandS(
    rho: bytes, l: int, k: int, eta: int
) -> Tuple[List[List[int]], List[List[int]]]:
    """Expand secret vectors **s1** and **s2**.

    Uses the Centered Binomial Distribution (CBD) with parameter *eta*:

      * **s1** contains ``l`` polynomials.
      * **s2** contains ``k`` polynomials.

    Each polynomial coefficient is generated from ``2·eta`` bits::

        coeff = count_ones(first eta bits) - count_ones(second eta bits)

    Domain separation distinguishes each polynomial index within **s1** and
    **s2**::

        s1[j] = CBD(SHAKE256(rho || uint16(j)), eta)      for j = 0..l-1
        s2[j] = CBD(SHAKE256(rho || uint16(l + j)), eta)  for j = 0..k-1

    Required bytes per polynomial: ``eta · N // 4 = eta · 64``.

    Args:
        rho: 64-byte seed.
        l: Length of **s1** vector (number of polynomials).
        k: Length of **s2** vector (number of polynomials).
        eta: CBD bound parameter.  One of ``2`` or ``4``.

    Returns:
        Tuple ``(s1, s2)`` where each is a list of coefficient lists
        (each coefficient in ``[-eta, eta]``).

    Raises:
        ValueError: If *eta* is not ``2`` or ``4``.
    """
    if eta not in (2, 4):
        raise ValueError(f"ML-DSA eta must be 2 or 4, got {eta}")

    bytes_per_poly = eta * (N // 4)  # eta * 64 bytes for N = 256

    # --- s1: l polynomials ---
    s1: List[List[int]] = []
    for j in range(l):
        seed = rho + struct.pack("<H", j & 0xFFFF)
        shake = hashlib.shake_256()
        shake.update(seed)
        output = shake.digest(bytes_per_poly)
        coeffs = _cbd_mldsa(output, eta)
        s1.append(coeffs)

    # --- s2: k polynomials ---
    s2: List[List[int]] = []
    for j in range(k):
        seed = rho + struct.pack("<H", (l + j) & 0xFFFF)
        shake = hashlib.shake_256()
        shake.update(seed)
        output = shake.digest(bytes_per_poly)
        coeffs = _cbd_mldsa(output, eta)
        s2.append(coeffs)

    return s1, s2


# ---------------------------------------------------------------------------
# CBD helper for ML-DSA (shared with ML-KEM semantics)
# ---------------------------------------------------------------------------
def _cbd_mldsa(B: bytes, eta: int) -> List[int]:
    """Centered Binomial Distribution for ML-DSA.

    Identical to FIPS 203 Algorithm 8, but uses a bit-stream over exactly
    ``eta * 64`` bytes.  Each coefficient consumes ``2 * eta`` bits::

        f_i = sum_{t=0}^{eta-1}  b_{i*2*eta + t}
            - sum_{t=0}^{eta-1}  b_{i*2*eta + eta + t}

    Args:
        B: Exactly ``eta * 64`` bytes.
        eta: CBD parameter (``2`` or ``4``).

    Returns:
        ``N = 256`` coefficients in ``[-eta, eta]``.
    """
    # Flatten to individual bits (LSB first within each byte)
    bits: List[int] = []
    for byte in B:
        for b in range(8):
            bits.append((byte >> b) & 1)

    coeffs: List[int] = []
    for i in range(N):
        start = i * 2 * eta
        count1 = sum(bits[start : start + eta])
        count2 = sum(bits[start + eta : start + 2 * eta])
        coeffs.append(count1 - count2)

    return coeffs


# ---------------------------------------------------------------------------
# ExpandMask (FIPS 204, Algorithm 8)
# ---------------------------------------------------------------------------
def ExpandMask(
    rho: bytes, kappa: int, gamma1: int, k: int, l: int
) -> List[List[int]]:
    """Expand the mask vector **y**.

    Each coefficient of **y** lies in ``[-gamma1 + 1, gamma1]``.  The bits
    per coefficient are::

        bits_per_coeff = gamma1.bit_length()

    which is ``18`` for ``gamma1 = 2^17`` and ``20`` for ``gamma1 = 2^19``.

    For each polynomial ``y[j]`` (``0 ≤ j < l``)::

        y[j] = bit_unpack(SHAKE256(rho || uint16(kappa + j)), gamma1)

    ``bit_unpack`` interprets the byte string as a little-endian stream of
    ``bits_per_coeff``-wide chunks.  Each chunk *w* is mapped to the signed
    range::

        coeff = w            if w < gamma1
        coeff = w - 2^bits   otherwise  (i.e. negative branch)

    In practice, since the caller ensures ``w < 2·gamma1``, the second case
    maps to ``w - 2·gamma1`` giving values in ``[-gamma1, gamma1-1]``.

    Args:
        rho: 64-byte seed from the rejection-sampling loop.
        kappa: Non-negative counter incremented on each restart.
        gamma1: Mask width.  One of ``2**17`` (Level-1) or ``2**19``
                (Level-3 / Level-5).
        k: Number of rows of **A** (unused directly, part of the signature).
        l: Number of polynomials in **y** (``4``, ``5``, or ``7``).

    Returns:
        ``l`` polynomials, each a list of 256 coefficients in
        ``[-gamma1 + 1, gamma1]``.
    """
    bits_per_coeff = gamma1.bit_length()  # 18 or 20
    total_bits = bits_per_coeff * N
    bytes_needed = (total_bits + 7) // 8

    y: List[List[int]] = []
    for j in range(l):
        seed = rho + struct.pack("<H", (kappa + j) & 0xFFFF)
        shake = hashlib.shake_256()
        shake.update(seed)
        output = shake.digest(bytes_needed)

        coeffs = _bit_unpack(output, bits_per_coeff, N)
        # Map [0, 2*gamma1 - 1] → [-gamma1 + 1, gamma1]
        coeffs = [w if w < gamma1 else w - 2 * gamma1 for w in coeffs]
        y.append(coeffs)

    return y


# ---------------------------------------------------------------------------
# Bit-unpack helper (little-endian, variable width)
# ---------------------------------------------------------------------------
def _bit_unpack(
    data: bytes, bits_per_coeff: int, num_coeffs: int
) -> List[int]:
    """Unpack a byte string into *num_coeffs* little-endian integers.

    Reads the byte string as a contiguous stream of bits (least-significant
    bit of each byte first) and chops it into ``bits_per_coeff``-wide
    chunks.  Each chunk is returned as an unsigned integer.

    Args:
        data: Input byte string.
        bits_per_coeff: Width of each unpacked value (e.g. ``18`` or ``20``).
        num_coeffs: Number of coefficients to extract (``256`` for ML-DSA).

    Returns:
        List of *num_coeffs* unsigned integers.
    """
    coeffs: List[int] = []
    bit_idx = 0
    total_bits = len(data) * 8

    for _ in range(num_coeffs):
        val = 0
        for b in range(bits_per_coeff):
            if bit_idx >= total_bits:
                break
            byte_pos = bit_idx // 8
            bit_pos = bit_idx % 8
            bit = (data[byte_pos] >> bit_pos) & 1
            val |= bit << b
            bit_idx += 1
        coeffs.append(val)

    # Pad if necessary (should not happen for well-formed input)
    while len(coeffs) < num_coeffs:
        coeffs.append(0)

    return coeffs


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
__all__ = [
    "SampleInBall",
    "RejNTTPoly",
    "ExpandA",
    "ExpandS",
    "ExpandMask",
]
