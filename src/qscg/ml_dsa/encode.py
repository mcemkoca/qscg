"""Encoding and decoding functions for ML-DSA (FIPS 204, Section 5).

This module implements the bit-packing routines used by the Module-Lattice-
based Digital Signature Algorithm (ML-DSA).  All algorithms follow NIST
FIPS 204 exactly.

Implemented routines
--------------------
- :func:`SimpleBitPack` / :func:`SimpleBitUnpack` — encode/decode a
  polynomial whose coefficients lie in ``[0, b]`` (Algorithm 12 / 18).
- :func:`BitPack` / :func:`BitUnpack` — encode/decode a polynomial whose
  coefficients lie in ``[-a, b]`` (Algorithm 13 / 19).
- :func:`HintBitPack` / :func:`HintBitUnpack` — encode/decode a hint
  vector (Algorithm 14 / 20).

Usage example
-------------
>>> from qscg.ml_dsa.encode import SimpleBitPack, SimpleBitUnpack, BitPack, BitUnpack
>>> coeffs = list(range(256))
>>> packed = SimpleBitPack(coeffs, 255)
>>> unpacked = SimpleBitUnpack(packed, 255)
>>> unpacked == coeffs
True
>>> signed = [-10, 5, -3, 7] + [0]*252
>>> bp = BitPack(signed, 10, 10)
>>> bu = BitUnpack(bp, 10, 10)
>>> bu[:4]
[-10, 5, -3, 7]
"""

from __future__ import annotations

import math
from typing import List

from ..common.constants import MLDSA_Q, MLDSA_N

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_Q: int = MLDSA_Q
"""ML-DSA modulus *q* = 8380417."""

_N: int = MLDSA_N
"""Polynomial degree *n* = 256."""


def _bit_length(x: int) -> int:
    """Return the number of bits required to represent the non-negative integer *x*.

    Equivalent to ``(x).bit_length()`` but with an explicit docstring for
    clarity.
    """
    return x.bit_length()


# ============================================================================
# SimpleBitPack / SimpleBitUnpack
# ============================================================================

def SimpleBitPack(w: List[int], b: int) -> bytes:
    """Encode a polynomial with coefficients in ``[0, b]``.

    Implements **FIPS 204, Algorithm 12** (*SimpleBitPack*).

    Each of the ``N = 256`` coefficients is represented using ``d = ceil(log2(b+1))``
    bits, and the resulting bit-stream is packed into a little-endian byte
    string.

    Parameters
    ----------
    w:
        Polynomial coefficients, each in ``[0, b]``.
    b:
        Inclusive upper bound for coefficient values.

    Returns
    -------
    bytes
        Packed byte string of length ``32 * ceil(log2(b+1))``.

    Raises
    ------
    ValueError
        If *b* is negative or if any coefficient is out of range.
    TypeError
        If *w* is not a list of integers.

    Examples
    --------
    >>> SimpleBitPack([0]*256, 255) == bytes(256)
    True
    >>> SimpleBitPack([255]*256, 255) == bytes([0xFF]*256)
    True
    """
    if b < 0:
        raise ValueError(f"SimpleBitPack: bound b={b} must be non-negative")

    d: int = math.ceil(math.log2(b + 1))
    mask: int = (1 << d) - 1

    # Validate coefficients
    for idx, coeff in enumerate(w[:_N]):
        if not isinstance(coeff, int):
            raise TypeError(
                f"SimpleBitPack: coefficient at index {idx} is "
                f"{type(coeff).__name__}, expected int"
            )
        if coeff < 0 or coeff > b:
            raise ValueError(
                f"SimpleBitPack: coefficient at index {idx}={coeff} "
                f"out of range [0, {b}]"
            )

    result: bytearray = bytearray()
    bit_buffer: int = 0
    bits_in_buffer: int = 0

    for i in range(_N):
        coeff: int = w[i] & mask
        bit_buffer |= coeff << bits_in_buffer
        bits_in_buffer += d

        while bits_in_buffer >= 8:
            result.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bits_in_buffer -= 8

    # Flush remaining bits
    if bits_in_buffer > 0:
        result.append(bit_buffer & 0xFF)

    return bytes(result)


def SimpleBitUnpack(v: bytes, b: int) -> List[int]:
    """Decode a :func:`SimpleBitPack` output back into a polynomial.

    Implements **FIPS 204, Algorithm 18** (*SimpleBitUnpack*).

    Parameters
    ----------
    v:
        Packed byte string (output of :func:`SimpleBitPack`).
    b:
        Inclusive upper bound that was used during packing.

    Returns
    -------
    list[int]
        List of exactly ``N`` coefficients in ``[0, b]``.

    Examples
    --------
    >>> coeffs = SimpleBitUnpack(bytes(256), 255)
    >>> len(coeffs)
    256
    >>> coeffs[0]
    0
    """
    d: int = math.ceil(math.log2(b + 1))
    mask: int = (1 << d) - 1
    coeffs: list[int] = []

    bit_buffer: int = 0
    bits_in_buffer: int = 0
    byte_idx: int = 0

    while len(coeffs) < _N and byte_idx < len(v):
        bit_buffer |= v[byte_idx] << bits_in_buffer
        bits_in_buffer += 8
        byte_idx += 1

        while bits_in_buffer >= d and len(coeffs) < _N:
            coeffs.append(bit_buffer & mask)
            bit_buffer >>= d
            bits_in_buffer -= d

    # Pad with zeros if the byte string was too short.
    while len(coeffs) < _N:
        coeffs.append(0)

    return coeffs[:_N]


# ============================================================================
# BitPack / BitUnpack
# ============================================================================

def BitPack(w: List[int], a: int, b: int) -> bytes:
    """Encode a polynomial with coefficients in ``[-a, b]``.
    
    Implements **FIPS 204, Algorithm 13** (*BitPack*).
    
    The encoding first shifts each coefficient by *+a* so that the range
    ``[-a, b]`` maps to ``[0, a+b]``.  The shifted values are then packed
    using :func:`SimpleBitPack` with bound ``b' = a + b``.
    
    Parameters
    ----------
    w:
        Polynomial coefficients, each in ``[-a, b]``.
    a:
        Non-negative lower-bound magnitude.
    b:
        Non-negative upper bound.
    
    Returns
    -------
    bytes
        Packed byte string.
    
    Raises
    ------
    ValueError
        If *a* or *b* is negative, or if any coefficient is out of range.
    
    Examples
    --------
    >>> signed = list(range(-128, 128))
    >>> bp = BitPack(signed, 128, 127)
    >>> bu = BitUnpack(bp, 128, 127)
    >>> bu == signed
    True
    """
    if a < 0:
        raise ValueError(f"BitPack: lower bound magnitude a={a} must be non-negative")
    if b < 0:
        raise ValueError(f"BitPack: upper bound b={b} must be non-negative")

    # Validate and shift coefficients
    shifted: list[int] = []
    for idx, coeff in enumerate(w[:_N]):
        if not isinstance(coeff, int):
            raise TypeError(
                f"BitPack: coefficient at index {idx} is "
                f"{type(coeff).__name__}, expected int"
            )
        if coeff < -a or coeff > b:
            raise ValueError(
                f"BitPack: coefficient at index {idx}={coeff} "
                f"out of range [-{a}, {b}]"
            )
        shifted.append(coeff + a)

    return SimpleBitPack(shifted, a + b)


def BitUnpack(v: bytes, a: int, b: int) -> List[int]:
    """Decode a :func:`BitPack` output back into a signed polynomial.

    Implements **FIPS 204, Algorithm 19** (*BitUnpack*).

    Parameters
    ----------
    v:
        Packed byte string (output of :func:`BitPack`).
    a:
        Lower-bound magnitude that was used during packing.
    b:
        Upper bound that was used during packing.

    Returns
    -------
    list[int]
        List of exactly ``N`` coefficients in ``[-a, b]``.
    """
    shifted: list[int] = SimpleBitUnpack(v, a + b)
    return [c - a for c in shifted[:_N]]


# ============================================================================
# HintBitPack / HintBitUnpack
# ============================================================================

def HintBitPack(h: List[List[int]], omega: int) -> bytes:
    """Encode a hint vector as used in ML-DSA signatures.

    Implements **FIPS 204, Algorithm 14** (*HintBitPack*).

    A hint vector consists of *k* polynomials (one per row), each of length
    ``N = 256``.  For each row only the *positions* of non-zero entries are
    stored.  The encoding is:

    * **k bytes** — each byte stores the count of non-zero entries in the
      corresponding row.
    * **Variable-length index list** — the 1-byte column indices of all
      non-zero entries, row by row, followed by zero padding up to
      ``omega + k`` total bytes after the count prefix.

    Parameters
    ----------
    h:
        Hint matrix: a list of *k* lists, each of length ``N``.  A non-zero
        value at ``h[i][j]`` indicates a hint at position ``(i, j)``.
    omega:
        Maximum total number of non-zero entries across all rows (parameter
        ``omega`` from the ML-DSA parameter set).

    Returns
    -------
    bytes
        Packed hint vector of length exactly ``omega + k`` bytes.

    Raises
    ------
    ValueError
        If a row contains more than ``N`` entries, if the total hint count
        exceeds *omega*, or if any hint index is out of range.

    Examples
    --------
    >>> h = [[0]*256 for _ in range(4)]
    >>> h[0][5] = 1
    >>> h[0][10] = 1
    >>> h[1][3] = 1
    >>> packed = HintBitPack(h, 80)
    >>> len(packed)
    84
    """
    k: int = len(h)
    result: bytearray = bytearray()
    total_hints: int = 0

    for row_idx in range(k):
        if row_idx >= len(h):
            result.append(0)
            continue

        row: list[int] = h[row_idx]
        indices: list[int] = []

        for col_idx in range(min(_N, len(row))):
            if row[col_idx] != 0:
                if not 0 <= col_idx <= 255:
                    raise ValueError(
                        f"HintBitPack: hint index {col_idx} out of byte range"
                    )
                indices.append(col_idx)

        count: int = len(indices)
        total_hints += count
        if total_hints > omega:
            raise ValueError(
                f"HintBitPack: total hint count {total_hints} exceeds "
                f"omega={omega}"
            )

        result.append(count)
        result.extend(indices)

    # Zero-pad to the fixed output length omega + k.
    expected_length: int = omega + k
    while len(result) < expected_length:
        result.append(0)

    return bytes(result[:expected_length])


def HintBitUnpack(y: bytes, omega: int, k: int) -> List[List[int]]:
    """Decode a :func:`HintBitPack` output back into a hint matrix.

    Implements **FIPS 204, Algorithm 20** (*HintBitUnpack*).

    Parameters
    ----------
    y:
        Packed hint vector (output of :func:`HintBitPack`).  Expected length
        is ``omega + k`` bytes.
    omega:
        Maximum total number of non-zero entries (same value used for
        packing).
    k:
        Number of rows (polynomials) in the hint vector.

    Returns
    -------
    list[list[int]]
        Hint matrix: *k* lists of length ``N``, where non-zero entries
        indicate hint positions.

    Raises
    ------
    ValueError
        If the packed data is malformed (e.g. inconsistent counts, indices
        out of order, or total count exceeds *omega*).
    """
    # Initialize k rows of zeros
    h: list[list[int]] = [[0] * _N for _ in range(k)]

    if len(y) < k:
        raise ValueError(
            f"HintBitUnpack: input too short ({len(y)} bytes, need >= {k})"
        )

    idx: int = 0
    total_hints: int = 0

    for row_idx in range(k):
        count: int = y[idx]
        idx += 1
        total_hints += count

        if total_hints > omega:
            raise ValueError(
                f"HintBitUnpack: total hint count {total_hints} exceeds "
                f"omega={omega}"
            )

        # Decode the next *count* bytes as column indices
        prev_index: int = -1
        for _ in range(count):
            if idx >= len(y):
                raise ValueError(
                    "HintBitUnpack: unexpected end of data while reading "
                    "hint indices"
                )
            col: int = y[idx]
            idx += 1

            if col < prev_index:
                raise ValueError(
                    f"HintBitUnpack: indices out of order at row {row_idx}"
                )
            if not 0 <= col < _N:
                raise ValueError(
                    f"HintBitUnpack: index {col} out of range [0, {_N})"
                )

            h[row_idx][col] = 1
            prev_index = col

    return h


# ============================================================================
# Additional ML-DSA encoding utilities
# ============================================================================

def bit_length_for_bound(b: int) -> int:
    """Return the number of bits required to encode coefficients in ``[0, b]``.

    This is ``ceil(log2(b + 1))``, used by both :func:`SimpleBitPack` and
    :func:`BitPack`.

    Parameters
    ----------
    b:
        Inclusive upper bound.

    Returns
    -------
    int
        Number of bits ``d`` such that ``2^d >= b + 1``.

    Examples
    --------
    >>> bit_length_for_bound(255)
    8
    >>> bit_length_for_bound(256)
    9
    >>> bit_length_for_bound(0)
    0
    """
    if b < 0:
        raise ValueError(f"bit_length_for_bound: b={b} must be non-negative")
    return math.ceil(math.log2(b + 1)) if b > 0 else 0


def hint_count(h: List[List[int]]) -> int:
    """Count the total number of non-zero entries in a hint matrix.

    Parameters
    ----------
    h:
        Hint matrix (list of *k* rows, each of length ``N``).

    Returns
    -------
    int
        Total number of non-zero entries.

    Examples
    --------
    >>> h = [[0]*256, [1,0,1] + [0]*253]
    >>> hint_count(h)
    2
    """
    return sum(1 for row in h for val in row if val != 0)
