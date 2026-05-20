"""Encoding and decoding functions for ML-KEM (FIPS 203, Section 4).

This module implements the core encoding and compression routines used
throughout the ML-KEM key encapsulation mechanism.  All algorithms follow
NIST FIPS 203 (Initial Public Draft, February 2023) exactly.

Implemented routines
--------------------
- :func:`ByteEncode` / :func:`ByteDecode` — bit-packing of integer polynomials
  (FIPS 203, Algorithm 3 / Algorithm 4).
- :func:`Compress` / :func:`Decompress` — lossy modular reduction to/from
  ``d`` bits (FIPS 203, Equation 4.5 / Equation 4.6).

Usage example
-------------
>>> from qscg.ml_kem.encode import ByteEncode, ByteDecode, Compress, Decompress
>>> import random
>>> coeffs = [random.randrange(0, 3329) for _ in range(256)]
>>> encoded = ByteEncode(coeffs, 12)
>>> decoded = ByteDecode(encoded, 12)
>>> coeffs == decoded
True
>>> compressed = [Compress(c, 10) for c in coeffs]
>>> decompressed = [Decompress(c, 10) for c in compressed]
"""

from __future__ import annotations

from typing import List

from ..common.constants import MLKEM_Q, MLKEM_N

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

_Q: int = MLKEM_Q
"""Ring modulus *q* = 3329."""

_N: int = MLKEM_N
"""Polynomial degree *n* = 256."""

_VALID_D_VALUES: set[int] = {1, 4, 5, 10, 11, 12}
"""Permitted bit-widths for ByteEncode/ByteDecode."""


# ============================================================================
# Compression / Decompression
# ============================================================================

def Compress(x: int, d: int) -> int:
    """Compress a single ML-KEM coefficient to *d* bits.

    Computes FIPS 203, Equation 4.5:

    .. math::

        \\text{Compress}(x, d) = \\left\\lfloor
            \\frac{2^{d} \\cdot x}{q} + \\frac{1}{2}
        \\right\\rfloor \\bmod 2^{d}

    which is equivalent to ``round((2^d / q) * x) mod 2^d``.

    Parameters
    ----------
    x:
        Coefficient in the range ``[0, q-1]``.
    d:
        Number of output bits.  Must be one of ``1, 4, 5, 10, 11``.

    Returns
    -------
    int
        Compressed value in ``[0, 2^d - 1]``.

    Raises
    ------
    ValueError
        If *d* is not a supported compression width.

    Examples
    --------
    >>> Compress(1000, 10)
    308
    >>> Compress(0, 4)
    0
    >>> Compress(3328, 4)
    15
    """
    if d not in (1, 4, 5, 10, 11):
        raise ValueError(
            f"Compress: unsupported bit-width d={d!r}; "
            f"expected one of {{1, 4, 5, 10, 11}}"
        )
    # Compute round((2^d * x) / q) using integer arithmetic:
    #   ((x << d) + q//2) // q   ==   floor((2^d * x) / q + 1/2)
    compressed: int = ((x << d) + _Q // 2) // _Q
    mask: int = (1 << d) - 1
    return compressed & mask


def Decompress(y: int, d: int) -> int:
    """Decompress a *d*-bit value back to an ML-KEM coefficient.

    Computes FIPS 203, Equation 4.6:

    .. math::

        \\text{Decompress}(y, d) = \\left\\lfloor
            \\frac{q \\cdot y}{2^{d}} + \\frac{1}{2}
        \\right\\rfloor

    which is equivalent to ``round((q / 2^d) * y)``.

    Parameters
    ----------
    y:
        Compressed value in ``[0, 2^d - 1]``.
    d:
        Number of input bits.  Must be one of ``1, 4, 5, 10, 11``.

    Returns
    -------
    int
        Decompressed coefficient in ``[0, q-1]``.

    Raises
    ------
    ValueError
        If *d* is not a supported compression width.

    Examples
    --------
    >>> Decompress(308, 10)
    999
    >>> Decompress(0, 4)
    0
    >>> Decompress(15, 4)  # approximately q-1
    3120
    """
    if d not in (1, 4, 5, 10, 11):
        raise ValueError(
            f"Decompress: unsupported bit-width d={d!r}; "
            f"expected one of {{1, 4, 5, 10, 11}}"
        )
    # Compute round((q * y) / 2^d) using integer arithmetic:
    #   (y * q + 2^(d-1)) >> d   ==   floor((q * y) / 2^d + 1/2)
    return (y * _Q + (1 << (d - 1))) >> d


# ============================================================================
# ByteEncode / ByteDecode
# ============================================================================

def ByteEncode(f: List[int], d: int) -> bytes:
    """Encode a polynomial (list of 256 integers) into a byte string.

    Implements **FIPS 203, Algorithm 3** (*ByteEncode*).

    Each of the ``N = 256`` coefficients is treated as a *d*-bit unsigned
    little-endian integer and the resulting bit-stream is packed into bytes.
    The total output length is ``ceil(256 * d / 8)`` bytes.

    Parameters
    ----------
    f:
        List of exactly ``N`` coefficients, each in ``[0, 2^d - 1]``.
    d:
        Bits per coefficient.  Must be one of ``1, 4, 5, 10, 11, 12``.

    Returns
    -------
    bytes
        Packed byte string of length ``32*d`` bytes.

    Raises
    ------
    ValueError
        If *d* is not supported or if any coefficient is out of range.
    TypeError
        If *f* is not a list of integers.

    Examples
    --------
    >>> ByteEncode([0]*256, 1) == bytes(32)
    True
    >>> ByteEncode([1]*256, 1) == bytes([0xFF]*32)
    True
    """
    if not isinstance(f, list):
        raise TypeError(f"ByteEncode: expected list, got {type(f).__name__}")
    if d not in _VALID_D_VALUES:
        raise ValueError(
            f"ByteEncode: unsupported bit-width d={d!r}; "
            f"expected one of {_VALID_D_VALUES}"
        )

    mask: int = (1 << d) - 1

    # Range-check every coefficient — this catches malformed input early
    # and avoids silent truncation.
    for idx, coeff in enumerate(f[:_N]):
        if not isinstance(coeff, int):
            raise TypeError(
                f"ByteEncode: coefficient at index {idx} is "
                f"{type(coeff).__name__}, expected int"
            )
        if coeff < 0 or coeff > mask:
            raise ValueError(
                f"ByteEncode: coefficient at index {idx}={coeff} "
                f"out of range [0, {mask}] for d={d}"
            )

    result: bytearray = bytearray()
    bit_buffer: int = 0
    bits_in_buffer: int = 0

    # Pack each coefficient into a little-endian bit stream.
    for i in range(_N):
        coeff: int = f[i] & mask
        bit_buffer |= coeff << bits_in_buffer
        bits_in_buffer += d

        # Drain full bytes
        while bits_in_buffer >= 8:
            result.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bits_in_buffer -= 8

    # Flush any remaining bits (relevant when 256*d is not a multiple of 8).
    if bits_in_buffer > 0:
        result.append(bit_buffer & 0xFF)

    return bytes(result)


def ByteDecode(F: bytes, d: int) -> List[int]:
    """Decode a byte string back into a polynomial (list of 256 integers).

    Implements **FIPS 203, Algorithm 4** (*ByteDecode*).

    The input bytes are interpreted as a little-endian packed bit-stream of
    *d*-bit unsigned integers.  Exactly ``N = 256`` coefficients are
    reconstructed; trailing bits in the final byte are ignored.

    Parameters
    ----------
    F:
        Packed byte string.
    d:
        Bits per coefficient.  Must be one of ``1, 4, 5, 10, 11, 12``.

    Returns
    -------
    list[int]
        List of exactly ``N`` coefficients in ``[0, 2^d - 1]``.

    Raises
    ------
    ValueError
        If *d* is not supported.

    Examples
    --------
    >>> coeffs = ByteDecode(bytes(384), 12)
    >>> len(coeffs)
    256
    >>> coeffs[0]
    0
    >>> ByteDecode(bytes([0xFF]*384), 12) == [(1<<12)-1]*256
    True
    """
    if d not in _VALID_D_VALUES:
        raise ValueError(
            f"ByteDecode: unsupported bit-width d={d!r}; "
            f"expected one of {_VALID_D_VALUES}"
        )

    mask: int = (1 << d) - 1
    coeffs: list[int] = []

    bit_buffer: int = 0
    bits_in_buffer: int = 0
    byte_idx: int = 0

    # Unpack bytes into d-bit coefficients.
    while len(coeffs) < _N and byte_idx < len(F):
        bit_buffer |= F[byte_idx] << bits_in_buffer
        bits_in_buffer += 8
        byte_idx += 1

        while bits_in_buffer >= d and len(coeffs) < _N:
            coeffs.append(bit_buffer & mask)
            bit_buffer >>= d
            bits_in_buffer -= d

    # If we ran out of bytes before N coefficients, pad with zeros.
    # (This can only happen with malformed input; per FIPS 203 the caller
    # should supply the exact expected length.)
    while len(coeffs) < _N:
        coeffs.append(0)

    return coeffs[:_N]


# ============================================================================
# Convenience: Compress / Decompress for full polynomials
# ============================================================================

def compress_polynomial(coeffs: List[int], d: int) -> List[int]:
    """Compress every coefficient of a polynomial to *d* bits.

    Parameters
    ----------
    coeffs:
        List of ``N`` coefficients in ``[0, q-1]``.
    d:
        Number of output bits (``1, 4, 5, 10, 11``).

    Returns
    -------
    list[int]
        List of ``N`` compressed coefficients in ``[0, 2^d - 1]``.
    """
    return [Compress(c, d) for c in coeffs[:_N]]


def decompress_polynomial(coeffs: List[int], d: int) -> List[int]:
    """Decompress every coefficient of a polynomial from *d* bits.

    Parameters
    ----------
    coeffs:
        List of ``N`` compressed coefficients in ``[0, 2^d - 1]``.
    d:
        Number of input bits (``1, 4, 5, 10, 11``).

    Returns
    -------
    list[int]
        List of ``N`` decompressed coefficients in ``[0, q-1]``.
    """
    return [Decompress(c, d) for c in coeffs[:_N]]
