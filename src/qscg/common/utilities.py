"""Utility functions for QSCG.

This module provides low-level arithmetic, bit-manipulation, and
cryptographic helper routines shared across the ML-KEM, ML-DSA, and
SLH-DSA implementations.

All functions are written in pure Python with no external dependencies
beyond the standard library.
"""

import math
import secrets
from typing import List, Tuple

__all__ = [
    "mod_exp",
    "mod_inv",
    "bit_reverse",
    "bytes_to_bits",
    "bits_to_bytes",
    "generate_random_bytes",
    "center_reduce",
    "floor_div",
]


def mod_exp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation using the square-and-multiply method.

    Computes ``base ** exp % mod`` efficiently in O(log exp) time.

    Args:
        base: The base integer.
        exp: The non-negative exponent.
        mod: A positive modulus.

    Returns:
        ``base ** exp (mod mod)``.

    Raises:
        ValueError: If ``mod`` is not positive.
    """
    if mod <= 0:
        raise ValueError("modulus must be positive")
    result = 1
    base = base % mod
    while exp > 0:
        if exp & 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp >>= 1
    return result


def mod_inv(a: int, mod: int) -> int:
    """Modular multiplicative inverse via the extended Euclidean algorithm.

    Computes ``a^{-1} (mod mod)`` such that ``a * a^{-1} ≡ 1 (mod mod)``.

    Args:
        a: The integer to invert.
        mod: A positive modulus.  Must be coprime with *a*.

    Returns:
        The modular inverse of *a* modulo *mod*, normalised to the
        range ``[0, mod - 1]``.

    Raises:
        ValueError: If *a* has no inverse modulo *mod* (i.e. gcd > 1).
    """
    def _extended_gcd(aa: int, bb: int) -> Tuple[int, int, int]:
        """Return (gcd, x, y) satisfying aa*x + bb*y == gcd(aa, bb)."""
        if aa == 0:
            return bb, 0, 1
        gcd, x1, y1 = _extended_gcd(bb % aa, aa)
        x = y1 - (bb // aa) * x1
        y = x1
        return gcd, x, y

    gcd, x, _ = _extended_gcd(a % mod, mod)
    if gcd != 1:
        raise ValueError(f"No modular inverse for {a} modulo {mod} (gcd={gcd})")
    return (x % mod + mod) % mod


def bit_reverse(n: int, bits: int) -> int:
    """Bit-reversal permutation.

    Reverses the order of the lowest *bits* bits of *n*.  For example,
    ``bit_reverse(6, 3)`` returns ``3`` because ``0b110`` reversed
    over 3 bits is ``0b011``.

    This operation is used in the Number-Theoretic Transform (NTT)
    re-indexing for both ML-KEM and ML-DSA.

    Args:
        n: The integer whose bits are to be reversed.
        bits: The number of low-order bits to reverse.

    Returns:
        The bit-reversed integer.
    """
    result = 0
    for i in range(bits):
        if (n >> i) & 1:
            result |= 1 << (bits - 1 - i)
    return result


def bytes_to_bits(data: bytes) -> List[int]:
    """Convert a byte string to a flat list of bits.

    Bits are emitted in little-endian order within each byte (bit 0
    first).  This matches the convention used in FIPS 203 for byte
    decompression and Encode/Decode operations.

    Args:
        data: Input byte string.

    Returns:
        List of integer bits (0 or 1).
    """
    bits: List[int] = []
    for byte in data:
        for i in range(8):
            bits.append((byte >> i) & 1)
    return bits


def bits_to_bytes(bits: List[int]) -> bytes:
    """Convert a flat list of bits back into a byte string.

    Bits are packed in little-endian order within each byte.  If the
    length of *bits* is not a multiple of 8 the final byte is padded
    with zeros.

    Args:
        bits: List of integer bits (0 or 1).

    Returns:
        Packed byte string.
    """
    result = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for j in range(8):
            if i + j < len(bits):
                byte |= (bits[i + j] << j)
        result.append(byte)
    return bytes(result)


def generate_random_bytes(length: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Uses :func:`secrets.token_bytes`, which sources entropy from the
    operating-system CSPRNG (``/dev/urandom`` on Unix, ``CryptGenRandom``
    on Windows).

    Args:
        length: Number of random bytes to generate.

    Returns:
        A *length*-byte string of random data.
    """
    return secrets.token_bytes(length)


def center_reduce(x: int, q: int) -> int:
    """Centered modular reduction.

    Maps an integer into the symmetric range ``[-q/2, q/2]``.  This is
    the canonical representative used in lattice-based schemes for
    coefficient compression and signature verification.

    Args:
        x: The integer to reduce.
        q: A positive modulus.

    Returns:
        The centred representative of *x* modulo *q*.
    """
    x = x % q
    if x > q // 2:
        x -= q
    return x


def floor_div(a: int, b: int) -> int:
    """Floor division.

    Python's built-in ``//`` operator already implements mathematical
    floor division for all sign combinations, so this function is
    provided primarily as an explicit alias for documentation purposes
    in lattice algorithms (e.g. ``Decompress_q`` / ``Compress_q`` in
    FIPS 203).

    Args:
        a: Dividend.
        b: Divisor (must be non-zero).

    Returns:
        ``⌊a / b⌋``.

    Raises:
        ZeroDivisionError: If *b* is zero.
    """
    if b == 0:
        raise ZeroDivisionError("division by zero")
    return a // b
