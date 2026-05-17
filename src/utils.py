"""
QSCG Utilities Module

Professional utility functions for the Quantum-Safe Cryptography toolkit.
Provides secure helpers for encoding, randomness, timing-safe operations,
and key serialization across all post-quantum algorithm implementations.

All functions use type hints, Google-style docstrings, and robust error handling.

Example:
    >>> from src.utils import secure_random_bytes, constant_time_compare
    >>> key = secure_random_bytes(32)
    >>> match = constant_time_compare(key, key)
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
import secrets
import struct
import time
from typing import Any, Dict, List, Optional, Tuple, Union

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Secure randomness
# ---------------------------------------------------------------------------

def secure_random_bytes(size: int) -> bytes:
    """Generate cryptographically secure random bytes.

    Uses ``os.urandom`` which draws from the OS CSPRNG (e.g. ``getrandom``
    on Linux, ``CryptGenRandom`` on Windows).

    Args:
        size: Number of random bytes to generate. Must be non-negative.

    Returns:
        A ``bytes`` object of length *size*.

    Raises:
        ValueError: If *size* is negative.

    Example:
        >>> nonce = secure_random_bytes(16)
        >>> len(nonce)
        16
    """
    if size < 0:
        raise ValueError("size must be non-negative")
    return os.urandom(size)


def secure_random_int(min_val: int, max_val: int) -> int:
    """Generate a cryptographically secure random integer in ``[min, max)``.

    Args:
        min_val: Inclusive lower bound.
        max_val: Exclusive upper bound.

    Returns:
        A uniformly distributed random integer.

    Raises:
        ValueError: If ``min_val >= max_val``.

    Example:
        >>> secure_random_int(0, 256)  # doctest: +SKIP
        42
    """
    if min_val >= max_val:
        raise ValueError("min_val must be strictly less than max_val")
    return secrets.randbelow(max_val - min_val) + min_val


def secure_random_bits(n: int) -> int:
    """Return an *n*-bit random non-negative integer.

    Args:
        n: Number of bits. Must be >= 0.

    Returns:
        An ``int`` with exactly *n* random bits.

    Raises:
        ValueError: If *n* is negative.
    """
    if n < 0:
        raise ValueError("n must be non-negative")
    if n == 0:
        return 0
    return secrets.randbits(n)


# ---------------------------------------------------------------------------
# Timing-safe comparison
# ---------------------------------------------------------------------------

def constant_time_compare(a: bytes, b: bytes) -> bool:
    """Compare two byte strings in constant time to prevent timing attacks.

    This wrapper uses ``hmac.compare_digest``, which is guaranteed to run in
    constant time regardless of where the first mismatch occurs.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        ``True`` only if *a* and *b* are identical.

    Example:
        >>> constant_time_compare(b"secret", b"secret")
        True
        >>> constant_time_compare(b"secret", b"SecreT")
        False
    """
    if not isinstance(a, bytes) or not isinstance(b, bytes):
        raise TypeError("both arguments must be bytes-like objects")
    return hmac.compare_digest(a, b)


def constant_time_select(cond: bool, a: bytes, b: bytes) -> bytes:
    """Select one of two byte strings without branching on *cond*.

    This is a best-effort constant-time selection helper.  For highly
    sensitive code, consider a C extension or a library such as
    ``cryptography.hazmat``.

    Args:
        cond: If ``True``, return *a*; otherwise return *b*.
        a: Byte string selected when *cond* is ``True``.
        b: Byte string selected when *cond* is ``False``.

    Returns:
        The selected byte string.

    Raises:
        ValueError: If *a* and *b* differ in length.
    """
    if len(a) != len(b):
        raise ValueError("a and b must have the same length")
    mask = b"\xff" if cond else b"\x00"
    return bytes(x ^ y ^ (z & (x ^ y)) for x, y, z in zip(a, b, mask * len(a)))


# ---------------------------------------------------------------------------
# Encoding / decoding helpers
# ---------------------------------------------------------------------------

def bytes_to_hex(data: bytes) -> str:
    """Encode *data* as a lower-case hex string.

    Args:
        data: Raw bytes to encode.

    Returns:
        Hexadecimal representation (no ``0x`` prefix).

    Example:
        >>> bytes_to_hex(b"\x01\x02\x03")
        '010203'
    """
    return data.hex()


def hex_to_bytes(hex_str: str) -> bytes:
    """Decode a hex string back to raw bytes.

    Args:
        hex_str: Hexadecimal string (with or without ``0x`` prefix,
            case-insensitive). Whitespace is stripped automatically.

    Returns:
        Decoded ``bytes``.

    Raises:
        ValueError: If the string contains invalid hex characters or has
            an odd length after stripping the optional ``0x`` prefix.
    """
    hex_str = hex_str.strip().replace(" ", "")
    if hex_str.startswith(("0x", "0X")):
        hex_str = hex_str[2:]
    try:
        return bytes.fromhex(hex_str)
    except ValueError as exc:
        raise ValueError(f"invalid hex string: {exc}") from exc


def bytes_to_base64(data: bytes, urlsafe: bool = False) -> str:
    """Encode *data* to a Base64 string.

    Args:
        data: Raw bytes to encode.
        urlsafe: If ``True``, use URL-safe alphabet (``-`` and ``_``)
            instead of ``+`` and ``/``.

    Returns:
        Base64-encoded ASCII string (no padding stripped).

    Example:
        >>> bytes_to_base64(b"\x01\x02\x03")
        'AQID'
    """
    if urlsafe:
        return base64.urlsafe_b64encode(data).decode("ascii")
    return base64.b64encode(data).decode("ascii")


def base64_to_bytes(b64_str: str, urlsafe: bool = False) -> bytes:
    """Decode a Base64 string back to raw bytes.

    Args:
        b64_str: Base64-encoded ASCII string.
        urlsafe: Whether the string was encoded with the URL-safe alphabet.

    Returns:
        Decoded ``bytes``.

    Raises:
        ValueError: On malformed Base64 input.
    """
    try:
        if urlsafe:
            return base64.urlsafe_b64decode(b64_str)
        return base64.b64decode(b64_str)
    except binascii.Error as exc:
        raise ValueError(f"invalid base64 string: {exc}") from exc


def int_to_bytes(value: int, length: Optional[int] = None, byteorder: str = "big") -> bytes:
    """Convert a non-negative integer to a byte string.

    Args:
        value: Integer to encode (must be >= 0).
        length: Fixed output length in bytes.  If ``None``, the minimal
            number of bytes required to represent *value* is used.
        byteorder: ``"big"`` or ``"little"``.

    Returns:
        Encoded ``bytes``.

    Raises:
        ValueError: If *value* is negative, or if *length* is too small.
    """
    if value < 0:
        raise ValueError("value must be non-negative")
    if length is None:
        length = (value.bit_length() + 7) // 8 or 1
    try:
        return value.to_bytes(length, byteorder)
    except OverflowError as exc:
        raise ValueError(f"value too large for {length} bytes") from exc


def bytes_to_int(data: bytes, byteorder: str = "big") -> int:
    """Convert a byte string to a non-negative integer.

    Args:
        data: Raw bytes.
        byteorder: ``"big"`` or ``"little"``.

    Returns:
        The decoded integer.
    """
    return int.from_bytes(data, byteorder)


# ---------------------------------------------------------------------------
# Key serialization helpers
# ---------------------------------------------------------------------------

def serialize_public_key(raw_key: bytes, label: str = "PUBLIC KEY") -> str:
    """Wrap a raw public key in a PEM-like text block.

    Args:
        raw_key: Raw key bytes.
        label: Header/footer label (e.g. ``"PUBLIC KEY"``,
            ``"ML-KEM PUBLIC KEY"``).

    Returns:
        PEM-formatted string.
    """
    b64 = bytes_to_base64(raw_key)
    lines = [f"-----BEGIN {label}-----"]
    # Wrap at 64 characters
    for i in range(0, len(b64), 64):
        lines.append(b64[i : i + 64])
    lines.append(f"-----END {label}-----")
    return "\n".join(lines)


def deserialize_public_key(pem_str: str, label: str = "PUBLIC KEY") -> bytes:
    """Extract raw key bytes from a PEM-like text block.

    Args:
        pem_str: PEM-formatted string.
        label: Expected header/footer label.

    Returns:
        Raw key bytes.

    Raises:
        ValueError: If the PEM block is malformed or the label mismatches.
    """
    begin = f"-----BEGIN {label}-----"
    end = f"-----END {label}-----"
    pem_str = pem_str.strip()
    if not pem_str.startswith(begin):
        raise ValueError(f"missing '{begin}' header")
    if not pem_str.endswith(end):
        raise ValueError(f"missing '{end}' footer")
    b64 = pem_str[len(begin) : -len(end)].strip()
    return base64_to_bytes(b64)


def serialize_private_key(raw_key: bytes, label: str = "PRIVATE KEY") -> str:
    """Wrap a raw private key in a PEM-like text block.

    .. warning::
        Never log or transmit private keys over insecure channels.

    Args:
        raw_key: Raw key bytes.
        label: Header/footer label.

    Returns:
        PEM-formatted string.
    """
    return serialize_public_key(raw_key, label=label)


def deserialize_private_key(pem_str: str, label: str = "PRIVATE KEY") -> bytes:
    """Extract raw key bytes from a PEM-formatted private key block.

    Args:
        pem_str: PEM-formatted string.
        label: Expected header/footer label.

    Returns:
        Raw key bytes.

    Raises:
        ValueError: On malformed input.
    """
    return deserialize_public_key(pem_str, label=label)


# ---------------------------------------------------------------------------
# File I/O utilities
# ---------------------------------------------------------------------------

def read_file_bytes(path: str) -> bytes:
    """Read the entire contents of a file as bytes.

    Args:
        path: Absolute or relative filesystem path.

    Returns:
        File contents as ``bytes``.

    Raises:
        FileNotFoundError: If the file does not exist.
        PermissionError: If the file cannot be read.
    """
    with open(path, "rb") as fh:
        return fh.read()


def write_file_bytes(path: str, data: bytes) -> int:
    """Write *data* to *path*, creating parent directories if necessary.

    Args:
        path: Target file path.
        data: Raw bytes to write.

    Returns:
        Number of bytes written.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "wb") as fh:
        return fh.write(data)


def read_file_lines(path: str, encoding: str = "utf-8") -> List[str]:
    """Read a text file line-by-line, stripping trailing newlines.

    Args:
        path: File path.
        encoding: Text encoding (default ``"utf-8"``).

    Returns:
        List of stripped lines.
    """
    with open(path, "r", encoding=encoding) as fh:
        return [line.rstrip("\n\r") for line in fh]


# ---------------------------------------------------------------------------
# Bit / byte manipulation
# ---------------------------------------------------------------------------

def split_bytes(data: bytes, chunk_size: int) -> List[bytes]:
    """Split *data* into chunks of at most *chunk_size* bytes.

    Args:
        data: Input byte string.
        chunk_size: Maximum chunk size (must be > 0).

    Returns:
        List of byte chunks.

    Raises:
        ValueError: If *chunk_size* <= 0.
    """
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")
    return [data[i : i + chunk_size] for i in range(0, len(data), chunk_size)]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    """Compute the bitwise XOR of two equal-length byte strings.

    Args:
        a: First operand.
        b: Second operand.

    Returns:
        Element-wise XOR result.

    Raises:
        ValueError: If lengths differ.
    """
    if len(a) != len(b):
        raise ValueError("operands must have the same length")
    return bytes(x ^ y for x, y in zip(a, b))


def zero_bytes(length: int) -> bytes:
    """Return a byte string of all zeros.

    Args:
        length: Desired length (>= 0).

    Returns:
        ``b'\\x00' * length``
    """
    if length < 0:
        raise ValueError("length must be non-negative")
    return b"\x00" * length


def pad_bytes(data: bytes, block_size: int, pad_byte: bytes = b"\x00") -> bytes:
    """Pad *data* to a multiple of *block_size* using *pad_byte*.

    Args:
        data: Input bytes.
        block_size: Target block size.
        pad_byte: Single-byte padding value.

    Returns:
        Padded byte string.
    """
    if block_size <= 0:
        raise ValueError("block_size must be positive")
    if len(pad_byte) != 1:
        raise ValueError("pad_byte must be exactly one byte")
    pad_len = (block_size - (len(data) % block_size)) % block_size
    return data + pad_byte * pad_len


# ---------------------------------------------------------------------------
# Benchmark / diagnostics
# ---------------------------------------------------------------------------

def benchmark(func: callable, *args, iterations: int = 1000, **kwargs) -> Dict[str, float]:
    """Run *func* repeatedly and return timing statistics.

    Args:
        func: Callable to benchmark.
        *args: Positional arguments for *func*.
        iterations: Number of repetitions.
        **kwargs: Keyword arguments for *func*.

    Returns:
        Dictionary with ``mean``, ``min``, ``max``, and ``total`` times
        in milliseconds.
    """
    times: List[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        func(*args, **kwargs)
        elapsed = (time.perf_counter() - start) * 1000.0
        times.append(elapsed)
    return {
        "mean_ms": sum(times) / len(times),
        "min_ms": min(times),
        "max_ms": max(times),
        "total_ms": sum(times),
        "iterations": iterations,
    }


def memory_usage_kb() -> int:
    """Return the current process's resident memory in KiB.

    Uses ``/proc/self/status`` on Linux; falls back to ``0`` on other
    platforms.

    Returns:
        Resident memory size in KiB.
    """
    try:
        with open("/proc/self/status", "r") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    parts = line.split()
                    return int(parts[1])
    except (FileNotFoundError, ValueError, PermissionError):
        pass
    return 0


# ---------------------------------------------------------------------------
# Convenience re-exports for the package
# ---------------------------------------------------------------------------

__all__ = [
    "secure_random_bytes",
    "secure_random_int",
    "secure_random_bits",
    "constant_time_compare",
    "constant_time_select",
    "bytes_to_hex",
    "hex_to_bytes",
    "bytes_to_base64",
    "base64_to_bytes",
    "int_to_bytes",
    "bytes_to_int",
    "serialize_public_key",
    "deserialize_public_key",
    "serialize_private_key",
    "deserialize_private_key",
    "read_file_bytes",
    "write_file_bytes",
    "read_file_lines",
    "split_bytes",
    "xor_bytes",
    "zero_bytes",
    "pad_bytes",
    "benchmark",
    "memory_usage_kb",
]
