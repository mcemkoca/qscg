"""WOTS+: Winternitz One-Time Signature Plus (FIPS 205, Section 5).

Hash-based one-time signature scheme using iterative hash chains.
Each WOTS+ key pair can sign a single *n*-byte message digest.  The
secret key consists of ``len`` random *n*-byte strings; the public key
is derived by hashing each secret key element through a chain of
length ``w - 1``.  Signing reveals intermediate chain values
according to a base-*w* encoding of the message and a checksum.

Implemented routines
--------------------
- :func:`chain`           — iterative WOTS+ hash chain (Algorithm 2).
- :func:`wots_PKGen`      — public-key generation (Algorithm 3).
- :func:`wots_Sign`       — signing (Algorithm 4).
- :func:`wots_PKFromSig`  — public-key recovery from signature (Algorithm 5).
- :func:`_base_w`         — base-*w* encoding helper.
- :func:`_compute_lengths` — ``len1`` / ``len2`` / ``len`` computation.

Reference
---------
- NIST FIPS 205, Section 5 — WOTS+.
"""

from __future__ import annotations

import math
from typing import List, Tuple

from ..common import hashing
from .address import ADRS

__all__ = [
    "chain",
    "wots_PKGen",
    "wots_Sign",
    "wots_PKFromSig",
    "_base_w",
    "_compute_lengths",
]

# ---------------------------------------------------------------------------
# Parameter helpers
# ---------------------------------------------------------------------------


def _compute_lengths(n: int, w: int) -> Tuple[int, int, int]:
    """Compute WOTS+ chain-count parameters (FIPS 205, Section 5).

    The formulae are::

        len_1 = ceil(8 * n / log2(w))
        len_2 = floor(log2(len_1 * (w - 1)) / log2(w)) + 1
        len   = len_1 + len_2

    For the SLH-DSA-SHA2-128s parameter set (``n = 16``, ``w = 16``)
    this yields ``len_1 = 32``, ``len_2 = 3``, ``len = 35``.

    Parameters
    ----------
    n:
        Security parameter — hash output length in bytes.
    w:
        Winternitz parameter (typically 16).

    Returns
    -------
    tuple[int, int, int]
        ``(len_1, len_2, len)``.
    """
    log_w = int(math.log2(w))
    len_1 = math.ceil((8 * n) / log_w)
    len_2 = math.floor(math.log2(len_1 * (w - 1)) / log_w) + 1
    length = len_1 + len_2
    return len_1, len_2, length


# ---------------------------------------------------------------------------
# Algorithm 2 — chain (iterative hash chain)
# ---------------------------------------------------------------------------


def chain(
    PK_seed: bytes,
    adrs: ADRS,
    start: int,
    steps: int,
    n: int,
    sig_element: bytes | None = None,
) -> bytes:
    """WOTS+ chain function (FIPS 205, Algorithm 2).

    Iteratively applies the :func:`~qscg.common.hashing.F` hash function
    ``steps`` times beginning at iteration index ``start``.

    Algorithm
    ---------
    For *j* from *start* to *start + steps - 1*:

    1. Set ``ADRS.hash_address = j``.
    2. ``tmp = F(PK_seed, ADRS, tmp)``.

    Parameters
    ----------
    PK_seed:
        Public-key seed (*n* bytes) — serves as domain separator.
    adrs:
        Address structure.  The ``chain_address`` field must already
        identify the WOTS+ chain index; ``hash_address`` is mutated
        inside this function.
    start:
        Starting iteration index (inclusive).
    steps:
        Number of additional iterations to apply.  May be zero, in
        which case the input is returned unchanged.
    n:
        Security parameter (hash output length in bytes).
    sig_element:
        Starting value (*n* bytes).  If *None*, a zero-filled buffer of
        length *n* is used.  In the WOTS+ context this is typically a
        secret-key element; during verification it is a signature
        element.

    Returns
    -------
    bytes
        The final *n*-byte chain value.
    """
    if sig_element is None:
        sig_element = b"\x00" * n

    tmp = sig_element
    # Guard against negative or zero steps
    if steps <= 0:
        return tmp

    for j in range(start, start + steps):
        adrs.hash_address = j
        tmp = hashing.F(PK_seed, bytes(adrs), tmp)[:n]

    return tmp


# ---------------------------------------------------------------------------
# Algorithm 3 — wots_PKGen (public-key generation)
# ---------------------------------------------------------------------------


def wots_PKGen(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: dict,
) -> bytes:
    """WOTS+ public-key generation (FIPS 205, Algorithm 3).

    Derives the WOTS+ public key from the secret-key seed by
    generating ``len`` secret values, hashing each through a full
    chain of length ``w - 1``, and compressing the resulting vector
    with :func:`~qscg.common.hashing.T_l`.

    Algorithm
    ---------
    1. Compute ``len_1, len_2, len``.
    2. For *i* from ``0`` to ``len - 1``:

       a. ``ADRS.type = WOTS_HASH``
       b. ``ADRS.chain_address = i``
       c. ``ADRS.hash_address = 0``
       d. ``sk = PRF(PK_seed, SK_seed, ADRS)``  → truncate to *n* bytes.
       e. ``tmp[i] = chain(sk, 0, w - 1)``.

    3. ``ADRS.type = WOTS_PK``
    4. ``pk = T_l(PK_seed, ADRS, tmp[0] || ... || tmp[len - 1])``.
    5. Return ``pk``.

    Parameters
    ----------
    SK_seed:
        Secret-key seed.
    PK_seed:
        Public-key seed.
    adrs:
        Address structure with ``layer``, ``tree_address`` and
        ``keypair_address`` already set.
    params:
        SLH-DSA parameter dictionary.  Must contain ``'n'`` and
        ``'w'``.  If ``'len1'`` / ``'len2'`` are absent they are
        computed automatically.

    Returns
    -------
    bytes
        The WOTS+ public key — *n* bytes.
    """
    n: int = params["n"]
    w: int = params["w"]

    len_1, len_2, length = _compute_lengths(n, w)

    # Allow caller to override lengths (useful for test vectors)
    len_1 = params.get("len1", len_1)
    len_2 = params.get("len2", len_2)
    length = params.get("len", len_1 + len_2)

    tmp: List[bytes] = []

    for i in range(length):
        # Derive the i-th secret key element
        adrs.type = ADRS.WOTS_HASH
        adrs.chain_address = i
        adrs.hash_address = 0
        sk_i = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
        sk_i = sk_i[:n]

        # Hash it through the full chain [0, w-1]
        adrs.chain_address = i
        tmp_i = chain(PK_seed, adrs, 0, w - 1, n, sk_i)
        tmp.append(tmp_i)

    # Compress the public-key vector
    adrs.type = ADRS.WOTS_PK
    adrs.chain_address = 0
    adrs.hash_address = 0
    pk = hashing.T_l(PK_seed, bytes(adrs), b"".join(tmp))
    return pk[:n]


# ---------------------------------------------------------------------------
# Algorithm 4 — wots_Sign (signing)
# ---------------------------------------------------------------------------


def wots_Sign(
    M: bytes,
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: dict,
) -> List[bytes]:
    """WOTS+ signing (FIPS 205, Algorithm 4).

    Signs an *n*-byte message *M* by encoding it in base *w*,
    computing a checksum, and revealing the corresponding chain
    positions for each secret-key element.

    Algorithm
    ---------
    1. Compute ``len_1, len_2, len``.
    2. ``msg = base_w(M, w, len_1)``.
    3. ``csum = sum(w - 1 - msg[i])`` for *i* from ``0`` to ``len_1 - 1``.
    4. ``csum_bytes = toByte(csum, ceil(len_2 * log2(w) / 8))``.
    5. ``csum_base_w = base_w(csum_bytes, w, len_2)``.
    6. ``sig = msg || csum_base_w`` (concatenated digit lists).
    7. For *i* from ``0`` to ``len - 1``:

       a. Derive ``sk_i`` via ``PRF`` (same address pattern as
          ``wots_PKGen``).
       b. ``sig[i] = chain(sk_i, 0, sig[i])``.

    8. Return the list of *n*-byte signature elements.

    Parameters
    ----------
    M:
        *n*-byte message digest to sign.
    SK_seed:
        Secret-key seed.
    PK_seed:
        Public-key seed.
    adrs:
        Address structure with ``layer``, ``tree_address`` and
        ``keypair_address`` already set.
    params:
        SLH-DSA parameter dictionary containing ``'n'`` and ``'w'``.

    Returns
    -------
    list[bytes]
        WOTS+ signature — ``len`` elements, each *n* bytes.
    """
    n: int = params["n"]
    w: int = params["w"]

    len_1, len_2, length = _compute_lengths(n, w)
    len_1 = params.get("len1", len_1)
    len_2 = params.get("len2", len_2)
    length = params.get("len", len_1 + len_2)

    log_w = int(math.log2(w))

    # ---- Step 1–2: base-w encode the message ---------------------------
    msg_digits: List[int] = _base_w(M, w, len_1)

    # ---- Step 3: compute checksum --------------------------------------
    csum = 0
    for m in msg_digits:
        csum += (w - 1) - m

    # ---- Step 4–5: encode checksum in base-w ---------------------------
    # The checksum must be written as a big-endian integer occupying
    # exactly ceil(len_2 * log2(w) / 8) bytes.
    csum_nbytes = math.ceil((len_2 * log_w) / 8)
    csum_bytes = csum.to_bytes(csum_nbytes, byteorder="big")
    csum_digits: List[int] = _base_w(csum_bytes, w, len_2)

    # Concatenate message digits and checksum digits
    digits: List[int] = msg_digits + csum_digits

    # ---- Step 6–7: derive signature elements ---------------------------
    sig: List[bytes] = []
    for i in range(length):
        adrs.type = ADRS.WOTS_HASH
        adrs.chain_address = i
        adrs.hash_address = 0
        sk_i = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
        sk_i = sk_i[:n]

        sig_i = chain(PK_seed, adrs, 0, digits[i], n, sk_i)
        sig.append(sig_i)

    return sig


# ---------------------------------------------------------------------------
# Algorithm 5 — wots_PKFromSig (public-key recovery from signature)
# ---------------------------------------------------------------------------


def wots_PKFromSig(
    sig: List[bytes],
    M: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: dict,
) -> bytes:
    """WOTS+ public-key recovery from signature (FIPS 205, Algorithm 5).

    Reconstructs the WOTS+ public key from a signature and the original
    message so that the verifier can compare it against the expected
    public-key value (or its Merkle-tree commitment).

    Algorithm
    ---------
    1. Compute ``len_1, len_2, len``.
    2. ``msg = base_w(M, w, len_1)``.
    3. ``csum = sum(w - 1 - msg[i])``.
    4. ``csum_bytes = toByte(csum, ceil(len_2 * log2(w) / 8))``.
    5. ``csum_base_w = base_w(csum_bytes, w, len_2)``.
    6. ``digits = msg || csum_base_w``.
    7. For *i* from ``0`` to ``len - 1``:

       ``tmp[i] = chain(sig[i], digits[i], w - 1 - digits[i])``.

    8. ``ADRS.type = WOTS_PK``.
    9. ``pk = T_l(PK_seed, ADRS, tmp[0] || ... || tmp[len - 1])``.
    10. Return ``pk``.

    Parameters
    ----------
    sig:
        WOTS+ signature — ``len`` elements, each *n* bytes.
    M:
        Original *n*-byte message digest.
    PK_seed:
        Public-key seed.
    adrs:
        Address structure with ``layer``, ``tree_address`` and
        ``keypair_address`` already set.
    params:
        SLH-DSA parameter dictionary containing ``'n'`` and ``'w'``.

    Returns
    -------
    bytes
        Recovered WOTS+ public key — *n* bytes.
    """
    n: int = params["n"]
    w: int = params["w"]

    len_1, len_2, length = _compute_lengths(n, w)
    len_1 = params.get("len1", len_1)
    len_2 = params.get("len2", len_2)
    length = params.get("len", len_1 + len_2)

    log_w = int(math.log2(w))

    # ---- Recompute base-w digits of the message ------------------------
    msg_digits: List[int] = _base_w(M, w, len_1)

    # ---- Recompute checksum --------------------------------------------
    csum = 0
    for m in msg_digits:
        csum += (w - 1) - m

    csum_nbytes = math.ceil((len_2 * log_w) / 8)
    csum_bytes = csum.to_bytes(csum_nbytes, byteorder="big")
    csum_digits: List[int] = _base_w(csum_bytes, w, len_2)

    digits: List[int] = msg_digits + csum_digits

    # ---- Complete each chain from the signature value ------------------
    tmp: List[bytes] = []
    for i in range(length):
        adrs.chain_address = i
        steps_remaining = (w - 1) - digits[i]
        tmp_i = chain(PK_seed, adrs, digits[i], steps_remaining, n, sig[i])
        tmp.append(tmp_i)

    # ---- Compress with T_l ---------------------------------------------
    adrs.type = ADRS.WOTS_PK
    adrs.chain_address = 0
    adrs.hash_address = 0
    pk = hashing.T_l(PK_seed, bytes(adrs), b"".join(tmp))
    return pk[:n]


# ---------------------------------------------------------------------------
# Helper — _base_w (base-w encoding)
# ---------------------------------------------------------------------------


def _base_w(X: bytes, w: int, out_len: int) -> List[int]:
    """Convert a byte string to a base-*w* digit vector (FIPS 205, Section 5).

    This is the ``base_w`` auxiliary function used throughout WOTS+.
    Bits are consumed from *X* most-significant-first; each group of
    ``log2(w)`` bits becomes one base-*w* digit.  If *X* runs out of
    bits before *out_len* digits are produced, the remaining digits
    are filled with ``0``.

    Algorithm
    ---------
    ::

        in  = 0          # total bits consumed
        out = 0          # digits produced
        total = 8 * len(X)
        bits  = 0
        buf   = 0

        while out < out_len and in < total:
            if bits < log_w:
                buf   = (buf << 8) | X[in // 8]
                bits += 8
                in   += 8
            digit = (buf >> (bits - log_w)) & (w - 1)
            result.append(digit)
            bits -= log_w
            out  += 1

    Parameters
    ----------
    X:
        Input byte string.
    w:
        Winternitz parameter (must be a power of two, e.g. 16).
    out_len:
        Desired number of output digits.

    Returns
    -------
    list[int]
        List of ``out_len`` base-*w* digits (each in ``[0, w - 1]``).

    Raises
    ------
    ValueError
        If *w* is not a power of two.
    """
    if w <= 0 or (w & (w - 1)) != 0:
        raise ValueError(f"_base_w: w must be a positive power of two, got {w}")

    log_w = int(math.log2(w))
    result: List[int] = []

    byte_idx = 0         # next byte to read from X
    out_count = 0        # digits produced so far
    bits_available = 0   # valid bits currently in buffer
    buffer = 0           # bit buffer

    while out_count < out_len:
        if bits_available < log_w:
            if byte_idx < len(X):
                buffer = (buffer << 8) | X[byte_idx]
                bits_available += 8
                byte_idx += 1
            else:
                # Input exhausted — stop producing digits
                break

        # Extract the top log_w bits from the buffer
        bits_available -= log_w
        digit = (buffer >> bits_available) & (w - 1)
        result.append(digit)
        out_count += 1

    # Pad with zeros if the input was too short
    while len(result) < out_len:
        result.append(0)

    return result[:out_len]


# ---------------------------------------------------------------------------
# Convenience — round-trip verify helper
# ---------------------------------------------------------------------------


def wots_Verify(
    sig: List[bytes],
    M: bytes,
    PK_seed: bytes,
    pk_expected: bytes,
    adrs: ADRS,
    params: dict,
) -> bool:
    """Verify a WOTS+ signature by recovering the public key.

    This is a thin wrapper around :func:`wots_PKFromSig` that compares
    the recovered public key against the expected value.

    Parameters
    ----------
    sig:
        WOTS+ signature.
    M:
        *n*-byte message digest that was signed.
    PK_seed:
        Public-key seed.
    pk_expected:
        Expected WOTS+ public key (*n* bytes).
    adrs:
        Address structure used during signing.
    params:
        SLH-DSA parameter dictionary.

    Returns
    -------
    bool
        ``True`` iff the recovered public key equals *pk_expected*.
    """
    pk_recovered = wots_PKFromSig(sig, M, PK_seed, adrs, params)
    return pk_recovered == pk_expected
