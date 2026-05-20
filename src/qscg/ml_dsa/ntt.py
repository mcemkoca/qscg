"""Complete NTT for ML-DSA (FIPS 204, CRYSTALS-Dilithium).

ML-DSA uses a complete Number-Theoretic Transform over the ring
:math:`\\mathbb{Z}_q[X]/(X^{256}+1)` with:

  - Modulus :math:`q = 8380417 = 2^{23} - 2^{13} + 1`
  - Degree  :math:`n = 256`
  - Primitive 512-th root of unity: :math:`\\zeta = 1753`
  - **8 NTT layers** (complete — output is 256 scalar values)
  - Montgomery radix: :math:`R = 2^{32}`

The complete NTT fully decomposes the ring into 256 copies of
:math:`\\mathbb{Z}_q`, so pointwise multiplication is simply the
pairwise product of the 256 scalar values.

The forward NTT follows the Dilithium reference implementation
(Cooley-Tukey, breadth-first, in-place).  Coefficients are consumed
in natural order; the output is in bit-reversed order (this is
handled transparently by the inverse transform).

This module provides:

  - :func:`ntt` / :func:`ntt_inv` — forward and inverse transforms
  - :func:`ntt_multiply` — pointwise multiplication in NTT domain
  - :func:`ntt_add` / :func:`ntt_sub` — element-wise addition/subtraction
  - :func:`barrett_reduce` — public Barrett reduction helper
  - :func:`to_montgomery` / :func:`from_montgomery` — Montgomery helpers

Example::

    >>> from qscg.ml_dsa.ntt import ntt, ntt_inv, ntt_multiply
    >>> a = [i % 8380417 for i in range(256)]
    >>> b = [(2 * i) % 8380417 for i in range(256)]
    >>> a_hat = ntt(a)
    >>> b_hat = ntt(b)
    >>> c_hat = ntt_multiply(a_hat, b_hat)
    >>> c = ntt_inv(c_hat)

References:
    - NIST FIPS 204, Section 4 — ML-DSA Internal Functions
    - CRYSTALS-Dilithium reference implementation (pq-crystals.org)
"""

from typing import List, Final

# ---------------------------------------------------------------------------
# Fixed parameters (FIPS 204 / Dilithium)
# ---------------------------------------------------------------------------
Q: Final[int] = 8380417
"""Modulus :math:`q = 8380417 = 2^{23} - 2^{13} + 1` (prime)."""

N: Final[int] = 256
"""Polynomial degree :math:`n = 256`."""

ZETA: Final[int] = 1753
"""Primitive 512-th root of unity modulo :math:`q`."""

NUM_LAYERS: Final[int] = 8
"""Complete NTT uses all 8 layers."""

MONT_R: Final[int] = 1 << 32
"""Montgomery radix :math:`R = 2^{32}`."""

# Barrett constant: v = floor(2^46 / Q) with 46-bit shift
_BARRETT_V: Final[int] = (1 << 46) // Q  # = 7026922

# Montgomery constant: q' = -q^(-1) mod 2^32 = 4236238847
# Satisfies: q * q' ≡ -1 (mod 2^32)
_MONT_Q_PRIME: Final[int] = 4236238847


def _bit_reverse(n: int, bits: int) -> int:
    """Bit-reversal permutation.

    Reverses the order of the lowest *bits* bits of *n*.

    Args:
        n: Integer whose bits are to be reversed.
        bits: Number of low-order bits to reverse.

    Returns:
        The bit-reversed value.

    Example::

        >>> _bit_reverse(6, 3)  # 0b110 -> 0b011
        3
    """
    result = 0
    for i in range(bits):
        if (n >> i) & 1:
            result |= 1 << (bits - 1 - i)
    return result


def _mod_exp(base: int, exp: int, mod: int) -> int:
    """Modular exponentiation by repeated squaring.

    Computes ``base**exp % mod`` for non-negative *exp*.

    Args:
        base: Base integer.
        exp: Non-negative exponent.
        mod: Positive modulus.

    Returns:
        ``base**exp mod mod``.
    """
    result = 1
    b = base % mod
    e = exp
    while e > 0:
        if e & 1:
            result = (result * b) % mod
        b = (b * b) % mod
        e >>= 1
    return result


# ---------------------------------------------------------------------------
# Pre-computed twiddle factors (Dilithium reference)
# ---------------------------------------------------------------------------
def _precompute_zetas() -> List[int]:
    """Pre-compute the 256 twiddle factors.

    ``zetas[i] = 1753^{bitreverse_8(i)} mod q`` for ``i = 0 .. 255``.

    The forward NTT consumes ``zetas[1]`` through ``zetas[255]``
    (PRE-increment indexing).  The inverse NTT consumes ``-zetas[255]``
    down to ``-zetas[1]`` (PRE-decrement, negated).  ``zetas[0]`` is
    never used.

    Returns:
        List of 256 integers in :math:`[0, q-1]`.
    """
    zetas: List[int] = []
    for i in range(256):
        rev = _bit_reverse(i, 8)
        zetas.append(_mod_exp(ZETA, rev, Q))
    return zetas


_ZETAS: Final[List[int]] = _precompute_zetas()
"""Pre-computed twiddle-factor table (256 entries).

Indexed by the Dilithium reference convention:
``_ZETAS[i] = 1753^{bitreverse_8(i)} mod q``."""


# ---------------------------------------------------------------------------
# Reduction helpers
# ---------------------------------------------------------------------------
def barrett_reduce(a: int) -> int:
    r"""Barrett reduction: fast ``a mod q``.

    Uses :math:`v = \\lfloor 2^{46} / q \\rfloor` with a 46-bit
    right shift:

    .. math::

        t = \\lfloor a \\cdot v / 2^{46} \\rfloor, \quad
        r = a - t \\cdot q

    One conditional correction yields :math:`r \\in [0, q-1]`.
    The 46-bit precision safely covers any 64-bit signed product.

    This function is exported for use by other ML-DSA sub-modules.

    Args:
        a: Input integer (may be negative or larger than *q*).

    Returns:
        ``a mod q`` in :math:`[0, q-1]`.
    """
    t = (a * _BARRETT_V) >> 46
    r = a - t * Q
    if r < 0:
        r += Q
    elif r >= Q:
        r -= Q
    return r


def _montgomery_reduce(a: int) -> int:
    r"""Single Montgomery reduction step: :math:`a \\cdot R^{-1} \\bmod q`.

    Uses :math:`q' = -q^{-1} \\bmod R = 58728449`:

    .. math::

        t = a \\cdot q' \\bmod R, \quad
        u = (a + t \\cdot q) / R

    Args:
        a: Input product (up to roughly :math:`q \\cdot R`).

    Returns:
        Reduced value in :math:`[0, q-1]`.
    """
    t = (a * _MONT_Q_PRIME) & (MONT_R - 1)
    u = (a + t * Q) >> 32
    if u >= Q:
        u -= Q
    if u >= Q:
        u -= Q
    return u


def to_montgomery(a: int) -> int:
    r"""Convert a plain coefficient to Montgomery form: :math:`aR \\bmod q`."""
    return (a * MONT_R) % Q


def from_montgomery(a_mont: int) -> int:
    r"""Convert Montgomery-form coefficient back to plain: :math:`aR^{-1} \\bmod q`."""
    return _montgomery_reduce(a_mont)


def montgomery_mul(a: int, b: int) -> int:
    r"""Montgomery multiplication: ``(a * b * R^{-1}) mod q``."""
    return _montgomery_reduce(a * b)


# ---------------------------------------------------------------------------
# Butterfly layers (internal)
# ---------------------------------------------------------------------------
def _ntt_layer_fwd(a: List[int], layer: int, zeta_offset: int) -> int:
    """Single forward Cooley-Tukey NTT layer.

    Follows the Dilithium reference: breadth-first, in-place,
    Cooley-Tukey butterflies.  No reduction is performed after
    additions or subtractions — a single ``% Q`` keeps coefficients
    in range.

    Layer structure (8 layers total)::

    ====== ====== =========== =========================================
    Layer  len    num_groups  zeta usage (PRE-increment)
    ====== ====== =========== =========================================
    0      128    1           ``_ZETAS[zeta_offset+1]``
    1      64     2           ``_ZETAS[zeta_offset+1 .. +2]``
    2      32     4           ``_ZETAS[zeta_offset+1 .. +4]``
    3      16     8           ``_ZETAS[zeta_offset+1 .. +8]``
    4      8      16          ``_ZETAS[zeta_offset+1 .. +16]``
    5      4      32          ``_ZETAS[zeta_offset+1 .. +32]``
    6      2      64          ``_ZETAS[zeta_offset+1 .. +64]``
    7      1      128         ``_ZETAS[zeta_offset+1 .. +128]``
    ====== ====== =========== =========================================

    Args:
        a: Mutable list of 256 coefficients.
        layer: Layer index ``0 .. 7``.
        zeta_offset: Current index into :data:`_ZETAS`.

    Returns:
        Updated *zeta_offset*.
    """
    length = 128 >> layer
    num_groups = N // (2 * length)
    for group in range(num_groups):
        base = group * 2 * length
        zeta_offset += 1  # PRE-increment (matches Dilithium reference)
        zeta = _ZETAS[zeta_offset]
        for j in range(length):
            idx = base + j
            t = (zeta * a[idx + length]) % Q
            a[idx + length] = (a[idx] - t) % Q
            a[idx] = (a[idx] + t) % Q
    return zeta_offset


def _ntt_layer_inv(a: List[int], layer: int, zeta_offset: int) -> int:
    """Single inverse Cooley-Tukey NTT layer.

    Uses twiddle factors in **reverse** order with **negation**
    (PRE-decrement, matching the Dilithium reference exactly).

    Butterfly (inverse)::

        t = a[idx]
        a[idx]       = (t + a[idx + length]) mod q
        a[idx + len] = (t - a[idx + length]) mod q
        a[idx + len] = (-zeta * a[idx + len]) mod q

    Args:
        a: Mutable list of 256 coefficients.
        layer: Layer index ``0 .. 7``.
        zeta_offset: Current index into :data:`_ZETAS` (decremented).

    Returns:
        Updated *zeta_offset*.
    """
    length = 128 >> layer
    num_groups = N // (2 * length)
    for group in range(num_groups):
        base = group * 2 * length
        zeta_offset -= 1  # PRE-decrement (matches Dilithium reference)
        zeta = (-_ZETAS[zeta_offset]) % Q  # NEGATED
        for j in range(length):
            idx = base + j
            t = a[idx]
            a[idx] = (t + a[idx + length]) % Q
            a[idx + length] = (t - a[idx + length]) % Q
            a[idx + length] = (zeta * a[idx + length]) % Q
    return zeta_offset


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def ntt(f: List[int]) -> List[int]:
    """Forward Complete NTT (FIPS 204, Dilithium).

    Maps a degree-255 polynomial to 256 scalar values in
    :math:`\\mathbb{Z}_q` via 8 butterfly layers.  The output is in
    bit-reversed order (the inverse transform handles reordering
    transparently).

    Args:
        f: Input coefficients, length 256, each in :math:`[0, q-1]`.

    Returns:
        NTT-domain representation (256 scalar values).

    Raises:
        ValueError: If input length is not 256.
    """
    if len(f) != N:
        raise ValueError(f"Expected {N} coefficients, got {len(f)}")

    a = [x % Q for x in f]

    zeta_offset = 0  # PRE-increment: first zeta is _ZETAS[1]
    for layer in range(NUM_LAYERS):
        zeta_offset = _ntt_layer_fwd(a, layer, zeta_offset)

    return a


def ntt_inv(f_hat: List[int]) -> List[int]:
    """Inverse Complete NTT (FIPS 204, Dilithium).

    Reverses :func:`ntt`.  Processes 8 layers in reverse with
    negated twiddle factors consumed in reverse order, then scales
    by :math:`256^{-1} \\bmod q`.

    Args:
        f_hat: NTT-domain representation (256 scalar values).

    Returns:
        Plain polynomial coefficients (256 values).

    Raises:
        ValueError: If input length is not 256.
    """
    if len(f_hat) != N:
        raise ValueError(f"Expected {N} coefficients, got {len(f_hat)}")

    a = [x % Q for x in f_hat]

    # Inverse layers: negated twiddles consumed in reverse (PRE-decrement)
    zeta_offset = 256  # one past last entry; first accessed will be _ZETAS[255]
    for layer in reversed(range(NUM_LAYERS)):
        zeta_offset = _ntt_layer_inv(a, layer, zeta_offset)

    # Scale by 256^(-1) mod q
    _256_INV: Final[int] = 8347681  # 256^(-1) mod 8380417
    for i in range(N):
        a[i] = (a[i] * _256_INV) % Q

    return a


def ntt_multiply(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Pointwise multiplication in the ML-DSA NTT domain.

    For the **complete** NTT, the ring is fully decomposed into
    256 copies of :math:`\\mathbb{Z}_q`.  Multiplication is
    coefficient-wise:

    .. math::

        \\hat{c}_i = \\hat{a}_i \\cdot \\hat{b}_i \\pmod q

    This is simpler than ML-KEM, which must multiply degree-2
    polynomial residues.

    Args:
        a_hat: First operand in NTT domain (256 values).
        b_hat: Second operand in NTT domain (256 values).

    Returns:
        Product in NTT domain (256 values).

    Raises:
        ValueError: If inputs are not length 256.
    """
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError("Both inputs must have length 256")

    return [barrett_reduce(a_hat[i] * b_hat[i]) for i in range(N)]


def ntt_add(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Element-wise addition: ``(a_i + b_i) mod q``."""
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError("Both inputs must have length 256")
    return [barrett_reduce(a_hat[i] + b_hat[i]) for i in range(N)]


def ntt_sub(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Element-wise subtraction: ``(a_i - b_i) mod q``."""
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError("Both inputs must have length 256")
    return [barrett_reduce(a_hat[i] - b_hat[i]) for i in range(N)]


def ntt_scalar_multiply(a_hat: List[int], c: int) -> List[int]:
    """Multiply every NTT coefficient by a scalar."""
    if len(a_hat) != N:
        raise ValueError(f"Expected {N} coefficients, got {len(a_hat)}")
    return [barrett_reduce(c * a_hat[i]) for i in range(N)]


def ntt_eq(a_hat: List[int], b_hat: List[int]) -> bool:
    """Compare two NTT-domain polynomials for equality."""
    if len(a_hat) != N or len(b_hat) != N:
        return False
    return all(a_hat[i] % Q == b_hat[i] % Q for i in range(N))


def ntt_zero() -> List[int]:
    """Return the NTT-domain zero polynomial (256 zeros)."""
    return [0] * N
