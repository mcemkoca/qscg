"""Incomplete NTT for ML-KEM (FIPS 203, Appendix A).

ML-KEM uses an incomplete Number-Theoretic Transform with the following parameters:

  - Modulus :math:`q = 3329`
  - Degree  :math:`n = 256`
  - Primitive 512-th root of unity: :math:`\\zeta = 17`
  - 7 NTT layers (incomplete — output is 128 degree-2 polynomials)
  - Montgomery radix: :math:`R = 2^{16}`

The incomplete NTT decomposes the ring
:math:`\\mathbb{Z}_q[X]/(X^{256}+1)` into 128 copies of
:math:`\\mathbb{Z}_q[X]/(X^2 - \\zeta^{2\\cdot\\text{br}(i)+1})`.

This module provides:

  - :func:`ntt` / :func:`ntt_inv` — forward and inverse transforms
  - :func:`ntt_multiply` — pointwise multiplication in NTT domain
  - :func:`ntt_add` / :func:`ntt_sub` — element-wise addition/subtraction
  - :func:`to_montgomery` / :func:`from_montgomery` — Montgomery helpers
  - :func:`barrett_reduce` — public Barrett reduction helper

Example::

    >>> from qscg.ml_kem.ntt import ntt, ntt_inv, ntt_multiply
    >>> a = [i % 3329 for i in range(256)]
    >>> b = [(2 * i) % 3329 for i in range(256)]
    >>> a_hat = ntt(a)
    >>> b_hat = ntt(b)
    >>> c_hat = ntt_multiply(a_hat, b_hat)
    >>> c = ntt_inv(c_hat)

References:
    - NIST FIPS 203, Section 4 — ML-KEM Internal Functions
    - NIST FIPS 203, Appendix A — NTT and SampleNTT
"""

from typing import List, Final

# ---------------------------------------------------------------------------
# Fixed parameters (FIPS 203)
# ---------------------------------------------------------------------------
Q: Final[int] = 3329
"""Modulus :math:`q = 3329` (prime, :math:`q \\equiv 1 \\pmod{512}`)."""

N: Final[int] = 256
"""Polynomial degree :math:`n = 256`."""

ZETA: Final[int] = 17
"""Primitive 512-th root of unity modulo :math:`q`."""

NUM_LAYERS: Final[int] = 7
"""Incomplete NTT uses 7 layers."""

MONT_R: Final[int] = 1 << 16
"""Montgomery radix :math:`R = 2^{16}`."""

# Barrett constant: v = floor(2^26 / Q) = 20159 (used with 26-bit shift)
# Matches the reference implementation constant.
_BARRETT_V: Final[int] = 20159

# Montgomery constant: q' = -q^(-1) mod 2^16 = 3327
_MONT_Q_PRIME: Final[int] = 3327


def _bit_reverse(n: int, bits: int) -> int:
    """Bit-reversal permutation.

    Reverses the order of the lowest *bits* bits of *n*.

    Args:
        n: Integer whose bits are to be reversed.
        bits: Number of low-order bits to reverse.

    Returns:
        The bit-reversed value.
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
# Pre-computed twiddle factors (FIPS 203, Appendix A)
# ---------------------------------------------------------------------------
def _precompute_zetas() -> List[int]:
    """Pre-compute the 128 twiddle factors used by ML-KEM NTT.

    FIPS 203 defines ``zetas[i] = 17^{bitreverse_7(i)} mod q`` for
    ``i = 0 .. 127``.

    The forward NTT (Algorithm 8) consumes ``zetas[1]`` through
    ``zetas[127]`` in breadth-first order.  ``zetas[0] = 1`` is
    unused by the NTT itself.

    Returns:
        List of 128 integers in :math:`[0, q-1]`.
    """
    zetas: List[int] = []
    for i in range(128):
        rev = _bit_reverse(i, 7)
        zetas.append(_mod_exp(ZETA, rev, Q))
    return zetas


_ZETAS: Final[List[int]] = _precompute_zetas()
"""Pre-computed twiddle-factor table (128 entries)."""


# ---------------------------------------------------------------------------
# Reduction helpers
# ---------------------------------------------------------------------------
def barrett_reduce(a: int) -> int:
    r"""Barrett reduction: fast ``a mod q``.

    Uses the constant :math:`v = \\lfloor 2^{26} / q \\rfloor = 20159`
    with a 26-bit right shift:

    .. math::

        t = \\lfloor a \\cdot v / 2^{26} \\rfloor, \quad
        r = a - t \\cdot q

    One conditional correction yields :math:`r \\in [0, q-1]`.

    This constant matches the official Kyber / ML-KEM reference
    implementation.

    Args:
        a: Input integer (may be negative or larger than *q*;
           for products of two coefficients, :math:`|a| < q^2`).

    Returns:
        ``a mod q`` in :math:`[0, q-1]`.
    """
    t = (a * _BARRETT_V) >> 26
    r = a - t * Q
    if r < 0:
        r += Q
    elif r >= Q:
        r -= Q
    return r


def _montgomery_reduce(a: int) -> int:
    r"""Single Montgomery reduction step: :math:`a \\cdot R^{-1} \\bmod q`.

    Uses :math:`q' = -q^{-1} \\bmod R = 3327`:

    .. math::

        t = a \\cdot q' \\bmod R, \quad
        u = (a + t \\cdot q) / R

    Args:
        a: Input product (up to roughly :math:`q \\cdot R`).

    Returns:
        Reduced value in :math:`[0, q-1]`.
    """
    t = (a * _MONT_Q_PRIME) & (MONT_R - 1)
    u = (a + t * Q) >> 16
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
    """Forward Cooley-Tukey NTT layer (FIPS 203 Algorithm 8).

    Layer structure::

    ====== ====== =========== ============================================
    Layer  len    num_groups  zeta usage
    ====== ====== =========== ============================================
    0      128    1           ``_ZETAS[zeta_offset]`` (one twiddle)
    1      64     2           ``_ZETAS[zeta_offset .. zeta_offset+1]``
    2      32     4           ``_ZETAS[zeta_offset .. zeta_offset+3]``
    3      16     8           ``_ZETAS[zeta_offset .. zeta_offset+7]``
    4      8      16          ``_ZETAS[zeta_offset .. zeta_offset+15]``
    5      4      32          ``_ZETAS[zeta_offset .. zeta_offset+31]``
    6      2      64          ``_ZETAS[zeta_offset .. zeta_offset+63]``
    ====== ====== =========== ============================================

    Args:
        a: Mutable list of 256 coefficients.
        layer: Layer index ``0 .. 6``.
        zeta_offset: Current index into :data:`_ZETAS`.

    Returns:
        Updated *zeta_offset*.
    """
    length = 128 >> layer
    num_groups = N // (2 * length)
    for group in range(num_groups):
        base = group * 2 * length
        zeta = _ZETAS[zeta_offset]
        zeta_offset += 1
        for j in range(length):
            idx = base + j
            u = a[idx]
            v = barrett_reduce(zeta * a[idx + length])
            a[idx] = barrett_reduce(u + v)
            a[idx + length] = barrett_reduce(u - v)
    return zeta_offset


def _ntt_layer_inv(a: List[int], layer: int, zeta_offset: int) -> int:
    """Inverse Cooley-Tukey NTT layer (FIPS 203 Algorithm 9).

    Uses twiddle factors in **reverse** order (zeta_offset is
    decremented).  The butterfly structure is the inverse of the
    forward butterfly **without** inverting the twiddle — the same
    ``zeta`` values are used as in the forward direction.

    Butterfly (inverse)::

        t = a[idx]
        a[idx]       = t + a[idx + length]
        a[idx + len] = zeta * (a[idx + len] - t)

    Args:
        a: Mutable list of 256 coefficients.
        layer: Layer index ``0 .. 6``.
        zeta_offset: Current index into :data:`_ZETAS` (decremented).

    Returns:
        Updated *zeta_offset*.
    """
    length = 128 >> layer
    num_groups = N // (2 * length)
    for group in range(num_groups):
        base = group * 2 * length
        zeta_offset -= 1
        zeta = _ZETAS[zeta_offset]
        for j in range(length):
            idx = base + j
            t = a[idx]
            a[idx] = barrett_reduce(t + a[idx + length])
            a[idx + length] = barrett_reduce(a[idx + length] - t)
            a[idx + length] = barrett_reduce(zeta * a[idx + length])
    return zeta_offset


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def ntt(f: List[int]) -> List[int]:
    """Forward Incomplete NTT (FIPS 203, Algorithm 8).

    Maps a degree-255 polynomial to 128 degree-2 polynomials via 7
    butterfly layers.  Output pair ``(out[2i], out[2i+1])`` is the
    residue modulo :math:`X^2 - \\zeta^{2\\cdot\\text{br}_7(i)+1}`.

    Args:
        f: Input coefficients, length 256, each in :math:`[0, q-1]`.

    Returns:
        NTT-domain representation (256 coefficients).

    Raises:
        ValueError: If input length is not 256.
    """
    if len(f) != N:
        raise ValueError(f"Expected {N} coefficients, got {len(f)}")

    a = [x % Q for x in f]

    zeta_offset = 1  # zetas[0] is unused; Algorithm 8 starts j at 1
    for layer in range(NUM_LAYERS):
        zeta_offset = _ntt_layer_fwd(a, layer, zeta_offset)

    return a


def ntt_inv(f_hat: List[int]) -> List[int]:
    """Inverse Incomplete NTT (FIPS 203, Algorithm 9).

    Reverses :func:`ntt`.  Processes 7 layers in reverse with the
    same twiddle values (consumed in reverse order), then scales
    by :math:`128^{-1} \\bmod q` (the incomplete NTT omits one
    layer, so the net scaling factor is :math:`2^7 = 128`, not
    :math:`n = 256`).

    Args:
        f_hat: NTT-domain coefficients (256 values).

    Returns:
        Plain polynomial coefficients (256 values).

    Raises:
        ValueError: If input length is not 256.
    """
    if len(f_hat) != N:
        raise ValueError(f"Expected {N} coefficients, got {len(f_hat)}")

    a = [x % Q for x in f_hat]

    # Inverse layers: twiddles consumed in reverse order
    zeta_offset = 128  # one past the last used entry (zetas[127])
    for layer in reversed(range(NUM_LAYERS)):
        zeta_offset = _ntt_layer_inv(a, layer, zeta_offset)

    # Scale by 128^(-1) mod q (net scaling from 7 butterfly layers)
    _128_INV: Final[int] = 3303  # 128^(-1) mod 3329
    for i in range(N):
        a[i] = barrett_reduce(a[i] * _128_INV)

    return a


def ntt_multiply(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Pointwise multiplication in the ML-KEM NTT domain.

    The 256 NTT coefficients are organised as 64 blocks of 4.
    Each block contains **two** degree-2 multiplications with
    opposite twiddle factors, matching the Kyber reference
    implementation::

        for i = 0 .. 63:
            z = zetas[64 + i]
            # first pair  (coeffs 4i, 4i+1)  mod (X^2 - z)
            # second pair (coeffs 4i+2, 4i+3) mod (X^2 + z)

    The degree-2 product formula is:

    .. math::

        (a_0 + a_1 X)(b_0 + b_1 X) \\bmod (X^2 - \\zeta)
        = (a_0 b_0 + a_1 b_1 \\zeta) + (a_0 b_1 + a_1 b_0) X

    Args:
        a_hat: First operand (256 coefficients).
        b_hat: Second operand (256 coefficients).

    Returns:
        Product (256 coefficients).

    Raises:
        ValueError: If inputs are not length 256.
    """
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError("Both inputs must have length 256")

    result: List[int] = [0] * N
    for i in range(64):
        # First pair: coefficients [4i, 4i+1] with zeta = zetas[64+i]
        z = _ZETAS[64 + i]
        a0, a1 = a_hat[4 * i], a_hat[4 * i + 1]
        b0, b1 = b_hat[4 * i], b_hat[4 * i + 1]
        result[4 * i]     = barrett_reduce(a0 * b0 + a1 * b1 * z)
        result[4 * i + 1] = barrett_reduce(a0 * b1 + a1 * b0)

        # Second pair: coefficients [4i+2, 4i+3] with zeta = -z
        z_neg = (-z) % Q
        a0, a1 = a_hat[4 * i + 2], a_hat[4 * i + 3]
        b0, b1 = b_hat[4 * i + 2], b_hat[4 * i + 3]
        result[4 * i + 2] = barrett_reduce(a0 * b0 + a1 * b1 * z_neg)
        result[4 * i + 3] = barrett_reduce(a0 * b1 + a1 * b0)

    return result


def ntt_add(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Element-wise addition in the NTT domain: ``(a_i + b_i) mod q``."""
    if len(a_hat) != N or len(b_hat) != N:
        raise ValueError("Both inputs must have length 256")
    return [barrett_reduce(a_hat[i] + b_hat[i]) for i in range(N)]


def ntt_sub(a_hat: List[int], b_hat: List[int]) -> List[int]:
    """Element-wise subtraction in the NTT domain: ``(a_i - b_i) mod q``."""
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
