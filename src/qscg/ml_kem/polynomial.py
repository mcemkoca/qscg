"""Polynomial ring R_q = Z_q[X]/(X^n + 1) for ML-KEM (FIPS 203).

This module implements polynomial arithmetic over the ML-KEM ring
:math:`\\mathbb{Z}_q[X]/(X^{256}+1)` with :math:`q=3329`.  All
operations use the incomplete Number-Theoretic Transform (NTT) with
7 layers for fast multiplication.

The main classes are:

    - :class:`Polynomial` -- a single polynomial in R_q
    - :class:`PolyVector`  -- a vector of *k* polynomials (module element)

Key design decisions:

    - Coefficients are stored as **plain** integers in ``[0, q-1]``
      (NOT Montgomery form).  Montgomery conversions are handled
      internally by the NTT layer when required.
    - :meth:`Polynomial.__mul__` automatically converts to NTT domain,
      multiplies pointwise, and inverse-NTTs back.
    - Serialization uses 12-bit little-endian packing (384 bytes per
      polynomial), matching FIPS 203 Section 4.2.1.

Example::

    >>> from qscg.ml_kem.polynomial import Polynomial, PolyVector
    >>> a = Polynomial([i % 3329 for i in range(256)])
    >>> b = Polynomial([(2*i) % 3329 for i in range(256)])
    >>> c = a + b        # Polynomial addition
    >>> d = a * b        # NTT-based multiplication
    >>> vec = PolyVector([a, b]) + PolyVector([b, a])

References:
    - NIST FIPS 203, Section 4 -- ML-KEM Internal Functions
    - NIST FIPS 203, Appendix A -- NTT and SampleNTT
"""

from typing import List, Optional

from . import ntt
from ..common.constants import MLKEM_Q, MLKEM_N
from ..common.utilities import center_reduce

Q: int = MLKEM_Q
"""Coefficient modulus :math:`q = 3329`."""

N: int = MLKEM_N
"""Polynomial degree :math:`n = 256`."""


class Polynomial:
    """A polynomial in :math:`R_q = \\mathbb{Z}_q[X]/(X^n+1)` for ML-KEM.

    Coefficients are stored as standard integers in ``[0, q-1]`` (NOT
    Montgomery form).  All NTT-domain conversions are handled
    transparently by :meth:`__mul__` and by the free functions in this
    module.

    Args:
        coeffs: List of coefficients.  Must have length ``N`` (256).
                Shorter lists are zero-padded; excess elements are
                truncated.  Each coefficient is reduced modulo ``Q``.

    Attributes:
        coeffs (List[int]): Coefficient list of length ``N``.

    Example::

        >>> p = Polynomial([1, 2, 3] + [0]*253)
        >>> p.coeffs[0]
        1
        >>> zero = Polynomial.zero()
    """

    def __init__(self, coeffs: List[int]) -> None:
        self.coeffs: List[int] = [c % Q for c in coeffs[:N]]
        while len(self.coeffs) < N:
            self.coeffs.append(0)

    def __add__(self, other: "Polynomial") -> "Polynomial":
        """Element-wise addition: ``(self + other) mod q``.

        Args:
            other: Polynomial to add.

        Returns:
            New polynomial with element-wise sum modulo ``Q``.
        """
        return Polynomial(
            [(a + b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        )

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        """Element-wise subtraction: ``(self - other) mod q``.

        Args:
            other: Polynomial to subtract.

        Returns:
            New polynomial with element-wise difference modulo ``Q``.
        """
        return Polynomial(
            [(a - b) % Q for a, b in zip(self.coeffs, other.coeffs)]
        )

    def __neg__(self) -> "Polynomial":
        """Negate all coefficients: ``(-self) mod q``.

        Returns:
            New polynomial with negated coefficients modulo ``Q``.
        """
        return Polynomial([(-c) % Q for c in self.coeffs])

    def __mul__(self, other: "Polynomial") -> "Polynomial":
        """NTT-based polynomial multiplication.

        Converts both operands to NTT domain via the incomplete 7-layer
        NTT, multiplies pointwise using degree-2 residue multiplication,
        then inverse-NTTs back.  This is the fast :math:`O(n \\log n)
        multiplication required by ML-KEM.

        Args:
            other: Polynomial multiplier.

        Returns:
            Product polynomial in the standard coefficient domain.
        """
        a_hat = ntt.ntt(self.coeffs)
        b_hat = ntt.ntt(other.coeffs)
        c_hat = ntt.ntt_multiply(a_hat, b_hat)
        c = ntt.ntt_inv(c_hat)
        return Polynomial(c)

    def __rmul__(self, scalar: int) -> "Polynomial":
        """Scalar multiplication from the left: ``scalar * self``.

        Args:
            scalar: Integer scalar to multiply each coefficient by.

        Returns:
            New polynomial with scaled coefficients modulo ``Q``.
        """
        return Polynomial([(scalar * c) % Q for c in self.coeffs])

    def __eq__(self, other: object) -> bool:
        """Compare two polynomials for coefficient-wise equality.

        Args:
            other: Object to compare against.

        Returns:
            ``True`` if *other* is a :class:`Polynomial` with identical
            coefficients (modulo ``Q``), ``False`` otherwise.
        """
        if not isinstance(other, Polynomial):
            return NotImplemented
        return self.coeffs == other.coeffs

    def __repr__(self) -> str:
        """Return a concise string representation.

        Returns:
            String of the form ``Polynomial([c0, c1, ..., cN-1])``.
        """
        return f"Polynomial({self.coeffs!r})"

    def center(self) -> List[int]:
        """Center coefficients to the symmetric range ``[-Q/2, Q/2]``.

        This is the canonical representative used in lattice-based
        schemes for coefficient compression (``Compress_q`` / ``Decompress_q``
        in FIPS 203).

        Returns:
            List of 256 integers in ``[-Q//2, Q//2]``.
        """
        return [center_reduce(c, Q) for c in self.coeffs]

    def infinity_norm(self) -> int:
        """Infinity norm: :math:`\\max_i |\\text{center_reduce}(c_i)|`.

        Returns:
            Maximum absolute value of centred coefficients.
        """
        centered = self.center()
        return max(abs(c) for c in centered)

    def to_ntt(self) -> List[int]:
        """Convert this polynomial to the NTT domain.

        Returns:
            NTT-domain coefficients (256 integers).
        """
        return ntt.ntt(self.coeffs)

    @classmethod
    def from_ntt(cls, ntt_coeffs: List[int]) -> "Polynomial":
        """Create a polynomial from NTT-domain coefficients.

        Args:
            ntt_coeffs: NTT-domain representation (256 integers).

        Returns:
            Polynomial in the standard coefficient domain.
        """
        return cls(ntt.ntt_inv(ntt_coeffs))

    def to_bytes(self) -> bytes:
        """Serialize to 12-bit little-endian packed bytes.

        Packs 256 coefficients into 384 bytes using the FIPS 203
        encoding: each pair of coefficients occupies 3 bytes
        (12 bits each, little-endian).

        Returns:
            384-byte packed representation.
        """
        result = bytearray()
        for i in range(0, N, 2):
            c0 = self.coeffs[i] & 0xFFF
            c1 = self.coeffs[i + 1] & 0xFFF if i + 1 < N else 0
            t = c0 | (c1 << 12)
            result.extend(t.to_bytes(3, "little"))
        return bytes(result)

    @classmethod
    def from_bytes(cls, data: bytes) -> "Polynomial":
        """Deserialize from 12-bit little-endian packed bytes.

        Args:
            data: Packed byte string (384 bytes for 256 coefficients).

        Returns:
            Reconstructed polynomial.

        Raises:
            ValueError: If *data* is too short to decode 256 coefficients.
        """
        if len(data) < 384:
            raise ValueError(f"Expected at least 384 bytes, got {len(data)}")
        coeffs: List[int] = []
        for i in range(0, 384, 3):
            t = int.from_bytes(data[i : i + 3], "little")
            coeffs.append(t & 0xFFF)
            coeffs.append((t >> 12) & 0xFFF)
        return cls(coeffs[:N])

    @classmethod
    def zero(cls) -> "Polynomial":
        """Return the zero polynomial (all coefficients are 0).

        Returns:
            Zero polynomial.
        """
        return cls([0] * N)

    @classmethod
    def random(cls) -> "Polynomial":
        """Generate a uniformly random polynomial in :math:`R_q`.

        Uses :func:`secrets.randbelow` for cryptographically secure
        randomness.

        Returns:
            Random polynomial with coefficients in ``[0, Q-1]``.
        """
        import secrets

        return cls([secrets.randbelow(Q) for _ in range(N)])

    @classmethod
    def delta(cls, idx: int) -> "Polynomial":
        """Return the monomial :math:`X^{\\text{idx}}` (Kronecker delta).

        Useful for unit-testing multiplication: multiplying by
        :math:`X^{\\text{idx}}` should rotate coefficients with sign
        changes due to the :math:`X^n+1` modulus.

        Args:
            idx: Degree of the monomial (0 <= idx < N).

        Returns:
            Polynomial with a single ``1`` at position *idx*.
        """
        coeffs = [0] * N
        coeffs[idx % N] = 1
        return cls(coeffs)


class PolyVector:
    """Vector of :math:`k` polynomials over :math:`R_q`.

    In ML-KEM, a module element is a vector of :math:`k` polynomials
    where :math:`k` varies by security parameter (2, 3, or 4).

    Args:
        polys: List of :class:`Polynomial` instances.

    Attributes:
        polys (List[Polynomial]): The list of polynomials.

    Example::

        >>> v = PolyVector.zero(3)  # k=3 (security level 3)
        >>> w = PolyVector.random(3)
        >>> u = v + w
    """

    def __init__(self, polys: List[Polynomial]) -> None:
        self.polys: List[Polynomial] = list(polys)

    def __add__(self, other: "PolyVector") -> "PolyVector":
        """Element-wise vector addition.

        Args:
            other: Vector to add.

        Returns:
            New vector with element-wise polynomial sums.

        Raises:
            ValueError: If vectors have different lengths.
        """
        if len(self.polys) != len(other.polys):
            raise ValueError(
                f"Cannot add vectors of length {len(self.polys)} and "
                f"{len(other.polys)}"
            )
        return PolyVector([a + b for a, b in zip(self.polys, other.polys)])

    def __sub__(self, other: "PolyVector") -> "PolyVector":
        """Element-wise vector subtraction.

        Args:
            other: Vector to subtract.

        Returns:
            New vector with element-wise polynomial differences.

        Raises:
            ValueError: If vectors have different lengths.
        """
        if len(self.polys) != len(other.polys):
            raise ValueError(
                f"Cannot subtract vectors of length {len(self.polys)} and "
                f"{len(other.polys)}"
            )
        return PolyVector([a - b for a, b in zip(self.polys, other.polys)])

    def __neg__(self) -> "PolyVector":
        """Negate every polynomial in the vector.

        Returns:
            New vector with all polynomials negated.
        """
        return PolyVector([-p for p in self.polys])

    def __len__(self) -> int:
        """Return the number of polynomials in the vector.

        Returns:
            Vector dimension (value of :math:`k`).
        """
        return len(self.polys)

    def __getitem__(self, idx: int) -> Polynomial:
        """Index into the polynomial vector.

        Args:
            idx: Zero-based index.

        Returns:
            The *idx*-th polynomial.
        """
        return self.polys[idx]

    def __eq__(self, other: object) -> bool:
        """Compare two polynomial vectors for equality.

        Args:
            other: Object to compare against.

        Returns:
            ``True`` if *other* is a :class:`PolyVector` with the same
            length and equal polynomials at every position.
        """
        if not isinstance(other, PolyVector):
            return NotImplemented
        if len(self.polys) != len(other.polys):
            return False
        return all(a == b for a, b in zip(self.polys, other.polys))

    def __repr__(self) -> str:
        """Return a concise string representation.

        Returns:
            String of the form ``PolyVector([p0, p1, ...])``.
        """
        return f"PolyVector({self.polys!r})"

    def infinity_norm(self) -> int:
        """Infinity norm of the vector: max polynomial infinity norm.

        Returns:
            Maximum :meth:`Polynomial.infinity_norm` across all
            components.
        """
        return max(p.infinity_norm() for p in self.polys)

    def to_ntt(self) -> List[List[int]]:
        """Convert every polynomial to NTT domain.

        Returns:
            List of NTT-domain coefficient lists (one per polynomial).
        """
        return [p.to_ntt() for p in self.polys]

    @classmethod
    def from_ntt(cls, ntt_coeffs: List[List[int]]) -> "PolyVector":
        """Create a vector from NTT-domain coefficient lists.

        Args:
            ntt_coeffs: List of NTT-domain representations.

        Returns:
            Vector in the standard coefficient domain.
        """
        return cls([Polynomial.from_ntt(nc) for nc in ntt_coeffs])

    @classmethod
    def zero(cls, k: int) -> "PolyVector":
        """Create a zero vector of dimension *k*.

        Args:
            k: Number of polynomials (2, 3, or 4 for ML-KEM).

        Returns:
            Zero vector of length *k*.
        """
        return cls([Polynomial.zero() for _ in range(k)])

    @classmethod
    def random(cls, k: int) -> "PolyVector":
        """Generate a uniformly random vector of dimension *k*.

        Args:
            k: Number of polynomials.

        Returns:
            Random vector of length *k*.
        """
        return cls([Polynomial.random() for _ in range(k)])

    @classmethod
    def from_polys(cls, polys: List[Polynomial]) -> "PolyVector":
        """Create a vector from an existing list of polynomials.

        Args:
            polys: List of :class:`Polynomial` instances.

        Returns:
            New polynomial vector wrapping the given list.
        """
        return cls(polys)


def mat_vec_mul(
    A_hat: List[List[Polynomial]], v_hat: PolyVector
) -> PolyVector:
    """Matrix-vector multiplication in the **NTT domain**.

    Computes :math:`\\hat{A} \\cdot \\hat{v}` where both the matrix
    and the vector are in NTT-domain representation.  This is the
    core operation in ML-KEM key generation and encapsulation.

    Args:
        A_hat: :math:`k \\times k` matrix of NTT-domain polynomials.
               Each entry is a :class:`Polynomial` whose coefficients
               are already in NTT form.
        v_hat: Vector of :math:`k` NTT-domain polynomials.

    Returns:
        Result vector of :math:`k` NTT-domain polynomials.

    Raises:
        ValueError: If dimensions are inconsistent.

    Example::

        >>> k = 2
        >>> A = [[Polynomial.random() for _ in range(k)] for _ in range(k)]
        >>> v = PolyVector.random(k)
        >>> result = mat_vec_mul(A, v)
        >>> len(result) == k
        True
    """
    k = len(A_hat)
    if k == 0:
        raise ValueError("Empty matrix")
    if len(v_hat) != k:
        raise ValueError(
            f"Matrix dimension {k}x{k} incompatible with vector length {len(v_hat)}"
        )

    result: List[Polynomial] = []
    for i in range(k):
        acc = Polynomial.zero()
        for j in range(k):
            a_ntt = A_hat[i][j].to_ntt()
            v_ntt = v_hat[j].to_ntt()
            prod_ntt = ntt.ntt_multiply(a_ntt, v_ntt)
            prod = Polynomial.from_ntt(prod_ntt)
            acc = acc + prod
        result.append(acc)
    return PolyVector(result)


def vec_vec_mul(u_hat: PolyVector, v_hat: PolyVector) -> Polynomial:
    """Inner product of two polynomial vectors in the **NTT domain**.

    Computes :math:`\\langle \\hat{u}, \\hat{v} \\rangle = \\sum_i
    \\hat{u}_i \\cdot \\hat{v}_i` where multiplication is in the NTT
    domain.

    Args:
        u_hat: First vector of NTT-domain polynomials.
        v_hat: Second vector of NTT-domain polynomials.

    Returns:
        Single polynomial (the inner product) in NTT domain.

    Raises:
        ValueError: If vectors have different lengths.
    """
    if len(u_hat) != len(v_hat):
        raise ValueError(
            f"Cannot compute inner product of vectors with lengths "
            f"{len(u_hat)} and {len(v_hat)}"
        )

    acc = Polynomial.zero()
    for i in range(len(u_hat)):
        u_ntt = u_hat[i].to_ntt()
        v_ntt = v_hat[i].to_ntt()
        prod_ntt = ntt.ntt_multiply(u_ntt, v_ntt)
        prod = Polynomial.from_ntt(prod_ntt)
        acc = acc + prod
    return acc


def poly_vec_ntt_add(
    a_hat: List[List[int]], b_hat: List[List[int]]
) -> List[List[int]]:
    """Element-wise addition of two polynomial vectors in NTT domain.

    Args:
        a_hat: First vector (list of NTT coefficient lists).
        b_hat: Second vector (list of NTT coefficient lists).

    Returns:
        Sum vector in NTT domain.
    """
    return [ntt.ntt_add(a, b) for a, b in zip(a_hat, b_hat)]


def poly_vec_ntt_sub(
    a_hat: List[List[int]], b_hat: List[List[int]]
) -> List[List[int]]:
    """Element-wise subtraction of two polynomial vectors in NTT domain.

    Args:
        a_hat: First vector (list of NTT coefficient lists).
        b_hat: Second vector (list of NTT coefficient lists).

    Returns:
        Difference vector in NTT domain.
    """
    return [ntt.ntt_sub(a, b) for a, b in zip(a_hat, b_hat)]
