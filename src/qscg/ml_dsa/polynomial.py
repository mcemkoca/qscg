"""Polynomial ring R_q = Z_q[X]/(X^n + 1) for ML-DSA (FIPS 204).

This module implements polynomial arithmetic over the ML-DSA ring
:math:`\\mathbb{Z}_q[X]/(X^{256}+1)` with :math:`q=8380417`.  All
operations use the complete Number-Theoretic Transform (NTT) with 8
layers for fast multiplication.

The main classes are:

    - :class:`Polynomial` -- a single polynomial in R_q
    - :class:`PolyVector`  -- a vector of polynomials (module element)

ML-DSA-specific operations include:

    - :meth:`Polynomial.infinity_norm` -- used in signature bound checks
    - :meth:`Polynomial.power2round` -- power-of-2 rounding for keygen
    - :meth:`Polynomial.decompose` -- coefficient decomposition for signing
    - :meth:`PolyVector.infinity_norm` -- vector infinity norm for checks

Key design decisions:

    - Coefficients are stored as **plain** integers in ``[0, q-1]``
      (NOT Montgomery form).  Montgomery conversions are handled
      internally by the NTT layer when required.
    - :meth:`Polynomial.__mul__` uses the complete NTT (8 layers),
      giving simple coefficient-wise multiplication in NTT domain.
    - The infinity norm uses centered representatives and is central
      to ML-DSA's rejection sampling and verification.

Example::

    >>> from qscg.ml_dsa.polynomial import Polynomial, PolyVector
    >>> a = Polynomial([i % 8380417 for i in range(256)])
    >>> b = Polynomial([(2*i) % 8380417 for i in range(256)])
    >>> c = a + b        # Polynomial addition
    >>> d = a * b        # NTT-based multiplication
    >>> norm = d.infinity_norm()
    >>> r1, r0 = a.power2round(13)

References:
    - NIST FIPS 204, Section 4 -- ML-DSA Internal Functions
    - CRYSTALS-Dilithium reference implementation (pq-crystals.org)
"""

from typing import List, Tuple, Optional

from . import ntt
from ..common.constants import MLDSA_Q, MLDSA_N
from ..common.utilities import center_reduce

Q: int = MLDSA_Q
"""Coefficient modulus :math:`q = 8380417`."""

N: int = MLDSA_N
"""Polynomial degree :math:`n = 256`."""

# Pre-computed constant for decomposition: 2*GAMMA2 must divide (Q-1)
# GAMMA2 values from MLDSA_PARAMS: 95 (Level 2), 112 (Levels 3/5)
_GAMMA2_VALUES: set[int] = {95, 112}
"""Valid gamma2 values for ML-DSA decomposition."""


def _make_positive(c: int) -> int:
    """Map a coefficient to the positive range ``[0, q-1]``.

    Args:
        c: Integer coefficient (may be negative).

    Returns:
        ``c mod q`` in ``[0, q-1]``.
    """
    return ((c % Q) + Q) % Q


class Polynomial:
    """A polynomial in :math:`R_q = \\mathbb{Z}_q[X]/(X^n+1)` for ML-DSA.

    Coefficients are stored as standard integers in ``[0, q-1]`` (NOT
    Montgomery form).  All NTT-domain conversions are handled
    transparently by :meth:`__mul__` and by the free functions in this
    module.

    Args:
        coeffs: List of coefficients.  Must have length ``N`` (256).
                Shorter lists are zero-padded; excess elements are
                truncated.  Each coefficient is reduced to ``[0, q-1]``.

    Attributes:
        coeffs (List[int]): Coefficient list of length ``N``.

    Example::

        >>> p = Polynomial([1, 2, 3] + [0]*253)
        >>> p.coeffs[0]
        1
        >>> zero = Polynomial.zero()
    """

    def __init__(self, coeffs: List[int]) -> None:
        self.coeffs: List[int] = [_make_positive(c) for c in coeffs[:N]]
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

        Converts both operands to NTT domain via the complete 8-layer
        NTT, multiplies pointwise (coefficient-wise product for the
        complete NTT), then inverse-NTTs back.  This is the fast
        :math:`O(n \\log n)` multiplication required by ML-DSA.

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

    def infinity_norm(self) -> int:
        """Infinity norm: :math:`\\max_i |\\text{center_reduce}(c_i)|`.

        Maps each coefficient to the centered range ``[-Q/2, Q/2]``
        and returns the maximum absolute value.  This is the critical
        quantity used in ML-DSA's rejection sampling and verification
        bounds.

        Returns:
            Maximum absolute value of centred coefficients.
        """
        centered = [c if c <= Q // 2 else c - Q for c in self.coeffs]
        return max(abs(c) for c in centered)

    def center(self) -> List[int]:
        """Center coefficients to the symmetric range ``[-Q/2, Q/2]``.

        Returns:
            List of 256 integers in ``[-Q//2, Q//2]``.
        """
        return [center_reduce(c, Q) for c in self.coeffs]

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

    def power2round(self, d: int) -> Tuple["Polynomial", "Polynomial"]:
        """Power-of-2 rounding: decompose each coefficient into high and low bits.

        For each coefficient :math:`c`, compute:

        .. math::

            r_1 = \\left\\lfloor \\frac{c}{2^d} \\right\\rfloor \\bmod q,
            \\quad
            r_0 = c - r_1 \\cdot 2^d  \\in [-2^{d-1}, 2^{d-1}]

        This is used in ML-DSA key generation to produce the public
        key :math:`t_1` from :math:`t = As + e`.

        Args:
            d: Number of low bits to discard (``d=13`` for ML-DSA).

        Returns:
            Tuple ``(r1, r0)`` where *r1* contains the high bits and
            *r0* contains the low bits.

        Raises:
            ValueError: If *d* is not positive.
        """
        if d <= 0:
            raise ValueError(f"d must be positive, got {d}")
        half = 1 << (d - 1)
        r1_coeffs: List[int] = []
        r0_coeffs: List[int] = []
        for c in self.coeffs:
            r = c % Q
            r0 = center_reduce(r, 1 << d)
            if r0 < 0:
                r0 += (1 << d)
            r1 = (r - r0) >> d
            r1_coeffs.append(r1 % Q)
            r0_coeffs.append(center_reduce(r0, 1 << d))
        return Polynomial(r1_coeffs), Polynomial(r0_coeffs)

    def decompose(
        self, gamma2: int
    ) -> Tuple["Polynomial", "Polynomial"]:
        """Decompose each coefficient into high and low parts for signing.

        For each coefficient :math:`c`, compute:

        .. math::

            r_0 = c \\bmod^± (2\\gamma_2), \\quad
            r_1 = \\left( c - r_0 \\right) / (2\\gamma_2)

        This is the ``Decompose`` algorithm from FIPS 204, Algorithm 7,
        used during signature generation to produce the hint polynomial.

        Args:
            gamma2: The decomposition parameter (``95`` for Level 2,
                    ``112`` for Levels 3 and 5).

        Returns:
            Tuple ``(r1, r0)`` of :class:`Polynomial` instances.

        Raises:
            ValueError: If *gamma2* is not a valid ML-DSA parameter.
        """
        if gamma2 not in _GAMMA2_VALUES:
            raise ValueError(
                f"Invalid gamma2={gamma2}; must be one of {_GAMMA2_VALUES}"
            )
        two_gamma = 2 * gamma2
        r1_coeffs: List[int] = []
        r0_coeffs: List[int] = []
        for c in self.coeffs:
            r = c % Q
            r0 = center_reduce(r, two_gamma)
            # Adjust r0 to be in [0, 2*gamma2) for the division
            r0_pos = r0 if r0 >= 0 else r0 + two_gamma
            r1 = (r - r0_pos) // two_gamma
            r1_coeffs.append(r1 % Q)
            r0_coeffs.append(r0)
        return Polynomial(r1_coeffs), Polynomial(r0_coeffs)

    def make_hint(
        self, other: "Polynomial", gamma2: int
    ) -> "Polynomial":
        """Create a hint polynomial for compressed signatures.

        The hint indicates which coefficients of ``self + other`` would
        round differently from ``self`` alone during decompositon with
        parameter *gamma2*.

        Args:
            other: Challenge polynomial (typically :math:`c \\cdot s_1`).
            gamma2: Decomposition parameter.

        Returns:
            Hint polynomial with coefficients in ``{0, 1}``.
        """
        w = self + other
        r1_w, r0_w = w.decompose(gamma2)
        r1_s, _ = self.decompose(gamma2)
        hint_coeffs = [
            1 if c1 != c2 else 0
            for c1, c2 in zip(r1_w.coeffs, r1_s.coeffs)
        ]
        return Polynomial(hint_coeffs)

    def use_hint(self, hint: "Polynomial", gamma2: int) -> "Polynomial":
        """Apply a hint polynomial to recover a rounded value.

        Uses the hint bits produced by :meth:`make_hint` to adjust
        the decomposition result, recovering the correctly rounded
        high bits.

        Args:
            hint: Hint polynomial (coefficients in ``{0, 1}``).
            gamma2: Decomposition parameter.

        Returns:
            Corrected high-bit polynomial.
        """
        r1, r0 = self.decompose(gamma2)
        corrected = []
        two_gamma = 2 * gamma2
        for i in range(N):
            h = hint.coeffs[i] % 2
            if h == 1:
                # Adjust r1 based on the sign of r0
                r0_c = center_reduce(r0.coeffs[i], two_gamma)
                if r0_c > 0:
                    corrected.append((r1.coeffs[i] + 1) % Q)
                else:
                    corrected.append((r1.coeffs[i] - 1) % Q)
            else:
                corrected.append(r1.coeffs[i])
        return Polynomial(corrected)

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

        Useful for unit-testing multiplication.

        Args:
            idx: Degree of the monomial (0 <= idx < N).

        Returns:
            Polynomial with a single ``1`` at position *idx*.
        """
        coeffs = [0] * N
        coeffs[idx % N] = 1
        return cls(coeffs)


class PolyVector:
    """Vector of polynomials over :math:`R_q` for ML-DSA.

    In ML-DSA, vectors of dimension :math:`k` (rows) and :math:`l`
    (columns) are used, where the exact dimensions depend on the
    security level:

        - Level 2 (ML-DSA-44):  :math:`k=4,  l=4`
        - Level 3 (ML-DSA-65):  :math:`k=6,  l=5`
        - Level 5 (ML-DSA-87):  :math:`k=8,  l=7`

    Args:
        polys: List of :class:`Polynomial` instances.

    Attributes:
        polys (List[Polynomial]): The list of polynomials.

    Example::

        >>> v = PolyVector([Polynomial.zero() for _ in range(4)])
        >>> w = PolyVector([Polynomial.random() for _ in range(4)])
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
            Vector dimension.
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
        """Infinity norm of the vector.

        Returns the maximum :meth:`Polynomial.infinity_norm` across all
        component polynomials.  This is the critical bound checked
        during ML-DSA signature verification.

        Returns:
            Maximum infinity norm of any component polynomial.
        """
        return max(p.infinity_norm() for p in self.polys)

    def center(self) -> List[List[int]]:
        """Center all polynomial coefficients.

        Returns:
            List of centered coefficient lists (one per polynomial).
        """
        return [p.center() for p in self.polys]

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
    def zero(cls, dim: int) -> "PolyVector":
        """Create a zero vector of given dimension.

        Args:
            dim: Number of polynomials.

        Returns:
            Zero vector of length *dim*.
        """
        return cls([Polynomial.zero() for _ in range(dim)])

    @classmethod
    def random(cls, dim: int) -> "PolyVector":
        """Generate a uniformly random vector of given dimension.

        Args:
            dim: Number of polynomials.

        Returns:
            Random vector of length *dim*.
        """
        return cls([Polynomial.random() for _ in range(dim)])

    def power2round(self, d: int) -> Tuple["PolyVector", "PolyVector"]:
        """Apply :meth:`Polynomial.power2round` to every component.

        Args:
            d: Number of low bits to discard.

        Returns:
            Tuple ``(r1_vec, r0_vec)`` of high-bit and low-bit vectors.
        """
        r1_polys = []
        r0_polys = []
        for p in self.polys:
            r1, r0 = p.power2round(d)
            r1_polys.append(r1)
            r0_polys.append(r0)
        return PolyVector(r1_polys), PolyVector(r0_polys)

    def decompose(
        self, gamma2: int
    ) -> Tuple["PolyVector", "PolyVector"]:
        """Apply :meth:`Polynomial.decompose` to every component.

        Args:
            gamma2: Decomposition parameter.

        Returns:
            Tuple ``(r1_vec, r0_vec)`` of decomposed vectors.
        """
        r1_polys = []
        r0_polys = []
        for p in self.polys:
            r1, r0 = p.decompose(gamma2)
            r1_polys.append(r1)
            r0_polys.append(r0)
        return PolyVector(r1_polys), PolyVector(r0_polys)


def mat_vec_mul(
    A_hat: List[List[Polynomial]], v_hat: PolyVector
) -> PolyVector:
    """Matrix-vector multiplication in the **NTT domain**.

    Computes :math:`\\hat{A} \\cdot \\hat{v}` where both the matrix
    and the vector are in NTT-domain representation.  This is the
    core module multiplication used in ML-DSA key generation and
    signature operations.

    For ML-DSA, :math:`\\hat{A}` is a :math:`k \\times l` matrix and
    :math:`\\hat{v}` is a length-:math:`l` vector.

    Args:
        A_hat: Matrix of NTT-domain polynomials (list of :math:`k`
               rows, each containing :math:`l` polynomials).
        v_hat: Vector of :math:`l` NTT-domain polynomials.

    Returns:
        Result vector of :math:`k` NTT-domain polynomials.

    Raises:
        ValueError: If dimensions are inconsistent.

    Example::

        >>> k, l = 4, 4
        >>> A = [[Polynomial.random() for _ in range(l)] for _ in range(k)]
        >>> v = PolyVector.random(l)
        >>> result = mat_vec_mul(A, v)
        >>> len(result) == k
        True
    """
    k = len(A_hat)
    if k == 0:
        raise ValueError("Empty matrix")
    l = len(A_hat[0]) if k > 0 else 0
    if len(v_hat) != l:
        raise ValueError(
            f"Matrix has {l} columns but vector has length {len(v_hat)}"
        )

    result: List[Polynomial] = []
    for i in range(k):
        acc = Polynomial.zero()
        for j in range(l):
            a_ntt = A_hat[i][j].to_ntt()
            v_ntt = v_hat[j].to_ntt()
            prod_ntt = ntt.ntt_multiply(a_ntt, v_ntt)
            prod = Polynomial.from_ntt(prod_ntt)
            acc = acc + prod
        result.append(acc)
    return PolyVector(result)


def transpose_mat_vec_mul(
    A_hat: List[List[Polynomial]], u_hat: PolyVector
) -> PolyVector:
    """Matrix^T-vector multiplication in the **NTT domain**.

    Computes :math:`\\hat{A}^T \\cdot \\hat{u}` where :math:`\\hat{A}`
    is a :math:`k \\times l` matrix and :math:`\\hat{u}` is a length-
    :math:`k` vector.

    Args:
        A_hat: :math:`k \\times l` matrix of NTT-domain polynomials.
        u_hat: Vector of :math:`k` NTT-domain polynomials.

    Returns:
        Result vector of :math:`l` NTT-domain polynomials.

    Raises:
        ValueError: If dimensions are inconsistent.
    """
    k = len(A_hat)
    if k == 0:
        raise ValueError("Empty matrix")
    l = len(A_hat[0])
    if len(u_hat) != k:
        raise ValueError(
            f"Matrix has {k} rows but vector has length {len(u_hat)}"
        )

    result: List[Polynomial] = []
    for j in range(l):
        acc = Polynomial.zero()
        for i in range(k):
            a_ntt = A_hat[i][j].to_ntt()
            u_ntt = u_hat[i].to_ntt()
            prod_ntt = ntt.ntt_multiply(a_ntt, u_ntt)
            prod = Polynomial.from_ntt(prod_ntt)
            acc = acc + prod
        result.append(acc)
    return PolyVector(result)


def vec_vec_dot(
    u_hat: PolyVector, v_hat: PolyVector
) -> Polynomial:
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
