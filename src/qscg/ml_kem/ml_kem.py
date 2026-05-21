"""ML-KEM: Module-Lattice-Based Key Encapsulation Mechanism (FIPS 203, Section 5.2).

Implements the IND-CCA2 secure KEM using the Fujisaki--Okamoto (FO)
transform applied to the underlying K-PKE scheme from
:mod:`qscg.ml_kem.k_pke`.

This module provides:

  * :class:`MLKEM` — the main KEM class with :meth:`~MLKEM.KeyGen`,
    :meth:`~MLKEM.Encaps`, and :meth:`~MLKEM.Decaps`.
  * :func:`_constant_time_compare` — constant-time byte comparison.

Supported parameter sets::

    +-----------+----------------+------+-------+-------+-----+-----+
    | Level     | Name           | k    | eta1  | eta2  | du  | dv  |
    +===========+================+======+=======+=======+=====+=====+
    | LEVEL_1   | ML-KEM-512     | 2    | 3     | 2     | 10  | 4   |
    +-----------+----------------+------+-------+-------+-----+-----+
    | LEVEL_3   | ML-KEM-768     | 3    | 2     | 2     | 10  | 4   |
    +-----------+----------------+------+-------+-------+-----+-----+
    | LEVEL_5   | ML-KEM-1024    | 4    | 2     | 2     | 11  | 5   |
    +-----------+----------------+------+-------+-------+-----+-----+

Example::

    >>> from qscg.ml_kem.ml_kem import MLKEM
    >>> from qscg.common.constants import SecurityLevel
    >>> kem = MLKEM(SecurityLevel.LEVEL_3)
    >>> ek, dk = kem.KeyGen()
    >>> c, K = kem.Encaps(ek)
    >>> K_prime = kem.Decaps(dk, c)
    >>> K == K_prime
    True

References:
    - NIST FIPS 203, Section 5.2 — ML-KEM
    - NIST FIPS 203, Section 6 — The Fujisaki-Okamoto Transform
"""

from typing import Tuple

from ..common.constants import SecurityLevel, MLKEM_PARAMS, MLKEM_N
from ..common.hashing import G, H, J
from ..common.utilities import generate_random_bytes
from . import k_pke

N: int = MLKEM_N
"""Polynomial degree :math:`n = 256`."""

# ByteEncode with d=12 produces 384 bytes per polynomial.
_BYTES_PER_POLY_12: int = (N * 12 + 7) // 8  # 384


# ============================================================================
# Constant-time helper
# ============================================================================


def _constant_time_compare(a: bytes, b: bytes) -> bool:
    """Constant-time byte-string comparison.

    Computes the bitwise-XOR of every byte pair and ORs the results
    together.  The running time depends only on the length of the
    inputs, not on their contents, preventing timing side-channels.

    Args:
        a: First byte string.
        b: Second byte string.

    Returns:
        ``True`` if *a* and *b* have identical length and content,
        ``False`` otherwise.
    """
    if len(a) != len(b):
        return False
    result: int = 0
    for x, y in zip(a, b):
        result |= x ^ y
    return result == 0


# ============================================================================
# ML-KEM class
# ============================================================================


class MLKEM:
    """ML-KEM key encapsulation mechanism.

    Implements ML-KEM-512 (Level 1), ML-KEM-768 (Level 3), and
    ML-KEM-1024 (Level 5) following NIST FIPS 203.

    Each instance is pinned to a single :class:`SecurityLevel`;
    key-generation, encapsulation, and decapsulation must all use the
    same parameter set.

    Args:
        level: Desired security level.  Defaults to
            :attr:`SecurityLevel.LEVEL_3` (ML-KEM-768).

    Attributes:
        level (:class:`~qscg.common.constants.SecurityLevel`): The
            security level / parameter set in use.
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> None:
        self.level: SecurityLevel = level
        self._params = MLKEM_PARAMS[level]
        self._k: int = self._params["k"]

    # ------------------------------------------------------------------
    # Key-length helpers (derived from the parameter set)
    # ------------------------------------------------------------------

    @property
    def _dk_pke_len(self) -> int:
        """Length of the K-PKE decryption key: ``384*k`` bytes."""
        return self._k * _BYTES_PER_POLY_12

    @property
    def _ek_len(self) -> int:
        """Length of the K-PKE / KEM encryption key: ``384*k + 32`` bytes."""
        return self._k * _BYTES_PER_POLY_12 + 32

    @property
    def _dk_total_len(self) -> int:
        """Total KEM decryption-key length: ``768*k + 96`` bytes.

        Breakdown::

            dk = dk_pke (384k) || ek (384k+32) || H(ek) (32) || z (32)
               = 768k + 96
        """
        return 2 * self._k * _BYTES_PER_POLY_12 + 96

    @property
    def _c1_len(self) -> int:
        """Length of the first ciphertext component: ``32*du*k`` bytes."""
        du: int = self._params["du"]
        return 32 * du * self._k

    @property
    def _c2_len(self) -> int:
        """Length of the second ciphertext component: ``32*dv`` bytes."""
        dv: int = self._params["dv"]
        return 32 * dv

    # =================================================================
    # ML-KEM.KeyGen (FIPS 203, Algorithm 15)
    # =================================================================

    def KeyGen(self) -> Tuple[bytes, bytes]:
        """Generate a KEM key pair.

        Algorithm 15 from FIPS 203::

            1. d  = randombytes(32)
            2. z  = randombytes(32)
            3. (ek_pke, dk_pke) = K-PKE.KeyGen(d)
            4. ek = ek_pke
            5. dk = dk_pke || ek || H(ek) || z

        Returns:
            Tuple ``(ek, dk)`` where:

              - ``ek`` is the encapsulation key (``384*k + 32`` bytes).
              - ``dk`` is the decapsulation key (``768*k + 96`` bytes).
        """
        d: bytes = generate_random_bytes(32)
        z: bytes = generate_random_bytes(32)

        # Step 3: Run K-PKE key generation
        ek_pke: bytes
        dk_pke: bytes
        ek_pke, dk_pke = k_pke.K_PKE_KeyGen(d, self.level)

        # Steps 4 & 5: Assemble KEM keys
        ek: bytes = ek_pke
        dk: bytes = dk_pke + ek + H(ek) + z

        return ek, dk

    # =================================================================
    # ML-KEM.Encaps (FIPS 203, Algorithm 16)
    # =================================================================

    def Encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate: generate a shared secret and ciphertext.

        Algorithm 16 from FIPS 203::

            1. m      = randombytes(32)
            2. (K,r)  = G(m || H(ek))
            3. c      = K-PKE.Encrypt(ek, m, r)
            4. K      = KDF(K || H(c))          # KDF = SHAKE-256 via J()

        Returns:
            Tuple ``(c, K)`` where:

              - ``c`` is the ciphertext.
              - ``K`` is the 32-byte shared secret.

        Raises:
            ValueError: If *ek* has an unexpected length for this level.
        """
        if len(ek) != self._ek_len:
            raise ValueError(
                f"MLKEM.Encaps: ek length mismatch for {self.level.name}: "
                f"expected {self._ek_len}, got {len(ek)}"
            )

        # Step 1: Fresh random message
        m: bytes = generate_random_bytes(32)

        # Step 2: Derive encryption randomness and pre-key
        g_input: bytes = m + H(ek)
        g_out: bytes = G(g_input)
        K_bar: bytes = g_out[:32]
        r: bytes = g_out[32:64]

        # Step 3: Encrypt under K-PKE
        c: bytes = k_pke.K_PKE_Encrypt(ek, m, r, self.level)

        # Step 4: Derive shared secret
        kdf_input: bytes = K_bar + H(c)
        K: bytes = J(kdf_input, 32)

        return c, K

    # =================================================================
    # ML-KEM.Decaps (FIPS 203, Algorithm 17)
    # =================================================================

    def Decaps(self, dk: bytes, c: bytes) -> bytes:
        """Decapsulate: recover the shared secret from a ciphertext.

        Algorithm 17 from FIPS 203 (with implicit rejection)::

            1. Parse dk  →  dk_pke || ek || h || z
            2. m' = K-PKE.Decrypt(dk_pke, c)
            3. (K_bar', r') = G(m' || h)
            4. c' = K-PKE.Encrypt(ek, m', r')
            5. If c == c' (constant-time compare):
                   K = KDF(K_bar' || H(c))
               Else:                       # implicit rejection
                   K = KDF(z || H(c))

        The *implicit rejection* branch (step 5 ``else``) is what provides
        CCA2 security: a malformed ciphertext yields a pseudorandom key
        that is independent of the actual secret.

        Args:
            dk: Decapsulation key (``768*k + 96`` bytes).
            c: Ciphertext.

        Returns:
            32-byte shared secret.

        Raises:
            ValueError: If *dk* has an unexpected length for this level.
        """
        if len(dk) != self._dk_total_len:
            raise ValueError(
                f"MLKEM.Decaps: dk length mismatch for {self.level.name}: "
                f"expected {self._dk_total_len}, got {len(dk)}"
            )

        # ------------------------------------------------------------------
        # Step 1: Parse dk = dk_pke || ek || h || z
        # ------------------------------------------------------------------
        dk_pke: bytes = dk[: self._dk_pke_len]
        ek: bytes = dk[self._dk_pke_len : self._dk_pke_len + self._ek_len]
        h: bytes = dk[
            self._dk_pke_len + self._ek_len : self._dk_pke_len + self._ek_len + 32
        ]
        z: bytes = dk[self._dk_pke_len + self._ek_len + 32 :]

        # ------------------------------------------------------------------
        # Step 2: Decrypt the ciphertext
        # ------------------------------------------------------------------
        m_prime: bytes = k_pke.K_PKE_Decrypt(dk_pke, c, self.level)

        # ------------------------------------------------------------------
        # Step 3: Re-derive encryption randomness
        # ------------------------------------------------------------------
        g_input: bytes = m_prime + h
        g_out: bytes = G(g_input)
        K_bar_prime: bytes = g_out[:32]
        r_prime: bytes = g_out[32:64]

        # ------------------------------------------------------------------
        # Step 4: Re-encrypt to obtain c'
        # ------------------------------------------------------------------
        c_prime: bytes = k_pke.K_PKE_Encrypt(ek, m_prime, r_prime, self.level)

        # ------------------------------------------------------------------
        # Step 5: Constant-time equality test + implicit rejection
        # ------------------------------------------------------------------
        equal: bool = _constant_time_compare(c, c_prime)

        if equal:
            kdf_input: bytes = K_bar_prime + H(c)
        else:
            kdf_input = z + H(c)

        K: bytes = J(kdf_input, 32)
        return K


# =============================================================================
# Module-level convenience functions (stateless API)
# =============================================================================


def _create_kem(level: SecurityLevel) -> MLKEM:
    """Factory helper: instantiate :class:`MLKEM` for a given level."""
    return MLKEM(level)


def MLKEM_KeyGen(level: SecurityLevel = SecurityLevel.LEVEL_3) -> Tuple[bytes, bytes]:
    """Stateless wrapper for :meth:`MLKEM.KeyGen`.

    Args:
        level: Security level.  Defaults to LEVEL_3 (ML-KEM-768).

    Returns:
        ``(ek, dk)`` key pair.
    """
    kem = _create_kem(level)
    return kem.KeyGen()


def MLKEM_Encaps(
    ek: bytes, level: SecurityLevel = SecurityLevel.LEVEL_3
) -> Tuple[bytes, bytes]:
    """Stateless wrapper for :meth:`MLKEM.Encaps`.

    Args:
        ek: Encapsulation key.
        level: Security level that was used during key generation.

    Returns:
        ``(c, K)`` — ciphertext and shared secret.
    """
    kem = _create_kem(level)
    return kem.Encaps(ek)


def MLKEM_Decaps(
    dk: bytes, c: bytes, level: SecurityLevel = SecurityLevel.LEVEL_3
) -> bytes:
    """Stateless wrapper for :meth:`MLKEM.Decaps`.

    Args:
        dk: Decapsulation key.
        c: Ciphertext.
        level: Security level that was used during key generation.

    Returns:
        32-byte shared secret.
    """
    kem = _create_kem(level)
    return kem.Decaps(dk, c)
