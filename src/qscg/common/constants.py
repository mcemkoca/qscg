"""Common constants for QSCG post-quantum cryptography library.

This module defines shared constants used across ML-KEM (FIPS 203),
ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) implementations.
"""

from enum import Enum

# ---------------------------------------------------------------------------
# ML-KEM constants (FIPS 203)
# ---------------------------------------------------------------------------


class SecurityLevel(Enum):
    """ML-KEM security levels per FIPS 203.

    Members:
        LEVEL_1: ML-KEM-512 (NIST security category 1).
        LEVEL_3: ML-KEM-768 (NIST security category 3).
        LEVEL_5: ML-KEM-1024 (NIST security category 5).
    """

    LEVEL_1 = 512
    """ML-KEM-512 — security category 1."""

    LEVEL_3 = 768
    """ML-KEM-768 — security category 3."""

    LEVEL_5 = 1024
    """ML-KEM-1024 — security category 5."""


#: Parameter lookup table indexed by :class:`SecurityLevel`.
#: Each entry contains ``k``, ``eta1``, ``eta2``, ``du``, ``dv``.
MLKEM_PARAMS = {
    SecurityLevel.LEVEL_1: {"k": 2, "eta1": 3, "eta2": 2, "du": 10, "dv": 4},
    SecurityLevel.LEVEL_3: {"k": 3, "eta1": 2, "eta2": 2, "du": 10, "dv": 4},
    SecurityLevel.LEVEL_5: {"k": 4, "eta1": 2, "eta2": 2, "du": 11, "dv": 5},
}
"""ML-KEM parameter sets (FIPS 203, Table 2)."""

MLKEM_Q: int = 3329
"""Modulus for ML-KEM ring operations: q = 3329."""

MLKEM_N: int = 256
"""Degree of the polynomial ring: n = 256."""

MLKEM_ETA1: dict = {512: 3, 768: 2, 1024: 2}
"""ETA1 parameter for ML-KEM parameter sets."""

MLKEM_ETA2: int = 2
"""ETA2 parameter (shared across all ML-KEM parameter sets)."""

MLKEM_DU: dict = {512: 10, 768: 10, 1024: 11}
"""DU (compression bits for u vector) per parameter set."""

MLKEM_DV: dict = {512: 4, 768: 4, 1024: 5}
"""DV (compression bits for v scalar) per parameter set."""

# ---------------------------------------------------------------------------
# ML-DSA constants (FIPS 204)
# ---------------------------------------------------------------------------

MLDSA_Q: int = 8380417
"""Modulus for ML-DSA: q = 2^23 - 2^13 + 1 = 8380417."""

MLDSA_N: int = 256
"""Degree of the polynomial ring: n = 256."""

MLDSA_D: int = 13
"""Number of bits dropped in power-of-two rounding: d = 13."""

MLDSA_TAU: dict = {44: 39, 65: 49, 87: 60}
"""Number of +/-1s in challenge polynomial c for each parameter set."""

MLDSA_GAMMA1: dict = {44: 2**17, 65: 2**19, 87: 2**19}
"""Coefficient range for mask vectors y."""

MLDSA_GAMMA2: dict = {44: 95232, 65: 261888, 87: 261888}
"""Low-order rounding range. gamma2 = (q - 1) / 88 for ML-DSA-44,
(q - 1) / 32 for ML-DSA-65/87."""

MLDSA_BETA: dict = {44: 78, 65: 196, 87: 120}
"""Hint bound: beta = tau * eta."""

MLDSA_OMEGA: dict = {44: 80, 65: 80, 87: 128}
"""Max number of 1s in the hint polynomial."""

# Combined parameter sets for ML-DSA (indexed by SecurityLevel)
MLDSA_PARAMS: dict = {
    SecurityLevel.LEVEL_1: {
        "param_id": 44,
        "tau": 39,
        "gamma1": 2**17,
        "gamma2": 95232,
        "k": 4,
        "l": 4,
        "eta": 2,
        "beta": 78,
        "omega": 80,
        "d": 13,
    },
    SecurityLevel.LEVEL_3: {
        "param_id": 65,
        "tau": 49,
        "gamma1": 2**19,
        "gamma2": 261888,
        "k": 6,
        "l": 5,
        "eta": 4,
        "beta": 196,
        "omega": 80,
        "d": 13,
    },
    SecurityLevel.LEVEL_5: {
        "param_id": 87,
        "tau": 60,
        "gamma1": 2**19,
        "gamma2": 261888,
        "k": 8,
        "l": 7,
        "eta": 2,
        "beta": 120,
        "omega": 128,
        "d": 13,
    },
}
"""Complete ML-DSA parameter sets indexed by SecurityLevel."""

# ---------------------------------------------------------------------------
# SLH-DSA constants (FIPS 205)
# ---------------------------------------------------------------------------

SLHDSA_N: int = 16
"""Security parameter: length of hash function outputs (in bytes)."""

SLHDSA_H: int = 66
"""Height of the hypertree (for SPHINCS+ SHA2-128f)."""

SLHDSA_D: int = 22
"""Number of layers in the hypertree."""

SLHDSA_A: int = 6
"""FORS tree parameter: number of trees."""

SLHDSA_K: int = 33
"""FORS tree parameter: number of FORS trees."""

SLHDSA_W: int = 16
"""Winternitz parameter (Winternitz chain length)."""

SLHDSA_LEN1: int = 32
"""Number of message digest bits split into base-w digits."""

SLHDSA_LEN2: int = 3
"""Number of checksum digits in WOTS+."""

SLHDSA_LEN: int = SLHDSA_LEN1 + SLHDSA_LEN2
"""Total number of WOTS+ chains."""


# SLH-DSA parameter sets indexed by SecurityLevel (FIPS 205).
# Using SHA2 'f' (fast) variants: larger signatures, faster signing.
SLHDSA_PARAMS = {
    SecurityLevel.LEVEL_1: {
        "n": 16,      # Security parameter (hash output length)
        "h": 66,      # Hypertree height
        "d": 22,      # Number of hypertree layers
        "a": 6,       # FORS tree height
        "k": 33,      # Number of FORS trees
        "w": 16,      # Winternitz parameter
        "len1": 32,   # WOTS+ message digits
        "len2": 3,    # WOTS+ checksum digits
        "len": 35,    # Total WOTS+ chains (len1 + len2)
    },
    SecurityLevel.LEVEL_3: {
        "n": 24,
        "h": 66,
        "d": 22,
        "a": 8,
        "k": 33,
        "w": 16,
        "len1": 48,
        "len2": 3,
        "len": 51,
    },
    SecurityLevel.LEVEL_5: {
        "n": 32,
        "h": 68,
        "d": 17,
        "a": 9,
        "k": 35,
        "w": 16,
        "len1": 64,
        "len2": 3,
        "len": 67,
    },
}
"""SLH-DSA parameter sets (FIPS 205, Table 1) — SHA2 'f' (fast) variants."""
