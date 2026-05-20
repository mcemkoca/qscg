"""Common constants for QSCG post-quantum cryptography library.

This module defines shared constants used across ML-KEM (FIPS 203),
ML-DSA (FIPS 204), and SLH-DSA (FIPS 205) implementations.
"""

# ---------------------------------------------------------------------------
# ML-KEM constants (FIPS 203)
# ---------------------------------------------------------------------------

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
