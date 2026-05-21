"""ML-KEM (FIPS 203) implementation package.

Sub-modules
-----------
ntt.py:
    Number-Theoretic Transform (incomplete 7-layer NTT).
polynomial.py:
    Polynomial ring arithmetic and vector/matrix operations.
sampling.py:
    CBD, SampleNTT, Parse, and matrix/vector sampling.
encode.py:
    ByteEncode/ByteDecode and Compress/Decompress.
k_pke.py:
    K-PKE component (KeyGen, Encrypt, Decrypt).
ml_kem.py:
    IND-CCA2 ML-KEM via Fujisaki-Okamoto (KeyGen, Encaps, Decaps).

Typical usage::

    >>> from qscg.ml_kem.ml_kem import MLKEM
    >>> from qscg.common.constants import SecurityLevel
    >>> kem = MLKEM(SecurityLevel.LEVEL_3)
    >>> ek, dk = kem.KeyGen()
    >>> c, K = kem.Encaps(ek)
    >>> K_prime = kem.Decaps(dk, c)
    >>> assert K == K_prime
"""

from .k_pke import K_PKE_KeyGen, K_PKE_Encrypt, K_PKE_Decrypt
from .ml_kem import MLKEM, MLKEM_KeyGen, MLKEM_Encaps, MLKEM_Decaps

__all__ = [
    "ntt",
    "polynomial",
    "sampling",
    "encode",
    "k_pke",
    "ml_kem",
    # K-PKE functions
    "K_PKE_KeyGen",
    "K_PKE_Encrypt",
    "K_PKE_Decrypt",
    # ML-KEM class and helpers
    "MLKEM",
    "MLKEM_KeyGen",
    "MLKEM_Encaps",
    "MLKEM_Decaps",
]
