"""ML-DSA (FIPS 204) implementation package.

Sub-modules
-----------
ntt.py:
    Complete 8-layer NTT for ML-DSA modulus q = 8380417.
encode.py:
    Bit-packing routines for keys and signatures.
polynomial.py:
    Polynomial ring arithmetic and vector operations.
sampling.py:
    ExpandA, ExpandS, SampleInBall, and masking vector sampling.
ml_dsa.py:
    Main ML-DSA class with KeyGen, Sign, and Verify.

Typical usage::

    >>> from qscg.ml_dsa.ml_dsa import MLDSA
    >>> from qscg.common.constants import SecurityLevel
    >>> dsa = MLDSA(SecurityLevel.LEVEL_3)
    >>> pk, sk = dsa.keygen()
    >>> sig = dsa.sign(sk, b"Quantum-safe message")
    >>> assert dsa.verify(pk, b"Quantum-safe message", sig)
"""

from .ml_dsa import MLDSA

__all__ = [
    "ntt",
    "polynomial",
    "sampling",
    "encode",
    "ml_dsa",
    "MLDSA",
]
