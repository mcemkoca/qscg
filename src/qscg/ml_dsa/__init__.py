"""ML-DSA (Module-Lattice-Based Digital Signature Algorithm).

This package implements the NIST FIPS 204 ML-DSA scheme with three
parameter sets:

    - ML-DSA-44 — NIST security category 2 (``LEVEL_1``)
    - ML-DSA-65 — NIST security category 3 (``LEVEL_3``)
    - ML-DSA-87 — NIST security category 5 (``LEVEL_5``)

The public API is provided by :class:`.ml_dsa.MLDSA`, which wraps
key generation, signing, and verification in a single object.

Example::

    >>> from qscg.ml_dsa import MLDSA
    >>> from qscg.common.constants import SecurityLevel
    >>> mldsa = MLDSA(SecurityLevel.LEVEL_3)
    >>> pk, sk = mldsa.keygen()
    >>> msg = b"Hello, post-quantum world!"
    >>> sig = mldsa.sign(sk, msg)
    >>> assert mldsa.verify(pk, msg, sig)

Low-level functions and classes are also exported for advanced use.
"""

from .encode import BitPack, HintBitPack, SimpleBitPack
from .ml_dsa import MLDSA, MLDSA_KeyGen, MLDSA_Sign, MLDSA_Verify
from .polynomial import Polynomial, PolyVector
from .sampling import ExpandA, ExpandMask, ExpandS, SampleInBall

__all__ = [
    # High-level interface
    "MLDSA",
    # Low-level algorithms
    "MLDSA_KeyGen",
    "MLDSA_Sign",
    "MLDSA_Verify",
    # Polynomial arithmetic
    "Polynomial",
    "PolyVector",
    # Sampling primitives
    "SampleInBall",
    "ExpandA",
    "ExpandS",
    "ExpandMask",
    # Encoding
    "SimpleBitPack",
    "BitPack",
    "HintBitPack",
]
