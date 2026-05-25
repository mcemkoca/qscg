"""SLH-DSA: Stateless Hash-Based Digital Signature Algorithm (FIPS 205).

Sub-modules:
    slh_dsa   -- Main SLHDSA class (keygen, sign, verify)
    wots      -- WOTS+ one-time signatures
    fors      -- FORS few-time signatures
    xmss      -- XMSS Merkle trees
    hypertree -- Multi-layer hypertree
    address   -- ADRS 32-byte address structure

Example:
    >>> from qscg.slh_dsa import SLHDSA
    >>> from qscg.common.constants import SecurityLevel
    >>> slh = SLHDSA(SecurityLevel.LEVEL_1)
    >>> pk, sk = slh.keygen()
    >>> sig = slh.sign(b"Hello", sk)
    >>> assert slh.verify(b"Hello", sig, pk)
"""

from .slh_dsa import SLHDSA
from .address import ADRS

__all__ = [
    "SLHDSA",
    "ADRS",
]
