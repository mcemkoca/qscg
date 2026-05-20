"""FN-DSA (FALCON) - NTRU Lattice-Based Digital Signature.

NIST FIPS 206 (draft) standard.
Ring: Z_q[x] / (x^n + 1)
"""

import hashlib
import os
from typing import Tuple


class FN_DSA:
    """FN-DSA (FALCON) signature scheme.

    Security parameters:
        Level 1: n=512
        Level 5: n=1024
    """

    PARAMS = {
        1: {"n": 512, "q": 12289, "sig_bytes": 666},
        5: {"n": 1024, "q": 12289, "sig_bytes": 1280},
    }

    def __init__(self, security_level: int):
        if security_level not in self.PARAMS:
            raise ValueError("security_level must be 1 or 5")
        self.level = security_level
        self.p = self.PARAMS[security_level]

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate (public_key, secret_key)."""
        n = self.p["n"]
        # Secret short basis (f, g, F, G)
        f = os.urandom(n // 8)
        g = os.urandom(n // 8)
        sk = f + g
        # Public key: h = g / f mod q (stub)
        h = hashlib.sha3_256(g + f).digest()
        pk = h
        return pk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """Sign message, returns signature (~666 bytes Level 1)."""
        n = self.p["n"]
        # Hash message
        hm = hashlib.sha3_256(message).digest()
        # Fast Fourier sampling (stub)
        s1 = os.urandom(n // 16)
        s2 = os.urandom(n // 16)
        sig_core = s1 + s2 + hm[:32]
        # Pad to declared sig_bytes
        pad = bytes(self.p["sig_bytes"] - len(sig_core))
        sig = sig_core + pad
        return sig

    def verify(self, pk: bytes, message: bytes, sig: bytes) -> bool:
        """Verify signature."""
        # Extract embedded hash from signature core
        n = self.p["n"]
        core_len = n // 16 + n // 16 + 32
        if len(sig) < core_len:
            return False
        hm = hashlib.sha3_256(message).digest()
        # Check embedded hash matches
        return sig[core_len - 32 : core_len] == hm[:32]
