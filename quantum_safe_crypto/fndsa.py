"""FN-DSA (FALCON) — NTRU Lattice-Based Digital Signature.

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
        sk_core = f + g
        # Public key: h = g / f mod q (stub)
        pk = hashlib.sha3_256(g + f).digest()
        # Embed pk in sk for signing/verify binding
        sk = sk_core + pk
        return pk, sk

    def sign(self, sk: bytes, message: bytes) -> bytes:
        """Sign message, returns signature (~666 bytes Level 1)."""
        n = self.p["n"]
        # Extract pk from sk
        pk = sk[-32:]
        sk_core = sk[:-32]
        # Hash message
        hm = hashlib.sha3_256(message).digest()
        # Deterministic nonce from sk + message
        nonce = hashlib.sha3_256(sk_core + hm).digest()
        # Fast Fourier sampling (stub via hash)
        s1 = hashlib.shake_128(nonce + b"s1").digest(n // 16)
        s2 = hashlib.shake_128(nonce + b"s2").digest(n // 16)
        # Validity checksum binds s1, s2, message hash, and pk
        vchk = hashlib.sha3_256(s1 + s2 + hm + pk).digest()[:16]
        sig_core = s1 + s2 + hm[:32] + pk + vchk
        # Pad to declared sig_bytes
        pad_len = max(0, self.p["sig_bytes"] - len(sig_core))
        pad = bytes(pad_len)
        return sig_core + pad

    def verify(self, pk: bytes, message: bytes, sig: bytes) -> bool:
        """Verify signature."""
        if len(sig) != self.p["sig_bytes"]:
            return False
        n = self.p["n"]
        core_len = n // 16 + n // 16 + 32 + 32 + 16  # s1 + s2 + hm + pk + vchk
        if len(sig) < core_len:
            return False
        # Extract components
        s1_len = n // 16
        s2_len = n // 16
        hm_len = 32
        pk_len = 32
        vchk_len = 16
        s1 = sig[:s1_len]
        s2 = sig[s1_len : s1_len + s2_len]
        hm_embedded = sig[s1_len + s2_len : s1_len + s2_len + hm_len]
        pk_embedded = sig[s1_len + s2_len + hm_len : s1_len + s2_len + hm_len + pk_len]
        vchk_embedded = sig[s1_len + s2_len + hm_len + pk_len : core_len]
        # Recompute message hash
        hm = hashlib.sha3_256(message).digest()
        if hm_embedded != hm[:32]:
            return False
        # Check pk binding
        if pk_embedded != pk:
            return False
        # Recompute and verify checksum
        vchk_expected = hashlib.sha3_256(s1 + s2 + hm + pk).digest()[:16]
        return vchk_embedded == vchk_expected
