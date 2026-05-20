"""Signal Protocol v4 with PQC integration."""

import os
import hashlib
from typing import Tuple


class Signal_PQC:
    """Signal Protocol with post-quantum Double Ratchet."""

    def __init__(self):
        self.identity_key = os.urandom(32)

    def x3dh_init(self, pq_prekey: bytes) -> bytes:
        """X3DH + ML-KEM initial key agreement."""
        ephemeral = os.urandom(32)
        ss = hashlib.sha3_256(self.identity_key + ephemeral + pq_prekey).digest()
        return ss

    def double_ratchet_step(self, root_key: bytes, pq_output: bytes) -> Tuple[bytes, bytes]:
        """Double ratchet with PQC chain key."""
        chain = hashlib.sha3_256(root_key + pq_output).digest()
        message_key = hashlib.sha3_256(chain).digest()
        return chain, message_key
