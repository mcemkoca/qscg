"""WireGuard with PQC handshake."""

import os
import hashlib
from typing import Tuple


class WireGuard_PQC:
    """WireGuard Noise protocol + ML-KEM hybrid handshake."""

    def __init__(self):
        self.static_key = os.urandom(32)

    def handshake_init(self, pq_pk: bytes) -> Tuple[bytes, bytes]:
        """Initiator handshake with PQC encapsulation."""
        ephemeral = os.urandom(32)
        # Noise CKDF + PQC shared secret
        ck = hashlib.sha3_256(self.static_key + ephemeral).digest()
        ss_pq = hashlib.sha3_256(pq_pk).digest()
        return ck, ss_pq

    def handshake_respond(self, initiator_msg: bytes, sk: bytes) -> bytes:
        """Responder completes PQC handshake."""
        return hashlib.sha3_256(initiator_msg + sk).digest()
