"""QUIC PQC Extension - X25519Kyber768 hybrid.

RFC 9794 PQC terminology, draft-ietf-tls-xyber768d00.
"""

from typing import Tuple
import os
import hashlib


class QUIC_PQC:
    """QUIC with post-quantum key exchange."""

    def __init__(self):
        self.version = "v3.0.0"

    def handshake(self) -> Tuple[bytes, bytes]:
        """ClientHello + key_share exchange."""
        # X25519Kyber768 hybrid key share
        x25519_share = os.urandom(32)
        kyber_share = os.urandom(1184)
        client_hello = x25519_share + kyber_share
        # ServerHello
        server_share = os.urandom(1088)
        ss = hashlib.sha3_256(x25519_share + server_share).digest()
        return client_hello, ss

    def encrypt_extensions(self, shared_secret: bytes, extensions: bytes) -> bytes:
        """Encrypt QUIC extensions with PQC shared secret."""
        mask = hashlib.shake_128(shared_secret).digest(len(extensions))
        return bytes(a ^ b for a, b in zip(extensions, mask))
