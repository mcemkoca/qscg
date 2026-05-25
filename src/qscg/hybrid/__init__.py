"""Hybrid KEM: X25519 + ML-KEM-768

Implements the IETF draft "Hybrid PQ Key Exchange in TLS 1.3".
Combines classical X25519 elliptic-curve Diffie-Hellman with
post-quantum ML-KEM-768 for defense-in-depth against HNDL.

This is a STUB — full implementation tracked in issue #4.
"""

from __future__ import annotations

from typing import Tuple

from qscg.common.constants import SecurityLevel
from qscg_v2_1_final import MLKEM


__all__ = ["X25519Kyber768"]


class X25519Kyber768:
    """Hybrid key exchange combining X25519 and ML-KEM-768.

    Design rationale:
    - X25519: fast, battle-tested classical key exchange
    - ML-KEM-768: NIST-standardized post-quantum KEM
    - Hybrid: if either is broken, the other still protects confidentiality

    Ref: IETF draft-ietf-tls-hybrid-design
    Ref: Chrome / BoringSSL deployment (Sept 2024)
    Ref: Cloudflare PQ TLS to origin (Sept 2023)

    Attributes:
        mlkem: Underlying ML-KEM-768 instance.
        x25519_private: Classical X25519 private key (32 bytes).
        x25519_public: Classical X25519 public key (32 bytes).
    """

    # ------------------------------------------------------------------
    # TODO list (issue #4)
    # ------------------------------------------------------------------
    # [ ] X25519 key generation (Curve25519 scalar multiplication)
    # [ ] Shared secret derivation (X25519 ECDH)
    # [ ] Hybrid shared secret combiner ( ConcatKDF or HKDF )
    # [ ] TLS 1.3 key schedule integration
    # [ ] Encapsulation produces both classical and PQC ciphertexts
    # [ ] Decapsulation accepts both ciphertexts
    # [ ] Constant-time X25519 operations
    # [ ] Interop test vectors (if available from IETF)
    # ------------------------------------------------------------------

    PUBLIC_KEY_SIZE = 1216   # 32 (X25519) + 1184 (ML-KEM-768)
    SECRET_KEY_SIZE = 2432   # 32 (X25519) + 2400 (ML-KEM-768 decaps key)
    CIPHERTEXT_SIZE = 1120   # 32 (X25519) + 1088 (ML-KEM-768 ciphertext)

    def __init__(self) -> None:
        self.mlkem = MLKEM(level=SecurityLevel.LEVEL_3)
        self.x25519_private: bytes | None = None
        self.x25519_public: bytes | None = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a hybrid keypair.

        Returns:
            (public_key, secret_key) where public_key is the hybrid
            public key to be sent to the peer, and secret_key is kept
            locally for decapsulation.

        Raises:
            NotImplementedError: This is a stub. Full implementation
                requires X25519 key generation (issue #4).
        """
        raise NotImplementedError(
            "X25519Kyber768.keygen() is a stub. "
            "Full implementation tracked in issue #4. "
            "Required: X25519 scalar multiplication, hybrid key combiner."
        )

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate a shared secret to the given hybrid public key.

        Args:
            public_key: The recipient's hybrid public key
                (X25519 pubkey || ML-KEM pubkey).

        Returns:
            (ciphertext, shared_secret) where ciphertext is sent to
            the peer and shared_secret is the derived session key.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "X25519Kyber768.encapsulate() is a stub. "
            "Full implementation tracked in issue #4. "
            "Required: X25519 ECDH, ML-KEM encapsulate, secret combiner."
        )

    def decapsulate(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate the shared secret using the hybrid secret key.

        Args:
            ciphertext: The hybrid ciphertext from the peer
                (X25519 ephemeral pubkey || ML-KEM ciphertext).
            secret_key: The local hybrid secret key
                (X25519 private key || ML-KEM decapsulation key).

        Returns:
            The derived shared secret (session key).

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "X25519Kyber768.decapsulate() is a stub. "
            "Full implementation tracked in issue #4. "
            "Required: X25519 ECDH, ML-KEM decapsulate, secret combiner."
        )
