"""LMS — Leighton-Micali Hash-Based Signature Scheme

Implements NIST SP 800-208: Recommendation for Stateful Hash-Based
Signature Schemes. LMS and its multi-tree variant HSS are the
preferred algorithms for firmware signing under CNSA 2.0.

This is a STUB — full implementation tracked in issue #3.
"""

from __future__ import annotations

from typing import Tuple, Optional

import hashlib


__all__ = ["LMS", "HSS"]


class LMS:
    """Single-tree Leighton-Micali Signature (LMS).

    LMS uses a Merkle hash tree where each leaf is a one-time
    signature (OTS) key. After each signing operation the OTS key
    is consumed and must never be reused.

    Parameters supported (per SP 800-208):
        - LMS_SHA256_M32_H5  (height=5,  32 leaves,  SHA-256)
        - LMS_SHA256_M32_H10 (height=10, 1024 leaves, SHA-256)
        - LMS_SHA256_M32_H15 (height=15, 32768 leaves, SHA-256)

    Attributes:
        tree_height: Height of the Merkle tree.
        hash_function: Hash algorithm (SHA-256).
        next_index: Next available leaf index for signing.
        _private_seed: Secret seed for OTS key generation.
    """

    # ------------------------------------------------------------------
    # TODO list (issue #3)
    # ------------------------------------------------------------------
    # [ ] Merkle tree construction (hash-based, bottom-up)
    # [ ] LM-OTS key generation (Winternitz one-time signatures)
    # [ ] LM-OTS sign and verify (per RFC 8554)
    # [ ] Merkle path generation for authentication
    # [ ] Signature format: (typecode, ots_sig, merkle_path, leaf_index)
    # [ ] Verification: OTS verify + Merkle root check
    # [ ] Index tracking (stateful — NEVER reuse an index)
    # [ ] NIST CAVP test vectors
    # ------------------------------------------------------------------

    SHA256_M32_H5 = (5, hashlib.sha256, 32)
    SHA256_M32_H10 = (10, hashlib.sha256, 32)
    SHA256_M32_H15 = (15, hashlib.sha256, 32)

    def __init__(self, params: tuple = SHA256_M32_H10) -> None:
        self.tree_height, self.hash_function, self.m = params
        self.next_index: int = 0
        self._private_seed: bytes | None = None
        self._public_key: bytes | None = None
        self._secret_key: bytes | None = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an LMS keypair.

        Returns:
            (public_key, secret_key)

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "LMS.keygen() is a stub. Full implementation tracked in issue #3. "
            "Required: Winternitz OTS keygen, Merkle tree construction."
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign a message with the next available LMS one-time key.

        WARNING: This is a STATEFUL signature scheme. Each index
        can only be used ONCE. Reusing an index breaks security.

        Args:
            secret_key: The LMS secret key (includes tree state).
            message: The message to sign.

        Returns:
            The LMS signature.

        Raises:
            NotImplementedError: This is a stub.
            RuntimeError: When all OTS keys are exhausted.
        """
        raise NotImplementedError(
            "LMS.sign() is a stub. Full implementation tracked in issue #3. "
            "Required: Winternitz OTS sign, Merkle path, index tracking."
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an LMS signature.

        Args:
            public_key: The LMS public key.
            message: The signed message.
            signature: The LMS signature to verify.

        Returns:
            True if the signature is valid, False otherwise.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "LMS.verify() is a stub. Full implementation tracked in issue #3. "
            "Required: Winternitz OTS verify, Merkle root reconstruction."
        )


class HSS:
    """Hierarchical Signature System (HSS) — multi-tree LMS.

    HSS uses a tree of LMS trees to increase the total number of
    available signatures. The top-level tree signs the public key
    of the next level, and so on.

    Parameters:
        levels: Number of LMS tree levels (e.g., 2 or 3).
        lms_params: LMS parameter set for each level.

    Example: HSS with L=2, each LMS_SHA256_M32_H10 gives
    1024 × 1024 = ~1M signatures total.
    """

    def __init__(self, levels: int = 2, lms_params: tuple = LMS.SHA256_M32_H10) -> None:
        self.levels = levels
        self.lms_params = lms_params
        self._trees: list[LMS] = []

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an HSS keypair.

        Returns:
            (public_key, secret_key)

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "HSS.keygen() is a stub. Full implementation tracked in issue #3. "
            "Required: Multi-tree LMS keygen with inter-level signing."
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign with the next available HSS one-time key.

        Args:
            secret_key: The HSS secret key.
            message: The message to sign.

        Returns:
            The HSS signature.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "HSS.sign() is a stub. Full implementation tracked in issue #3."
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an HSS signature.

        Args:
            public_key: The HSS public key.
            message: The signed message.
            signature: The HSS signature.

        Returns:
            True if valid, False otherwise.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "HSS.verify() is a stub. Full implementation tracked in issue #3."
        )
