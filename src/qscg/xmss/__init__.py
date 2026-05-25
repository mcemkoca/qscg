"""XMSS — eXtended Merkle Signature Scheme

Implements NIST SP 800-208 and RFC 8391.
XMSS^MT is the multi-tree variant for larger signature counts.

This is a STUB — full implementation tracked in issue #3.
"""

from __future__ import annotations

from typing import Tuple

import hashlib


__all__ = ["XMSS", "XMSSMT"]


class XMSS:
    """Single-tree XMSS signature scheme.

    XMSS uses WOTS+ (Winternitz OTS variant) as the underlying
    one-time signature, organized in a Merkle hash tree.

    Parameters (per RFC 8391 / SP 800-208):
        - XMSS-SHA2_10_256  (height=10,  SHA-256, n=32)
        - XMSS-SHA2_16_256  (height=16,  SHA-256, n=32)
        - XMSS-SHA2_20_256  (height=20,  SHA-256, n=32)

    Attributes:
        tree_height: Height of the Merkle tree.
        hash_function: Hash algorithm.
        n: Security parameter (hash output length in bytes).
        w: Winternitz parameter (typically 16).
    """

    # ------------------------------------------------------------------
    # TODO list (issue #3)
    # ------------------------------------------------------------------
    # [ ] WOTS+ key generation (RFC 8391 Section 3.1)
    # [ ] WOTS+ sign and verify (RFC 8391 Section 3.2)
    # [ ] L-tree construction (hashing WOTS+ public key into single value)
    # [ ] XMSS tree construction (Merkle tree of L-tree roots)
    # [ ] Signature format: (index, randomness, ots_sig, auth_path)
    # [ ] Verification: WOTS+ verify + auth path → root comparison
    # [ ] Index tracking (stateful — NEVER reuse)
    # [ ] NIST CAVP test vectors
    # ------------------------------------------------------------------

    SHA2_10_256 = (10, hashlib.sha256, 32, 16)
    SHA2_16_256 = (16, hashlib.sha256, 32, 16)
    SHA2_20_256 = (20, hashlib.sha256, 32, 16)

    def __init__(self, params: tuple = SHA2_10_256) -> None:
        self.tree_height, self.hash_function, self.n, self.w = params
        self.next_index: int = 0
        self._private_seed: bytes | None = None
        self._public_key: bytes | None = None

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an XMSS keypair.

        Returns:
            (public_key, secret_key)

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "XMSS.keygen() is a stub. Full implementation tracked in issue #3. "
            "Required: WOTS+ keygen, L-tree, Merkle tree construction."
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign with the next available XMSS one-time key.

        WARNING: STATEFUL. Never reuse an index.

        Args:
            secret_key: The XMSS secret key.
            message: The message to sign.

        Returns:
            The XMSS signature.

        Raises:
            NotImplementedError: This is a stub.
            RuntimeError: When all OTS keys are exhausted.
        """
        raise NotImplementedError(
            "XMSS.sign() is a stub. Full implementation tracked in issue #3. "
            "Required: WOTS+ sign, auth path generation, index tracking."
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an XMSS signature.

        Args:
            public_key: The XMSS public key.
            message: The signed message.
            signature: The XMSS signature.

        Returns:
            True if valid, False otherwise.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "XMSS.verify() is a stub. Full implementation tracked in issue #3. "
            "Required: WOTS+ verify, auth path → root reconstruction."
        )


class XMSSMT:
    """Multi-tree XMSS (XMSS^MT) for larger signature counts.

    XMSS^MT is a hyper-tree of XMSS trees. The top-level XMSS tree
    signs the public keys of the next level, and so on.

    Parameters:
        d: Number of XMSS tree layers (e.g., 2 or 4).
        xmss_params: XMSS parameter set for each tree.

    Example: XMSSMT with d=2, each XMSS-SHA2_10_256 gives
    1024 × 1024 = ~1M signatures total.
    """

    def __init__(self, d: int = 2, xmss_params: tuple = XMSS.SHA2_10_256) -> None:
        self.d = d
        self.xmss_params = xmss_params
        self._trees: list[XMSS] = []

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an XMSS^MT keypair.

        Returns:
            (public_key, secret_key)

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "XMSSMT.keygen() is a stub. Full implementation tracked in issue #3. "
            "Required: Multi-tree XMSS keygen with inter-level signing."
        )

    def sign(self, secret_key: bytes, message: bytes) -> bytes:
        """Sign with the next available XMSS^MT one-time key.

        Args:
            secret_key: The XMSS^MT secret key.
            message: The message to sign.

        Returns:
            The XMSS^MT signature.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "XMSSMT.sign() is a stub. Full implementation tracked in issue #3."
        )

    def verify(self, public_key: bytes, message: bytes, signature: bytes) -> bool:
        """Verify an XMSS^MT signature.

        Args:
            public_key: The XMSS^MT public key.
            message: The signed message.
            signature: The XMSS^MT signature.

        Returns:
            True if valid, False otherwise.

        Raises:
            NotImplementedError: This is a stub.
        """
        raise NotImplementedError(
            "XMSSMT.verify() is a stub. Full implementation tracked in issue #3."
        )
