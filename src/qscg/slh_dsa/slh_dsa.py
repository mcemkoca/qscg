"""SLH-DSA: Stateless Hash-Based Digital Signature Algorithm (FIPS 205).

This module provides the main user-facing interface for SLH-DSA (SPHINCS+)
combining the FORS few-time signature scheme, WOTS+ one-time signatures,
XMSS Merkle trees, and a multi-layer hypertree for stateless signing.

The implementation is organised as a :class:`SLHDSA` class that exposes
the standard key generation, signing, and verification workflow.  All
cryptographic primitives (hash functions, address management, etc.) are
imported from sibling modules within the ``slh_dsa`` package.

The WOTS+ and FORS modules are imported lazily so that :class:`SLHDSA` can
be instantiated and used for key generation even when those submodules are
not yet fully implemented (development workflow).  Real WOTS+ / FORS
functions are used when available; otherwise thin deterministic stubs are
used.

Implemented routines
--------------------
- :class:`SLHDSA` — Main SLH-DSA interface (keygen / sign / verify).

Usage example
-------------
>>> from qscg.slh_dsa.slh_dsa import SLHDSA
>>> from qscg.common.constants import SecurityLevel
>>> slh = SLHDSA(SecurityLevel.LEVEL_1)
>>> pk, sk = slh.keygen()
>>> message = b"Hello, quantum-safe world!"
>>> sig = slh.sign(message, sk)
>>> assert slh.verify(message, sig, pk)

Reference
---------
- NIST FIPS 205 — *Stateless Hash-Based Digital Signature Standard*.
"""

from __future__ import annotations

import secrets
from typing import Callable, Dict, List, Optional, Tuple

from ..common import hashing
from ..common.constants import SLHDSA_PARAMS, SecurityLevel
from .address import ADRS
from . import xmss


# ---------------------------------------------------------------------------
# SLH-DSA main class
# ---------------------------------------------------------------------------


class SLHDSA:
    """SLH-DSA (SPHINCS+) stateless hash-based digital signature.

    This class implements the complete SLH-DSA pipeline as specified in
    FIPS 205, Section 9.  It combines:

    * **FORS** — few-time signature scheme for the bottom layer.
    * **WOTS+** — one-time signature scheme for XMSS leaves.
    * **XMSS** — single-layer Merkle tree of WOTS+ keys.
    * **Hypertree** — *d* layers of XMSS trees for stateless operation.

    Parameters
    ----------
    level:
        NIST security category.  Defaults to :attr:`SecurityLevel.LEVEL_3`.

    Attributes
    ----------
    level : SecurityLevel
        The security level this instance was configured with.
    params : dict
        Dictionary of SLH-DSA parameters (``n``, ``h``, ``d``, ``a``, ``k``,
        ``w``, ``len``, etc.).
    """

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> None:
        self.level = level
        self.params = SLHDSA_PARAMS[level]

        # Cache frequently accessed parameters.
        self._n: int = self.params["n"]
        self._h: int = self.params["h"]
        self._d: int = self.params["d"]
        self._a: int = self.params["a"]
        self._k: int = self.params["k"]
        self._w: int = self.params["w"]
        self._len: int = self.params["len"]
        self._h_prime: int = self._h // self._d

        # Cached references to WOTS+ / FORS functions (lazily resolved).
        self._wots_pkgen: Optional[Callable] = None
        self._wots_sign: Optional[Callable] = None
        self._wots_pkfromsig: Optional[Callable] = None
        self._fors_sign: Optional[Callable] = None
        self._fors_pkfromsig: Optional[Callable] = None
        self._fors_pkgen: Optional[Callable] = None

    # ------------------------------------------------------------------
    # Lazily resolved WOTS+ / FORS callbacks
    # ------------------------------------------------------------------

    def _resolve_wots_pkgen(self) -> Callable:
        """Return the WOTS+ PKGen callback, resolving lazily."""
        if self._wots_pkgen is None:
            try:
                from . import wots as wots_mod
                self._wots_pkgen = wots_mod.wots_PKGen
            except (ImportError, AttributeError):
                self._wots_pkgen = self._stub_wots_PKGen
        return self._wots_pkgen

    def _resolve_wots_sign(self) -> Callable:
        """Return the WOTS+ Sign callback, resolving lazily."""
        if self._wots_sign is None:
            try:
                from . import wots as wots_mod
                self._wots_sign = wots_mod.wots_Sign
            except (ImportError, AttributeError):
                self._wots_sign = self._stub_wots_Sign
        return self._wots_sign

    def _resolve_wots_pkfromsig(self) -> Callable:
        """Return the WOTS+ PKFromSig callback, resolving lazily."""
        if self._wots_pkfromsig is None:
            try:
                from . import wots as wots_mod
                self._wots_pkfromsig = wots_mod.wots_PKFromSig
            except (ImportError, AttributeError):
                self._wots_pkfromsig = self._stub_wots_PKFromSig
        return self._wots_pkfromsig

    def _resolve_fors_sign(self) -> Callable:
        """Return the FORS Sign callback, resolving lazily."""
        if self._fors_sign is None:
            try:
                from . import fors as fors_mod
                self._fors_sign = fors_mod.fors_Sign
            except (ImportError, AttributeError):
                self._fors_sign = self._stub_fors_Sign
        return self._fors_sign

    def _resolve_fors_pkfromsig(self) -> Callable:
        """Return the FORS PKFromSig callback, resolving lazily."""
        if self._fors_pkfromsig is None:
            try:
                from . import fors as fors_mod
                self._fors_pkfromsig = fors_mod.fors_PKFromSig
            except (ImportError, AttributeError):
                self._fors_pkfromsig = self._stub_fors_PKFromSig
        return self._fors_pkfromsig

    def _resolve_fors_pkgen(self) -> Callable:
        """Return the FORS PKGen callback, resolving lazily."""
        if self._fors_pkgen is None:
            try:
                from . import fors as fors_mod
                self._fors_pkgen = fors_mod.fors_PKGen
            except (ImportError, AttributeError):
                self._fors_pkgen = self._stub_fors_PKGen
        return self._fors_pkgen

    # ------------------------------------------------------------------
    # XMSS / Hypertree callback bundles
    # ------------------------------------------------------------------

    def _wots_funcs_dict(self) -> dict:
        """Build the WOTS+ functions dict for the XMSS layer.

        The XMSS layer expects ``pkgen``, ``sign``, and ``pkfromsig``
        keys.  Each callback receives ``(..., params)`` as its final
        argument.

        Returns
        -------
        dict
            WOTS+ callback bundle.
        """
        return {
            "pkgen": self._resolve_wots_pkgen(),
            "sign": self._resolve_wots_sign(),
            "pkfromsig": self._resolve_wots_pkfromsig(),
        }

    def _xmss_funcs(self) -> dict:
        """Build the XMSS functions dict expected by the hypertree layer.

        Returns
        -------
        dict
            Dictionary with keys ``pkgen``, ``sign``, ``pkfromsig``
            (XMSS functions) and ``wots_pkgen``, ``wots_sign``,
            ``wots_pkfromsig`` (WOTS+ functions forwarded to XMSS).
        """
        return {
            "pkgen": xmss.xmss_PKGen,
            "sign": xmss.xmss_Sign,
            "pkfromsig": xmss.xmss_PKFromSig,
            "wots_pkgen": self._resolve_wots_pkgen(),
            "wots_sign": self._resolve_wots_sign(),
            "wots_pkfromsig": self._resolve_wots_pkfromsig(),
        }

    # ------------------------------------------------------------------
    # Key generation (FIPS 205, Algorithm 20)
    # ------------------------------------------------------------------

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate an SLH-DSA key pair.

        The secret key consists of three *n*-byte values (``SK_seed``,
        ``SK_prf``, ``PK_seed``) followed by the public key.  The public
        key consists of ``PK_seed`` followed by ``PK_root`` (the hypertree
        root).

        Returns
        -------
        Tuple[bytes, bytes]
            ``(pk, sk)`` where *pk* is ``2n`` bytes and *sk* is ``4n`` bytes
            (the last ``2n`` bytes of *sk* duplicate *pk*).

        Reference
        ---------
        FIPS 205, Algorithm 20 (*slh_keygen*).
        """
        n = self._n

        SK_seed = secrets.token_bytes(n)
        SK_prf = secrets.token_bytes(n)
        PK_seed = secrets.token_bytes(n)

        # Generate PK_root using the hypertree.
        PK_root = self._generate_pk_root(SK_seed, PK_seed)

        pk = PK_seed + PK_root
        sk = SK_seed + SK_prf + pk

        return pk, sk

    # ------------------------------------------------------------------
    # Signing (FIPS 205, Algorithm 21)
    # ------------------------------------------------------------------

    def sign(self, M: bytes, sk: bytes, randomized: bool = True) -> bytes:
        """Sign a message with SLH-DSA.

        Parameters
        ----------
        M:
            Message to sign (arbitrary byte string).
        sk:
            Secret key — ``4n`` bytes as produced by :meth:`keygen`.
        randomized:
            If ``True`` (default), generate a fresh randomiser for hedged
            signing.  If ``False``, use ``PK_seed`` as the optional random
            value, yielding deterministic signatures.

        Returns
        -------
        bytes
            SLH-DSA signature.  The exact length depends on the parameter
            set.

        Raises
        ------
        ValueError
            If *sk* has the wrong length.

        Reference
        ---------
        FIPS 205, Algorithm 21 (*slh_sign*).
        """
        n = self._n

        if len(sk) != 4 * n:
            raise ValueError(
                f"SLH-DSA sign: expected sk length {4*n}, got {len(sk)}"
            )

        # Parse secret key.
        SK_seed = sk[0:n]
        SK_prf = sk[n:2*n]
        PK_seed = sk[2*n:3*n]
        PK_root = sk[3*n:4*n]

        # Generate randomness R.
        if randomized:
            opt_rand = secrets.token_bytes(n)
        else:
            opt_rand = PK_seed

        R = hashing.PRFmsg(SK_prf, opt_rand, M)
        R = R[:n]

        # Message digest: split into (index, FORS message).
        digest = hashing.H_msg(R, PK_seed, PK_root, M, n)
        idx, fors_message = self._split_digest(digest)

        # Split idx into tree and leaf components for the hypertree.
        # The lower h_prime bits give the leaf index within each XMSS
        # tree; the upper h - h_prime bits give the tree address.
        idx_tree = idx >> self._h_prime
        idx_leaf = idx & ((1 << self._h_prime) - 1)

        # FORS sign.
        fors_adrs = ADRS()
        fors_adrs.layer = 0
        fors_adrs.tree_address = idx_tree
        fors_adrs.keypair_address = idx_leaf

        fors_sig, fors_auth_paths = self._resolve_fors_sign()(
            fors_message, SK_seed, PK_seed, fors_adrs, self.params
        )

        # Reconstruct FORS public key (used as XMSS message).
        fors_pk = self._resolve_fors_pkfromsig()(
            fors_sig, fors_auth_paths, fors_message, PK_seed, fors_adrs,
            self.params,
        )
        fors_pk = fors_pk[:n]

        # Hypertree sign (authenticates the FORS public key).
        sig_ht = self._ht_sign(fors_pk, SK_seed, PK_seed, idx_tree, idx_leaf)

        # Encode the signature.
        sig = self._encode_signature(R, fors_sig, fors_auth_paths, sig_ht)

        return sig

    # ------------------------------------------------------------------
    # Verification (FIPS 205, Algorithm 22)
    # ------------------------------------------------------------------

    def verify(self, M: bytes, sig: bytes, pk: bytes) -> bool:
        """Verify an SLH-DSA signature.

        Parameters
        ----------
        M:
            Original message.
        sig:
            SLH-DSA signature produced by :meth:`sign`.
        pk:
            Public key — ``2n`` bytes as produced by :meth:`keygen`.

        Returns
        -------
        bool
            ``True`` if the signature is valid, ``False`` otherwise.

        Raises
        ------
        ValueError
            If *pk* has the wrong length.

        Reference
        ---------
        FIPS 205, Algorithm 22 (*slh_verify*).
        """
        n = self._n

        if len(pk) != 2 * n:
            raise ValueError(
                f"SLH-DSA verify: expected pk length {2*n}, got {len(pk)}"
            )

        PK_seed = pk[0:n]
        PK_root = pk[n:2*n]

        # Parse signature.
        R, fors_sig, fors_auth_paths, sig_ht = self._decode_signature(sig, n)

        # Recompute message digest and extract index.
        digest = hashing.H_msg(R, PK_seed, PK_root, M, n)
        idx, fors_message = self._split_digest(digest)

        # Split idx for the hypertree (same logic as sign).
        idx_tree = idx >> self._h_prime
        idx_leaf = idx & ((1 << self._h_prime) - 1)

        # FORS verify: reconstruct FORS public key.
        fors_adrs = ADRS()
        fors_adrs.layer = 0
        fors_adrs.tree_address = idx_tree
        fors_adrs.keypair_address = idx_leaf

        fors_pk = self._resolve_fors_pkfromsig()(
            fors_sig, fors_auth_paths, fors_message, PK_seed, fors_adrs,
            self.params,
        )
        fors_pk = fors_pk[:n]

        # Hypertree verify.
        return self._ht_verify(
            fors_pk, sig_ht, PK_seed, PK_root, idx_tree, idx_leaf,
        )

    # ==================================================================
    # Internal helpers
    # ==================================================================

    def _generate_pk_root(self, SK_seed: bytes, PK_seed: bytes) -> bytes:
        """Generate the hypertree public-key root.

        Parameters
        ----------
        SK_seed:
            *n*-byte secret-key seed.
        PK_seed:
            *n*-byte public-key seed.

        Returns
        -------
        bytes
            *n*-byte hypertree root.
        """
        return self._ht_pkgen(SK_seed, PK_seed)

    def _ht_pkgen(self, SK_seed: bytes, PK_seed: bytes) -> bytes:
        """Generate the hypertree public key root.

        Delegates to the hypertree module after building the callback
        bundle.

        Parameters
        ----------
        SK_seed:
            *n*-byte secret-key seed.
        PK_seed:
            *n*-byte public-key seed.

        Returns
        -------
        bytes
            *n*-byte hypertree root.
        """
        from . import hypertree as ht_mod

        return ht_mod.ht_PKGen(
            SK_seed, PK_seed, self.params, self._xmss_funcs()
        )

    def _ht_sign(
        self,
        M: bytes,
        SK_seed: bytes,
        PK_seed: bytes,
        idx_tree: int,
        idx_leaf: int,
    ) -> List[Tuple[List[bytes], List[bytes]]]:
        """Sign a message digest through the hypertree.

        Parameters
        ----------
        M:
            *n*-byte message digest (FORS public-key hash).
        SK_seed:
            *n*-byte secret-key seed.
        PK_seed:
            *n*-byte public-key seed.
        idx_tree:
            Tree index within layer 0.
        idx_leaf:
            Leaf index within the selected XMSS tree.

        Returns
        -------
        List[Tuple[List[bytes], List[bytes]]]
            Hypertree signature — list of *d* XMSS signature tuples.
        """
        from . import hypertree as ht_mod

        return ht_mod.ht_Sign(
            M, SK_seed, PK_seed, idx_tree, idx_leaf,
            self.params, self._xmss_funcs(),
        )

    def _ht_verify(
        self,
        M: bytes,
        sig_ht: List[Tuple[List[bytes], List[bytes]]],
        PK_seed: bytes,
        PK_root: bytes,
        idx_tree: int,
        idx_leaf: int,
    ) -> bool:
        """Verify a hypertree signature.

        Parameters
        ----------
        M:
            *n*-byte message digest.
        sig_ht:
            Hypertree signature.
        PK_seed:
            *n*-byte public-key seed.
        PK_root:
            *n*-byte expected hypertree root.
        idx_tree:
            Tree index used during signing.
        idx_leaf:
            Leaf index used during signing.

        Returns
        -------
        bool
            ``True`` if the hypertree signature is valid.
        """
        from . import hypertree as ht_mod

        return ht_mod.ht_Verify(
            M, sig_ht, PK_seed, PK_root, idx_tree, idx_leaf,
            self.params, self._xmss_funcs(),
        )

    # ------------------------------------------------------------------
    # Digest splitting
    # ------------------------------------------------------------------

    def _split_digest(self, digest: bytes) -> Tuple[int, bytes]:
        """Split the message digest into (tree index, FORS message).

        The digest is divided into:
        - ``h`` bits for the tree index (split further into idx_tree and
          idx_leaf by the caller).
        - ``k * a`` bits for the FORS message digest.

        Parameters
        ----------
        digest:
            *n*-byte message digest from :func:`hashing.H_msg`.

        Returns
        -------
        Tuple[int, bytes]
            ``(idx, fors_message)`` where *idx* is the tree index (``h``
            bits) and *fors_message* is the ``k * a``-bit FORS message.
        """
        h = self._h
        k = self._k
        a = self._a

        idx_bits = h
        fors_bits = k * a

        idx_bytes = (idx_bits + 7) // 8
        fors_bytes = (fors_bits + 7) // 8

        # Extract idx: h most-significant bits of the first idx_bytes.
        idx = int.from_bytes(digest[:idx_bytes], "big")
        idx >>= (8 * idx_bytes - idx_bits)
        idx &= (1 << idx_bits) - 1

        # Extract fors_message: next fors_bytes.
        fors_message = digest[idx_bytes:idx_bytes + fors_bytes]

        return idx, fors_message

    # ------------------------------------------------------------------
    # Signature encoding / decoding
    # ------------------------------------------------------------------

    def _encode_signature(
        self,
        R: bytes,
        fors_sig: List[bytes],
        fors_auth_paths: List[List[bytes]],
        sig_ht: List[Tuple[List[bytes], List[bytes]]],
    ) -> bytes:
        """Encode an SLH-DSA signature into a flat byte string.

        Format::

            sig = R || fors_sig || fors_auth_paths_flat || sig_ht_flat

        where:
        - *R* is *n* bytes.
        - *fors_sig* is ``k`` *n*-byte secret-key elements.
        - *fors_auth_paths_flat* is ``k * a`` *n*-byte auth nodes (each
          tree contributes ``a`` siblings).
        - *sig_ht_flat* is the concatenation of all *d* XMSS signatures,
          each consisting of ``len`` WOTS+ values plus ``h_prime`` auth
          nodes.

        Parameters
        ----------
        R:
            *n*-byte randomiser.
        fors_sig:
            FORS signature — list of ``k`` *n*-byte secret-key elements.
        fors_auth_paths:
            FORS authentication paths — list of ``k`` paths; each path is
            a list of ``a`` *n*-byte sibling digests.
        sig_ht:
            Hypertree signature — list of *d* tuples ``(sig_ots, auth)``.

        Returns
        -------
        bytes
            Encoded signature.
        """
        parts: List[bytes] = [R]

        # FORS signature elements.
        parts.extend(fors_sig)

        # FORS authentication paths (flatten).
        for path in fors_auth_paths:
            parts.extend(path)

        # Hypertree signatures.
        for sig_ots, auth in sig_ht:
            parts.extend(sig_ots)
            parts.extend(auth)

        return b"".join(parts)

    def _decode_signature(
        self,
        sig: bytes,
        n: int,
    ) -> Tuple[bytes, List[bytes], List[List[bytes]], List[Tuple[List[bytes], List[bytes]]]]:
        """Decode an SLH-DSA signature from a flat byte string.

        This is the inverse of :meth:`_encode_signature`.

        Parameters
        ----------
        sig:
            Encoded SLH-DSA signature.
        n:
            Security parameter.

        Returns
        -------
        Tuple[bytes, List[bytes], List[List[bytes]], List[Tuple[List[bytes], List[bytes]]]]
            ``(R, fors_sig, fors_auth_paths, sig_ht)``.
        """
        k = self._k
        d = self._d
        h_prime = self._h_prime
        wots_len = self._len
        a = self._a

        pos = 0

        # R.
        R = sig[pos:pos + n]
        pos += n

        # FORS signature: k n-byte values.
        fors_sig: List[bytes] = []
        for _ in range(k):
            end = min(pos + n, len(sig))
            chunk = sig[pos:end]
            if len(chunk) < n:
                chunk = chunk + b"\x00" * (n - len(chunk))
            fors_sig.append(chunk)
            pos += n

        # FORS authentication paths: k paths of a n-byte values each.
        fors_auth_paths: List[List[bytes]] = []
        for _ in range(k):
            path: List[bytes] = []
            for _ in range(a):
                end = min(pos + n, len(sig))
                chunk = sig[pos:end]
                if len(chunk) < n:
                    chunk = chunk + b"\x00" * (n - len(chunk))
                path.append(chunk)
                pos += n
            fors_auth_paths.append(path)

        # Hypertree signatures: d layers of (len + h_prime) n-byte values.
        sig_ht: List[Tuple[List[bytes], List[bytes]]] = []
        for _ in range(d):
            sig_ots: List[bytes] = []
            for _ in range(wots_len):
                end = min(pos + n, len(sig))
                chunk = sig[pos:end]
                if len(chunk) < n:
                    chunk = chunk + b"\x00" * (n - len(chunk))
                sig_ots.append(chunk)
                pos += n

            auth: List[bytes] = []
            for _ in range(h_prime):
                end = min(pos + n, len(sig))
                chunk = sig[pos:end]
                if len(chunk) < n:
                    chunk = chunk + b"\x00" * (n - len(chunk))
                auth.append(chunk)
                pos += n

            sig_ht.append((sig_ots, auth))

        return R, fors_sig, fors_auth_paths, sig_ht

    # ==================================================================
    # Deterministic stubs for development (when WOTS+/FORS are absent)
    # ==================================================================

    def _stub_wots_PKGen(
        self,
        SK_seed: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> bytes:
        """Stub WOTS+ PKGen: produce a single n-byte compressed PK.

        Uses T_l over a vector of ``len`` PRF-derived values.
        """
        n = params["n"]
        length = params.get("len", params.get("len1", 32) + params.get("len2", 3))
        tmp: List[bytes] = []
        for i in range(length):
            adrs.type = ADRS.WOTS_HASH
            adrs.chain_address = i
            adrs.hash_address = 0
            sk_i = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
            tmp.append(sk_i[:n])
        adrs.type = ADRS.WOTS_PK
        adrs.chain_address = 0
        adrs.hash_address = 0
        pk = hashing.T_l(PK_seed, bytes(adrs), b"".join(tmp))
        return pk[:n]

    def _stub_wots_Sign(
        self,
        M: bytes,
        SK_seed: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> List[bytes]:
        """Stub WOTS+ Sign: produce ``len`` n-byte signature elements."""
        n = params["n"]
        length = params.get("len", params.get("len1", 32) + params.get("len2", 3))
        sig_elements: List[bytes] = []
        for i in range(length):
            adrs.type = ADRS.WOTS_HASH
            adrs.chain_address = i
            adrs.hash_address = 0
            val = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
            sig_elements.append(val[:n])
        return sig_elements

    def _stub_wots_PKFromSig(
        self,
        sig: List[bytes],
        M: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> bytes:
        """Stub WOTS+ PKFromSig: return a single n-byte hash of the inputs."""
        n = params["n"]
        combined = b"".join(sig) + M + bytes(adrs)
        import hashlib
        shake = hashlib.shake_256()
        shake.update(combined)
        return shake.digest(n)

    def _stub_fors_Sign(
        self,
        md: bytes,
        SK_seed: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> Tuple[List[bytes], List[List[bytes]]]:
        """Stub FORS Sign: produce k n-byte signature values."""
        n = params["n"]
        k = params["k"]
        a = params["a"]
        fors_sig = []
        for i in range(k):
            adrs.type = ADRS.FORS_TREE
            adrs.keypair_address = i
            val = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
            fors_sig.append(val[:n])
        # Empty auth paths for the stub.
        auth_paths = [[] for _ in range(k)]
        return fors_sig, auth_paths

    def _stub_fors_PKFromSig(
        self,
        sig: List[bytes],
        auth_paths: List[List[bytes]],
        md: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> bytes:
        """Stub FORS PKFromSig: return a single n-byte hash."""
        n = params["n"]
        combined = b"".join(sig) + md + bytes(adrs)
        import hashlib
        shake = hashlib.shake_256()
        shake.update(combined)
        return shake.digest(n)

    def _stub_fors_PKGen(
        self,
        SK_seed: bytes,
        PK_seed: bytes,
        adrs: ADRS,
        params: dict,
    ) -> bytes:
        """Stub FORS PKGen: produce a single n-byte FORS public key."""
        n = params["n"]
        combined = SK_seed + PK_seed + bytes(adrs)
        import hashlib
        shake = hashlib.shake_256()
        shake.update(combined)
        return shake.digest(n)
