"""XMSS: eXtended Merkle Signature Scheme (FIPS 205, Section 7).

Single-layer Merkle tree built from WOTS+ public keys.  Uses L-trees to
compress WOTS+ public keys (``len`` hash values) into single *n*-byte leaf
values before inserting them into the XMSS binary hash tree.

The WOTS+ functions are passed as a *callbacks* dictionary so that this
module has no direct dependency on the ``wots`` submodule.  All WOTS+
callbacks receive ``params`` as their last argument.

Implemented routines
--------------------
- :func:`ltree` — Compress a WOTS+ public key into an *n*-byte L-tree root.
- :func:`xmss_TreeHash` — Build an XMSS subtree and return its root.
- :func:`xmss_PKGen` — Derive the XMSS public key (tree root).
- :func:`xmss_Sign` — Sign a message digest and produce the auth path.
- :func:`xmss_PKFromSig` — Reconstruct the XMSS root from a signature for
  verification.

Usage example
-------------
>>> from qscg.slh_dsa.xmss import xmss_PKGen, xmss_Sign, xmss_PKFromSig
>>> wots_funcs = {
...     'pkgen': lambda sk, pk, ad, pr: wots.wots_PKGen(sk, pk, ad, pr),
...     'sign':  lambda m, sk, pk, ad, pr: wots.wots_Sign(m, sk, pk, ad, pr),
...     'pkfromsig': lambda sig, m, pk, ad, pr: wots.wots_PKFromSig(sig, m, pk, ad, pr),
... }
>>> root = xmss_PKGen(sk_seed, pk_seed, adrs, n, h_prime, wots_funcs, params)
>>> sig_ots, auth = xmss_Sign(M, sk_seed, pk_seed, adrs, idx, n, h_prime,
...                           wots_funcs, params)
>>> assert xmss_PKFromSig(idx, sig_ots, auth, M, pk_seed, adrs, n, h_prime,
...                       wots_funcs, params) == root

Reference
---------
- NIST FIPS 205, Section 7 — *XMSS*.
- NIST FIPS 205, Section 5.2 — *L-Trees*.
"""

from __future__ import annotations

from typing import Callable, Dict, List, Tuple

from ..common import hashing
from .address import ADRS


# ---------------------------------------------------------------------------
# L-tree (public-key compression)
# ---------------------------------------------------------------------------


def ltree(
    PK_seed: bytes,
    pk_elements: List[bytes],
    adrs: ADRS,
    n: int,
) -> bytes:
    """Compress a WOTS+ public key into a single *n*-byte value via L-tree.

    An L-tree is an unbalanced binary tree that hashes ``len`` WOTS+ public-key
elements (each *n* bytes) down to a single *n*-byte root.  It is structurally
identical to a standard Merkle tree except that the last node on an odd level
is promoted to the next level unchanged (no dummy padding).

    The address fields ``tree_height`` and ``hash_address`` (used as tree
    index) are updated for every L-tree level to provide domain separation.

    Parameters
    ----------
    PK_seed:
        *n*-byte public seed from the SLH-DSA public key.
    pk_elements:
        List of ``len`` *n*-byte WOTS+ public-key hash values.
    adrs:
        ADRS with ``type == ADRS.TREE`` already set.  ``tree_height`` and
        ``hash_address`` are mutated in place during the computation.
    n:
        Security parameter — hash output length in bytes.

    Returns
    -------
    bytes
        *n*-byte L-tree root (compressed WOTS+ public key).

    Reference
    ---------
    FIPS 205, Section 5.2.
    """
    ltree_adrs = adrs.copy()
    ltree_adrs.type = ADRS.TREE
    ltree_adrs.tree_height = 0

    nodes: List[bytes] = list(pk_elements)

    while len(nodes) > 1:
        next_level: List[bytes] = []
        i = 0
        while i < len(nodes):
            if i + 1 < len(nodes):
                ltree_adrs.tree_height = 0
                ltree_adrs.hash_address = i // 2
                combined = nodes[i] + nodes[i + 1]
                node = hashing.T_l(PK_seed, bytes(ltree_adrs), combined)
                next_level.append(node[:n])
                i += 2
            else:
                next_level.append(nodes[i][:n])
                i += 1
        nodes = next_level

    return nodes[0][:n]


# ---------------------------------------------------------------------------
# XMSS TreeHash
# ---------------------------------------------------------------------------


def xmss_TreeHash(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    s: int,
    z: int,
    n: int,
    wots_funcs: dict,
    params: dict,
) -> bytes:
    """Build an XMSS subtree and return the root node.

    This is the standard *TreeHash* algorithm from FIPS 205.  It constructs
    a binary Merkle tree of height *z* whose left-most leaf is at index *s*.
    Each leaf is the L-tree compression of a WOTS+ public key.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        ADRS identifying the XMSS tree.  Only the layer and tree_address
        fields are significant on entry; type / tree_height / tree_index are
        set internally.
    s:
        Start (left-most) leaf index of the subtree.
    z:
        Subtree height (number of levels above the leaves).
    n:
        Security parameter — hash output length in bytes.
    wots_funcs:
        WOTS+ callback dictionary with keys ``pkgen``, ``sign``,
        ``pkfromsig``.  Each callback receives ``(..., params)`` as its
        final argument.
    params:
        SLH-DSA parameter dictionary.

    Returns
    -------
    bytes
        *n*-byte root hash of the subtree.

    Reference
    ---------
    FIPS 205, Algorithm 9 (*treehash*).
    """
    if z == 0:
        # ----- Leaf: WOTS+ public key compressed via L-tree ----------------
        wots_adrs = adrs.copy()
        wots_adrs.type = ADRS.WOTS_PK
        wots_adrs.keypair_address = s

        pk_result = wots_funcs["pkgen"](SK_seed, PK_seed, wots_adrs, params)

        # pkgen may return either a single n-byte value or a list of elements
        if isinstance(pk_result, (list, tuple)):
            pk_elements = list(pk_result)
            ltree_adrs = adrs.copy()
            ltree_adrs.type = ADRS.TREE
            leaf = ltree(PK_seed, pk_elements, ltree_adrs, n)
        else:
            leaf = pk_result[:n]

        return leaf[:n]

    # ----- Internal node: hash left and right children -------------------
    left = xmss_TreeHash(
        SK_seed, PK_seed, adrs, s, z - 1, n, wots_funcs, params
    )
    right = xmss_TreeHash(
        SK_seed, PK_seed, adrs, s + (1 << (z - 1)), z - 1, n, wots_funcs, params
    )

    tree_adrs = adrs.copy()
    tree_adrs.type = ADRS.TREE
    tree_adrs.tree_height = z
    tree_adrs.hash_address = s // (1 << z)

    parent = hashing.H_slh(PK_seed, bytes(tree_adrs), left + right)
    return parent[:n]


# ---------------------------------------------------------------------------
# XMSS Public Key Generation
# ---------------------------------------------------------------------------


def xmss_PKGen(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    n: int,
    h_prime: int,
    wots_funcs: dict,
    params: dict,
) -> bytes:
    """Derive the XMSS public key — the root of the full XMSS tree.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        ADRS identifying the XMSS tree (layer + tree_address).
    n:
        Security parameter — hash output length in bytes.
    h_prime:
        Height of the XMSS tree (``h / d`` in SLH-DSA notation).  The tree
        contains ``2 ** h_prime`` leaves.
    wots_funcs:
        WOTS+ callback dictionary.
    params:
        SLH-DSA parameter dictionary.

    Returns
    -------
    bytes
        *n*-byte XMSS public key (Merkle root).

    Reference
    ---------
    FIPS 205, Algorithm 11 (*xmss_PKGen*).
    """
    return xmss_TreeHash(SK_seed, PK_seed, adrs, 0, h_prime, n, wots_funcs, params)


# ---------------------------------------------------------------------------
# XMSS Signature
# ---------------------------------------------------------------------------


def xmss_Sign(
    M: bytes,
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    idx: int,
    n: int,
    h_prime: int,
    wots_funcs: dict,
    params: dict,
) -> Tuple[List[bytes], List[bytes]]:
    """Sign a message digest with XMSS and produce the authentication path.

    The XMSS signature consists of:
    1. **WOTS+ one-time signature** (``sig_ots``) — ``len`` *n*-byte values.
    2. **Authentication path** (``auth``) — ``h_prime`` sibling node hashes,
       one per tree level on the path from leaf *idx* to the root.

    Parameters
    ----------
    M:
        *n*-byte message digest to sign.
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        ADRS identifying the XMSS tree (layer + tree_address).
    idx:
        Leaf index in ``[0, 2**h_prime - 1]`` to use for signing.
    n:
        Security parameter.
    h_prime:
        XMSS tree height (``h / d``).
    wots_funcs:
        WOTS+ callback dictionary.  Required keys:

        - ``'sign'`` — callable ``(M, SK_seed, PK_seed, adrs, params) -> List[bytes]``
        - ``'pkgen'`` — callable ``(SK_seed, PK_seed, adrs, params) -> Union[bytes, List[bytes]]``
        - ``'pkfromsig'`` — callable ``(sig_ots, M, PK_seed, adrs, params) -> Union[bytes, List[bytes]]``

    params:
        SLH-DSA parameter dictionary.

    Returns
    -------
    Tuple[List[bytes], List[bytes]]
        ``(sig_ots, auth)`` where *sig_ots* has ``len`` elements and *auth*
        has ``h_prime`` elements.

    Reference
    ---------
    FIPS 205, Algorithm 12 (*xmss_sign*).
    """
    # ---- 1. WOTS+ one-time signature ------------------------------------
    wots_adrs = adrs.copy()
    wots_adrs.type = ADRS.WOTS_HASH
    wots_adrs.keypair_address = idx

    sig_ots: List[bytes] = wots_funcs["sign"](M, SK_seed, PK_seed, wots_adrs, params)

    # ---- 2. Authentication path ----------------------------------------
    # For each level, compute the sibling subtree that is *not* on the
    # path from leaf ``idx`` to the root.  At level ``level`` the node
    # index is ``idx >> level``; the sibling node index is that value
    # xor 1.  The sibling subtree starts at leaf
    # ``(sibling_node_idx) << level`` and has height ``level``.
    auth: List[bytes] = []
    current_idx = idx

    for level in range(h_prime):
        sibling_node_idx = current_idx ^ 1
        s_aligned = sibling_node_idx << level
        node = xmss_TreeHash(
            SK_seed, PK_seed, adrs.copy(), s_aligned, level, n,
            wots_funcs, params,
        )
        auth.append(node[:n])
        current_idx //= 2

    return sig_ots, auth


# ---------------------------------------------------------------------------
# XMSS Public-Key Recovery from Signature
# ---------------------------------------------------------------------------


def xmss_PKFromSig(
    idx: int,
    sig_ots: List[bytes],
    auth: List[bytes],
    M: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    n: int,
    h_prime: int,
    wots_funcs: dict,
    params: dict,
) -> bytes:
    """Reconstruct the XMSS root from a signature for verification.

    Starting from the WOTS+ public key recovered via
    ``wots_funcs['pkfromsig']``, the function walks up the Merkle tree
    by repeatedly hashing the current node with the corresponding sibling
    from the authentication path.

    Parameters
    ----------
    idx:
        Leaf index that was used for signing.
    sig_ots:
        WOTS+ one-time signature — list of ``len`` *n*-byte values.
    auth:
        Authentication path — list of ``h_prime`` *n*-byte sibling hashes.
    M:
        Original *n*-byte message digest.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        ADRS identifying the XMSS tree.
    n:
        Security parameter.
    h_prime:
        XMSS tree height (``h / d``).
    wots_funcs:
        WOTS+ callback dictionary.  Required key:

        - ``'pkfromsig'`` — callable ``(sig_ots, M, PK_seed, adrs, params)
          -> Union[bytes, List[bytes]]``

    params:
        SLH-DSA parameter dictionary.

    Returns
    -------
    bytes
        *n*-byte reconstructed XMSS root.

    Reference
    ---------
    FIPS 205, Algorithm 13 (*xmss_pkFromSig*).
    """
    # ---- 1. Recover WOTS+ public key from signature ---------------------
    # Note: wots_PKFromSig internally sets adrs.type = WOTS_PK only for
    # the final T_l compression.  During chain recovery it expects the
    # same type (WOTS_HASH) that wots_Sign uses, otherwise F() sees a
    # different domain separator and produces divergent chain values.
    wots_adrs = adrs.copy()
    wots_adrs.type = ADRS.WOTS_HASH
    wots_adrs.keypair_address = idx

    pk_result = wots_funcs["pkfromsig"](sig_ots, M, PK_seed, wots_adrs, params)

    # pkfromsig may return a single n-byte value or a list of elements
    if isinstance(pk_result, (list, tuple)):
        ltree_adrs = adrs.copy()
        ltree_adrs.type = ADRS.TREE
        node = ltree(PK_seed, list(pk_result), ltree_adrs, n)
    else:
        node = pk_result[:n]

    # ---- 2. Hash up the tree using the auth path ------------------------
    current_idx = idx
    tree_adrs = adrs.copy()

    for level in range(h_prime):
        sibling = auth[level][:n]

        if (current_idx % 2) == 0:
            combined = node + sibling
        else:
            combined = sibling + node

        tree_adrs.type = ADRS.TREE
        tree_adrs.tree_height = level + 1
        tree_adrs.hash_address = current_idx // 2

        node = hashing.H_slh(PK_seed, bytes(tree_adrs), combined)[:n]
        current_idx //= 2

    return node
