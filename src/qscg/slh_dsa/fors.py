"""FORS: Forest of Random Subsets (FIPS 205, Section 6).

FORS is a hash-based few-time signature scheme that uses *k* independent
Merkle trees each of height *a*.  It provides message-digest compression
for SLH-DSA: a message digest is split into *k* indices, each selecting a
leaf in one of the *k* trees.  The signature reveals the secret-key
elements at those leaves together with their Merkle authentication paths.

Public-domain reference implementations
---------------------------------------
- :func:`fors_SKGen` — secret-key element derivation.
- :func:`fors_TreeHash` — Merkle-tree root computation.
- :func:`fors_PKGen` — FORS public-key generation.
- :func:`fors_Sign` — signature generation.
- :func:`fors_PKFromSig` — public-key recovery from a signature.

Helper routines
---------------
- :func:`_md_to_indices` — split a message digest into *k* *a*-bit indices.
- :func:`_get_tree_node` — retrieve an arbitrary Merkle-tree node by index.

FORS parameter sets (SLH-DSA)
-----------------------------
+----------+------+------+------+--------+------------------------+
| Variant  |  n   |  a   |  k   | t=2^a  | sig_fors size (bytes)  |
+==========+======+======+======+========+========================+
| SHA2-128f|  16  |   6  |  33  |   64   |  k*(n + a*n) = 3564    |
| SHA2-128s|  16  |  12  |  14  | 4096   |  k*(n + a*n) = 2912    |
| SHA2-192f|  24  |   8  |  33  |  256   |  k*(n + a*n) = 7128    |
| SHA2-192s|  24  |  14  |  17  | 16384  |  k*(n + a*n) = 6120    |
| SHA2-256f|  32  |   9  |  35  |  512   |  k*(n + a*n) = 11200   |
| SHA2-256s|  32  |  14  |  22  | 16384  |  k*(n + a*n) = 7920    |
| SHAKE-128f|  16  |   6  |  33  |   64   |  k*(n + a*n) = 3564    |
| SHAKE-256f|  32  |   9  |  35  |  512   |  k*(n + a*n) = 11200   |
+----------+------+------+------+--------+------------------------+

References
----------
- NIST FIPS 205, Section 6 — *FORS*.
- SPHINCS+ specification, version 3.1.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

from ..common import hashing
from .address import ADRS

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

__all__ = [
    "fors_SKGen",
    "fors_TreeHash",
    "fors_PKGen",
    "fors_Sign",
    "fors_PKFromSig",
]


# ---------------------------------------------------------------------------
# FORS secret-key generation (FIPS 205, Algorithm 12)
# ---------------------------------------------------------------------------


def fors_SKGen(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    idx: int,
    n: int,
) -> bytes:
    """Generate a single FORS secret-key element (FIPS 205, Algorithm 12).

    The secret-key element is derived by evaluating the pseudorandom
    function :func:`~qscg.common.hashing.PRF` with the address set to
    ``FORS_TREE`` type and *idx* encoded in ``keypair_address``.  The
    PRF produces 32 bytes; the result is truncated to *n* bytes to
    match the security parameter.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure identifying the tree position.  The ``type``
        and ``keypair_address`` fields are updated in place before the
        PRF call.
    idx:
        FORS secret-key index.  Within a single tree this is the leaf
        index in ``[0, 2**a)``.
    n:
        Hash output length in bytes (security parameter).

    Returns
    -------
    bytes
        *n*-byte secret-key element.

    Raises
    ------
    TypeError
        If *adrs* is not an :class:`~qscg.slh_dsa.address.ADRS` instance.

    Examples
    --------
    >>> from qscg.slh_dsa.address import ADRS
    >>> adrs = ADRS()
    >>> adrs.layer = 0
    >>> adrs.tree_address = 0
    >>> sk = fors_SKGen(b'\\x00' * 16, b'\\x01' * 16, adrs, 0, 16)
    >>> len(sk)
    16
    """
    if not isinstance(adrs, ADRS):
        raise TypeError(f"adrs must be ADRS, got {type(adrs).__name__}")

    # Domain-separate as FORS_TREE and encode the element index
    adrs.type = ADRS.FORS_TREE
    adrs.keypair_address = idx

    # The remaining address words are zero for SKgen (chain/hash = 0)
    adrs.chain_address = 0
    adrs.hash_address = 0

    # PRF produces 32 bytes; truncate to n bytes
    sk: bytes = hashing.PRF(PK_seed, SK_seed, bytes(adrs))
    return sk[:n]


# ---------------------------------------------------------------------------
# FORS Merkle-tree hash (FIPS 205, Algorithm 13)
# ---------------------------------------------------------------------------


def fors_TreeHash(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    s: int,
    z: int,
    n: int,
    a: int,
) -> bytes:
    """Compute the root of a FORS Merkle subtree (FIPS 205, Algorithm 13).

    Recursively hashes a contiguous block of ``2**z`` leaf nodes starting
    at leaf index *s*.  The base case (*z* == 0) derives the leaf from
    the secret key via :func:`fors_SKGen` and applies the tweakable hash
    function :func:`~qscg.common.hashing.F`.  Internal nodes use
    :func:`~qscg.common.hashing.H_slh` on the concatenation of the two
    child digests.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure.  A copy is used for each recursive call so
        that the caller's object is not mutated.
    s:
        Start leaf index within the current FORS tree (inclusive).
    z:
        Target height of the subtree (0 means a single leaf).
    n:
        Hash output length in bytes (security parameter).
    a:
        Height of a single FORS tree (each tree has ``2**a`` leaves).

    Returns
    -------
    bytes
        *n*-byte subtree root digest.

    Notes
    -----
    * The ``tree_index`` address field encodes the node position at each
      height.  For height 0 it equals the leaf index *s*; for height
      *z* > 0 it equals ``s // (2**z)``.
    * The ``tree_height`` address field stores the current height *z*.
    """
    if z == 0:
        # Base case: leaf node
        leaf_adrs: ADRS = adrs.copy()

        # Derive the secret-key element at leaf position s
        sk: bytes = fors_SKGen(SK_seed, PK_seed, leaf_adrs.copy(), s, n)

        # Tweakable hash F for leaf compression
        leaf_adrs.type = ADRS.FORS_TREE
        leaf_adrs.tree_height = 0
        leaf_adrs.tree_index = s
        leaf_hash: bytes = hashing.F(PK_seed, bytes(leaf_adrs), sk)
        return leaf_hash[:n]

    # Recursive case: internal node — hash two children
    half: int = 1 << (z - 1)

    left: bytes = fors_TreeHash(SK_seed, PK_seed, adrs.copy(), s, z - 1, n, a)
    right: bytes = fors_TreeHash(
        SK_seed, PK_seed, adrs.copy(), s + half, z - 1, n, a
    )

    # Address for the parent node at height z
    parent_adrs: ADRS = adrs.copy()
    parent_adrs.type = ADRS.FORS_TREE
    parent_adrs.tree_height = z
    parent_adrs.tree_index = s // (1 << z)

    return hashing.H_slh(PK_seed, bytes(parent_adrs), left + right)[:n]


# ---------------------------------------------------------------------------
# FORS public-key generation (FIPS 205, Algorithm 14)
# ---------------------------------------------------------------------------


def fors_PKGen(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: Dict[str, int],
) -> bytes:
    """Generate the FORS public key (FIPS 205, Algorithm 14).

    Computes the roots of the *k* individual FORS Merkle trees and
    compresses them with :func:`~qscg.common.hashing.T_l` into a single
    *n*-byte public key.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure (``layer`` and ``tree_address`` must already
        be set by the caller).
    params:
        SLH-DSA parameter dictionary containing at least the keys
        ``'n'``, ``'a'``, and ``'k'``.

    Returns
    -------
    bytes
        *n*-byte FORS public-key digest.

    Notes
    -----
    Each tree root is computed over the full height *a* with the tree
    index encoded in ``keypair_address``.  The final
    :func:`~qscg.common.hashing.T_l` invocation uses ``ADRS.FORS_ROOTS``
    as the address type.
    """
    n: int = params["n"]
    a: int = params["a"]
    k: int = params["k"]

    # Collect the k tree roots
    roots: List[bytes] = []

    for tree_idx in range(k):
        tree_adrs: ADRS = adrs.copy()
        tree_adrs.keypair_address = tree_idx
        root: bytes = fors_TreeHash(SK_seed, PK_seed, tree_adrs, 0, a, n, a)
        roots.append(root)

    # Compress all roots into the final FORS public key
    fors_adrs: ADRS = adrs.copy()
    fors_adrs.type = ADRS.FORS_ROOTS

    pk: bytes = hashing.T_l(PK_seed, bytes(fors_adrs), b"".join(roots))
    return pk[:n]


# ---------------------------------------------------------------------------
# FORS sign (FIPS 205, Algorithm 15)
# ---------------------------------------------------------------------------


def fors_Sign(
    md: bytes,
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: Dict[str, int],
) -> Tuple[List[bytes], List[List[bytes]]]:
    """Generate a FORS signature (FIPS 205, Algorithm 15).

    The message digest *md* is split into *k* *a*-bit indices.  For each
    tree *i* the signature contains:

    1. The secret-key element at the selected leaf (``sig_fors[i]``).
    2. The Merkle authentication path from that leaf to the tree root
       (``auth_paths[i]``, a list of *a* sibling digests).

    Parameters
    ----------
    md:
        Message digest — exactly ``ceil(k * a / 8)`` bytes.
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure identifying the hypertree leaf position.
    params:
        SLH-DSA parameter dictionary with keys ``'n'``, ``'a'``, ``'k'``.

    Returns
    -------
    Tuple[List[bytes], List[List[bytes]]]
        A pair ``(sig_fors, auth_paths)`` where:

        * ``sig_fors`` — list of *k* secret-key elements (each *n* bytes).
        * ``auth_paths`` — list of *k* authentication paths; each path is
          a list of *a* sibling node digests (each *n* bytes).

    Notes
    -----
    The signature size is ``k * (n + a * n)`` bytes.  FORS is a
    *few-time* signature scheme: the same key pair must **not** be used
    for more than a small number of messages (determined by the
    parameter set).
    """
    n: int = params["n"]
    a: int = params["a"]
    k: int = params["k"]

    # Step 1: split digest into k indices
    indices: List[int] = _md_to_indices(md, k, a)

    sig_fors: List[bytes] = []
    auth_paths: List[List[bytes]] = []

    for tree_idx in range(k):
        leaf_idx: int = indices[tree_idx]

        # Secret-key element at the selected leaf.
        # The leaf index within the tree (0..2^a-1) is used to ensure
        # consistency with fors_TreeHash which indexes leaves the same way.
        sk_element: bytes = fors_SKGen(SK_seed, PK_seed, adrs.copy(), leaf_idx, n)
        sig_fors.append(sk_element)

        # Authentication path: sibling at each level
        path: List[bytes] = []
        current_idx: int = leaf_idx

        for level in range(a):
            sibling_idx: int = current_idx ^ 1
            sibling_hash: bytes = _get_tree_node(
                SK_seed, PK_seed, adrs.copy(),
                tree_idx, sibling_idx, level, n, a,
            )
            path.append(sibling_hash[:n])
            current_idx //= 2

        auth_paths.append(path)

    return sig_fors, auth_paths


# ---------------------------------------------------------------------------
# FORS public-key recovery from signature (FIPS 205, Algorithm 16)
# ---------------------------------------------------------------------------


def fors_PKFromSig(
    sig_fors: List[bytes],
    auth_paths: List[List[bytes]],
    md: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    params: Dict[str, int],
) -> bytes:
    """Recover the FORS public key from a signature (FIPS 205, Algorithm 16).

    Reconstructs each of the *k* tree roots by starting with the revealed
    secret-key element and hashing upwards using the authentication path.
    The recovered roots are then compressed with
    :func:`~qscg.common.hashing.T_l` to yield the public-key digest.

    Verification succeeds when the recovered public key matches the
    expected value (the caller performs the comparison).

    Parameters
    ----------
    sig_fors:
        List of *k* secret-key elements (each *n* bytes) from the
        signature.
    auth_paths:
        List of *k* authentication paths; each path contains *a* sibling
        digests.
    md:
        Original message digest.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure used during signing.
    params:
        SLH-DSA parameter dictionary with keys ``'n'``, ``'a'``, ``'k'``.

    Returns
    -------
    bytes
        *n*-byte recovered FORS public-key digest.

    Raises
    ------
    ValueError
        If the input lengths do not match the parameters.
    """
    n: int = params["n"]
    a: int = params["a"]
    k: int = params["k"]

    if len(sig_fors) != k:
        raise ValueError(
            f"sig_fors length mismatch: expected {k}, got {len(sig_fors)}"
        )
    if len(auth_paths) != k:
        raise ValueError(
            f"auth_paths length mismatch: expected {k}, got {len(auth_paths)}"
        )

    # Re-derive the k indices
    indices: List[int] = _md_to_indices(md, k, a)

    roots: List[bytes] = []

    for tree_idx in range(k):
        leaf_idx: int = indices[tree_idx]

        # Start with the revealed secret-key element hashed as a leaf.
        # The keypair_address must match the tree index used during PKGen
        # so that the tweakable hash F sees the same ADRS on both sides.
        node_adrs: ADRS = adrs.copy()
        node_adrs.type = ADRS.FORS_TREE
        node_adrs.keypair_address = tree_idx
        node_adrs.tree_height = 0
        node_adrs.tree_index = leaf_idx
        node: bytes = hashing.F(PK_seed, bytes(node_adrs), sig_fors[tree_idx])[:n]

        # Hash up the tree using the authentication path
        current_idx: int = leaf_idx
        for level in range(a):
            sibling: bytes = auth_paths[tree_idx][level]

            # Order matters: left child first, then right child
            if current_idx % 2 == 0:
                combined: bytes = node + sibling
            else:
                combined = sibling + node

            parent_adrs: ADRS = adrs.copy()
            parent_adrs.type = ADRS.FORS_TREE
            parent_adrs.keypair_address = tree_idx
            parent_adrs.tree_height = level + 1
            parent_adrs.tree_index = current_idx // 2
            node = hashing.H_slh(PK_seed, bytes(parent_adrs), combined)[:n]

            current_idx //= 2

        roots.append(node)

    # Compress roots into the final public key
    fors_adrs: ADRS = adrs.copy()
    fors_adrs.type = ADRS.FORS_ROOTS

    pk: bytes = hashing.T_l(PK_seed, bytes(fors_adrs), b"".join(roots))
    return pk[:n]


# ---------------------------------------------------------------------------
# Helper: message-digest to index vector
# ---------------------------------------------------------------------------


def _md_to_indices(md: bytes, k: int, a: int) -> List[int]:
    """Split a message digest into *k* indices of *a* bits each.

    The digest is treated as a big-endian bit string.  The first *a*
    bits form index 0, the next *a* bits form index 1, and so on.
    Each index is therefore in the range ``[0, 2**a)``.

    Parameters
    ----------
    md:
        Message digest byte string.  Must contain at least
        ``ceil(k * a / 8)`` bytes.
    k:
        Number of FORS trees (and thus indices to extract).
    a:
        Bit-width of each index (height of each FORS tree).

    Returns
    -------
    List[int]
        List of *k* integer indices.

    Examples
    --------
    >>> _md_to_indices(b'\xff\xff', 4, 4)
    [15, 15, 15, 15]
    >>> _md_to_indices(b'\x00\x00', 4, 4)
    [0, 0, 0, 0]
    >>> _md_to_indices(b'\x12\x34', 2, 8)
    [18, 52]
    """
    total_bits: int = k * a
    byte_len: int = (total_bits + 7) // 8

    # Convert digest to a flat list of bits (MSB first)
    bits: List[int] = []
    for i in range(byte_len):
        byte: int = md[i] if i < len(md) else 0
        for shift in range(7, -1, -1):
            bits.append((byte >> shift) & 1)

    # Slice the bit string into k chunks of a bits each
    indices: List[int] = []
    for i in range(k):
        start: int = i * a
        idx: int = 0
        for j in range(a):
            idx = (idx << 1) | bits[start + j]
        indices.append(idx)

    return indices


# ---------------------------------------------------------------------------
# Helper: retrieve an arbitrary Merkle-tree node by index and height
# ---------------------------------------------------------------------------


def _get_tree_node(
    SK_seed: bytes,
    PK_seed: bytes,
    adrs: ADRS,
    tree_idx: int,
    node_idx: int,
    height: int,
    n: int,
    a: int,
) -> bytes:
    """Recursively compute the hash of a specific FORS tree node.

    This is a convenience helper used by :func:`fors_Sign` to build
    authentication paths.  It is **not** part of the FIPS 205 pseudocode
    but follows the same logic as :func:`fors_TreeHash` with a targeted
    index rather than a contiguous range.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    adrs:
        Address structure.  A copy is used internally.
    tree_idx:
        FORS tree index in ``[0, k)``.
    node_idx:
        Node index within the tree at the requested *height*.
    height:
        Height of the target node (0 = leaf, *a* = root).
    n:
        Hash output length in bytes.
    a:
        Height of a single FORS tree.

    Returns
    -------
    bytes
        *n*-byte node digest.
    """
    adrs.keypair_address = tree_idx

    if height == 0:
        # Leaf: derive secret key and apply F
        sk: bytes = fors_SKGen(SK_seed, PK_seed, adrs.copy(), node_idx, n)

        leaf_adrs: ADRS = adrs.copy()
        leaf_adrs.type = ADRS.FORS_TREE
        leaf_adrs.tree_height = 0
        leaf_adrs.tree_index = node_idx
        return hashing.F(PK_seed, bytes(leaf_adrs), sk)[:n]

    # Internal node: recurse on children and hash with H
    left: bytes = _get_tree_node(
        SK_seed, PK_seed, adrs.copy(), tree_idx, node_idx * 2, height - 1, n, a
    )
    right: bytes = _get_tree_node(
        SK_seed, PK_seed, adrs.copy(), tree_idx, node_idx * 2 + 1, height - 1, n, a
    )

    parent_adrs: ADRS = adrs.copy()
    parent_adrs.type = ADRS.FORS_TREE
    parent_adrs.tree_height = height
    parent_adrs.tree_index = node_idx
    return hashing.H_slh(PK_seed, bytes(parent_adrs), left + right)[:n]
