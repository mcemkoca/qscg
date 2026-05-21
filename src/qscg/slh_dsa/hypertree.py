"""Hypertree: Multi-layer XMSS tree (FIPS 205, Section 8).

A hypertree is a stack of *d* XMSS trees where the public key (root) of
each tree (except the top one) is authenticated by the tree above it.  This
enables stateless signing: each signature traverses all *d* layers, and the
OTS key at layer 0 signs the actual message digest while layers 1..d-1 each
sign the root of the tree below.

The XMSS layer is invoked through a *callbacks* dictionary so that this
module has no hard dependency on the ``xmss`` submodule.  All XMSS
functions receive ``params`` as their final argument.

Implemented routines
--------------------
- :func:`ht_PKGen` — Derive the hypertree public key (root of the top tree).
- :func:`ht_Sign` — Sign a message digest through all *d* hypertree layers.
- :func:`ht_Verify` — Verify a hypertree signature against the public key.

Usage example
-------------
>>> from qscg.slh_dsa.hypertree import ht_PKGen, ht_Sign, ht_Verify
>>> pk_root = ht_PKGen(sk_seed, pk_seed, params, xmss_funcs)
>>> sig_ht = ht_Sign(M, sk_seed, pk_seed, idx_tree, idx_leaf,
...                  params, xmss_funcs)
>>> assert ht_Verify(M, sig_ht, pk_seed, pk_root, params, xmss_funcs)

Reference
---------
- NIST FIPS 205, Section 8 — *Hypertree*.
"""

from __future__ import annotations

import math
from typing import List, Tuple

from .address import ADRS


# ---------------------------------------------------------------------------
# Hypertree public key generation
# ---------------------------------------------------------------------------


def ht_PKGen(
    SK_seed: bytes,
    PK_seed: bytes,
    params: dict,
    xmss_funcs: dict,
) -> bytes:
    """Derive the hypertree public key — the root of the top XMSS tree.

    The top XMSS tree lives at hypertree layer ``d - 1`` and has tree
    address ``0``.

    Parameters
    ----------
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    params:
        SLH-DSA parameter dictionary containing at least ``n``, ``h``,
        and ``d``.
    xmss_funcs:
        Dictionary with XMSS callbacks:

        - ``'pkgen'`` — callable ``(SK_seed, PK_seed, adrs, n, h_prime,
          wots_funcs, params) -> bytes`` — generates an XMSS public key.
        - ``'wots_pkgen'`` — callable ``(SK_seed, PK_seed, adrs, params)
          -> Union[bytes, List[bytes]]`` — WOTS+ public-key generation
          (passed down to XMSS).
        - ``'wots_sign'`` / ``'wots_pkfromsig'`` — WOTS+ callbacks
          (forwarded to XMSS).

    Returns
    -------
    bytes
        *n*-byte hypertree public key (top-level XMSS root).

    Reference
    ---------
    FIPS 205, Algorithm 17 (*ht_PKGen*).
    """
    n: int = params["n"]
    d: int = params["d"]
    h_prime: int = params["h"] // params["d"]

    adrs = ADRS()
    adrs.layer = d - 1  # Top layer
    adrs.tree_address = 0

    wots_funcs = _build_wots_funcs_dict(xmss_funcs)

    pk_root = xmss_funcs["pkgen"](
        SK_seed,
        PK_seed,
        adrs,
        n,
        h_prime,
        wots_funcs,
        params,
    )

    return pk_root[:n]


# ---------------------------------------------------------------------------
# Hypertree signature
# ---------------------------------------------------------------------------


def ht_Sign(
    M: bytes,
    SK_seed: bytes,
    PK_seed: bytes,
    idx_tree: int,
    idx_leaf: int,
    params: dict,
    xmss_funcs: dict,
) -> List[Tuple[List[bytes], List[bytes]]]:
    """Sign a message digest through the full hypertree.

    The algorithm traverses *d* XMSS layers:

    1. **Layer 0** — sign *M* with the XMSS tree at ``idx_tree`` using
       leaf ``idx_leaf``.
    2. **Layers 1 .. d-1** — sign the public-key root of the previous
       layer using the appropriate tree and leaf indices.

    The tree address at layer *j* is ``idx_tree >> (h_prime * j)``; the
    leaf index is ``idx_leaf`` at every layer (each XMSS tree has the same
    shape).

    Parameters
    ----------
    M:
        *n*-byte message digest (FORS public-key hash).
    SK_seed:
        *n*-byte secret-key seed.
    PK_seed:
        *n*-byte public-key seed.
    idx_tree:
        Tree index within layer 0 (derived from the randomised digest).
    idx_leaf:
        Leaf index within the selected XMSS tree.
    params:
        SLH-DSA parameter dictionary (``n``, ``h``, ``d``).
    xmss_funcs:
        Dictionary with XMSS callbacks:

        - ``'sign'`` — callable ``(M, SK_seed, PK_seed, adrs, idx, n,
          h_prime, wots_funcs, params) -> (sig_ots, auth)``.
        - ``'pkfromsig'`` — callable ``(idx, sig_ots, auth, M, PK_seed,
          adrs, n, h_prime, wots_funcs, params) -> bytes`` — XMSS root
          recovery.
        - ``'wots_pkgen'``, ``'wots_sign'``, ``'wots_pkfromsig'`` —
          WOTS+ callbacks forwarded to XMSS.

    Returns
    -------
    List[Tuple[List[bytes], List[bytes]]]
        ``sig_ht`` — a list of *d* XMSS signature tuples
        ``(sig_ots, auth)``.  Each *sig_ots* has ``len`` elements and each
        *auth* has ``h_prime`` elements.

    Reference
    ---------
    FIPS 205, Algorithm 18 (*ht_sign*).
    """
    n: int = params["n"]
    h: int = params["h"]
    d: int = params["d"]
    h_prime: int = h // d

    sig_ht: List[Tuple[List[bytes], List[bytes]]] = []
    wots_funcs = _build_wots_funcs_dict(xmss_funcs)

    adrs = ADRS()

    # ------------------------------------------------------------------
    # Layer 0: sign the message digest M
    # ------------------------------------------------------------------
    adrs.layer = 0
    adrs.tree_address = idx_tree

    sig_0, auth_0 = xmss_funcs["sign"](
        M, SK_seed, PK_seed, adrs, idx_leaf, n, h_prime,
        wots_funcs, params,
    )
    sig_ht.append((sig_0, auth_0))

    # Recover the PK of layer 0 so the next layer can sign it.
    pk_prev = xmss_funcs["pkfromsig"](
        idx_leaf,
        sig_0,
        auth_0,
        M,
        PK_seed,
        adrs.copy(),
        n,
        h_prime,
        wots_funcs,
        params,
    )
    pk_prev = pk_prev[:n]

    # ------------------------------------------------------------------
    # Layers 1 .. d-1: sign the PK of the previous layer
    # ------------------------------------------------------------------
    for layer in range(1, d):
        adrs.layer = layer
        adrs.tree_address = idx_tree >> (h_prime * layer)

        sig_l, auth_l = xmss_funcs["sign"](
            pk_prev,
            SK_seed,
            PK_seed,
            adrs,
            idx_leaf,
            n,
            h_prime,
            wots_funcs,
            params,
        )
        sig_ht.append((sig_l, auth_l))

        # Recover the PK (root) of this layer for the next iteration.
        pk_prev = xmss_funcs["pkfromsig"](
            idx_leaf,
            sig_l,
            auth_l,
            pk_prev,
            PK_seed,
            adrs.copy(),
            n,
            h_prime,
            wots_funcs,
            params,
        )
        pk_prev = pk_prev[:n]

    return sig_ht


# ---------------------------------------------------------------------------
# Hypertree verification
# ---------------------------------------------------------------------------


def ht_Verify(
    M: bytes,
    sig_ht: List[Tuple[List[bytes], List[bytes]]],
    PK_seed: bytes,
    PK_root: bytes,
    idx_tree: int,
    idx_leaf: int,
    params: dict,
    xmss_funcs: dict,
) -> bool:
    """Verify a hypertree signature.

    The verifier mirrors the signing traversal:

    1. Reconstruct the XMSS root at layer 0 from ``sig_ht[0]`` and *M*.
    2. For layers 1 .. d-1, reconstruct each root using the recovered
       root from the previous layer as the "message".
    3. Compare the final reconstructed root with *PK_root*.

    Parameters
    ----------
    M:
        *n*-byte message digest that was originally signed.
    sig_ht:
        Hypertree signature — list of *d* tuples ``(sig_ots, auth)``.
    PK_seed:
        *n*-byte public-key seed.
    PK_root:
        *n*-byte hypertree public key (expected top-level root).
    idx_tree:
        Tree index used during signing.
    idx_leaf:
        Leaf index used during signing.
    params:
        SLH-DSA parameter dictionary (``n``, ``h``, ``d``).
    xmss_funcs:
        Dictionary with XMSS callbacks:

        - ``'pkfromsig'`` — XMSS root recovery callable.

    Returns
    -------
    bool
        ``True`` if the signature is valid (reconstructed root equals
        *PK_root*), ``False`` otherwise.

    Reference
    ---------
    FIPS 205, Algorithm 19 (*ht_verify*).
    """
    n: int = params["n"]
    h: int = params["h"]
    d: int = params["d"]
    h_prime: int = h // d

    if len(sig_ht) != d:
        return False

    wots_funcs = _build_wots_funcs_dict(xmss_funcs)

    # ---- Layer 0 --------------------------------------------------------
    adrs = ADRS()
    adrs.layer = 0
    adrs.tree_address = idx_tree

    pk = xmss_funcs["pkfromsig"](
        idx_leaf,
        sig_ht[0][0],
        sig_ht[0][1],
        M,
        PK_seed,
        adrs.copy(),
        n,
        h_prime,
        wots_funcs,
        params,
    )
    pk = pk[:n]

    # ---- Layers 1 .. d-1 ------------------------------------------------
    for layer in range(1, d):
        adrs.layer = layer
        adrs.tree_address = idx_tree >> (h_prime * layer)

        pk = xmss_funcs["pkfromsig"](
            idx_leaf,
            sig_ht[layer][0],
            sig_ht[layer][1],
            pk,
            PK_seed,
            adrs.copy(),
            n,
            h_prime,
            wots_funcs,
            params,
        )
        pk = pk[:n]

    # ---- Final comparison -----------------------------------------------
    return pk == PK_root[:n]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _build_wots_funcs_dict(xmss_funcs: dict) -> dict:
    """Build a WOTS+ functions dict for passing to the XMSS layer.

    The XMSS layer expects a flat dict with keys ``pkgen``, ``sign``,
    and ``pkfromsig`` pointing to the corresponding WOTS+ implementations.
    This helper extracts or maps those from the broader *xmss_funcs* dict
    that the hypertree layer receives.

    Parameters
    ----------
    xmss_funcs:
        Dictionary that may contain WOTS+ function references under keys
        ``wots_pkgen``, ``wots_sign``, ``wots_pkfromsig`` or directly as
        ``pkgen``, ``sign``, ``pkfromsig``.

    Returns
    -------
    dict
        WOTS+ functions dict suitable for the XMSS layer.
    """
    wots_dict: dict = {}

    if "wots_pkgen" in xmss_funcs:
        wots_dict["pkgen"] = xmss_funcs["wots_pkgen"]
    elif "pkgen" in xmss_funcs and xmss_funcs["pkgen"] != xmss_funcs.get("sign"):
        # Heuristic: if pkgen is different from sign, it's a WOTS+ pkgen
        wots_dict["pkgen"] = xmss_funcs["pkgen"]

    if "wots_sign" in xmss_funcs:
        wots_dict["sign"] = xmss_funcs["wots_sign"]
    elif "sign" in xmss_funcs and "wots_pkgen" not in xmss_funcs:
        wots_dict["sign"] = xmss_funcs["sign"]

    if "wots_pkfromsig" in xmss_funcs:
        wots_dict["pkfromsig"] = xmss_funcs["wots_pkfromsig"]
    elif "pkfromsig" in xmss_funcs and "wots_pkgen" not in xmss_funcs:
        wots_dict["pkfromsig"] = xmss_funcs["pkfromsig"]

    return wots_dict
