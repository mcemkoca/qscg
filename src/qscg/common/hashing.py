"""NIST FIPS 203/204/205 hash functions with domain separation.

This module provides the cryptographic primitives used across the three
NIST post-quantum standards.  All functions are implemented on top of
Python's standard :mod:`hashlib` module using SHA3-256, SHA3-512, and
SHAKE-256 as specified in the standards.

Domain separation is achieved through distinct function names (G, H, J,
etc.) and through the explicit inclusion of address structures (ADRS) in
SLH-DSA invocations.
"""

import hashlib
from typing import Union

__all__ = [
    "G",
    "H",
    "J",
    "KDF",
    "PRF",
    "PRFmsg",
    "H_msg",
    "F",
    "H_slh",
    "T_l",
]


def G(d: bytes) -> bytes:
    """G hash function.

    SHA3-512 producing a 64-byte digest.  Used in ML-KEM for
    simultaneous generation of the public seed and a pseudorandom
    value during key-pair generation and encapsulation.

    Reference:
        FIPS 203, Section 4.4.

    Args:
        d: Input byte string.

    Returns:
        64-byte digest.
    """
    return hashlib.sha3_512(d).digest()


def H(d: bytes) -> bytes:
    """H hash function.

    SHA3-256 producing a 32-byte digest.  Used in ML-KEM for hashing
    the public key into the shared-secret derivation.

    Reference:
        FIPS 203, Section 4.4.

    Args:
        d: Input byte string.

    Returns:
        32-byte digest.
    """
    return hashlib.sha3_256(d).digest()


def J(s: bytes, n: int) -> bytes:
    """J extendable-output function (XOF).

    SHAKE-256 with an arbitrary-length output of *n* bytes.  Used in
    ML-KEM for pseudorandom generation of noise polynomials and
    rejection-sampling of field elements.

    Reference:
        FIPS 203, Section 4.4.

    Args:
        s: Input byte string.
        n: Number of output bytes required.

    Returns:
        *n*-byte output.
    """
    shake = hashlib.shake_256()
    shake.update(s)
    return shake.digest(n)


def KDF(s: bytes, n: int) -> bytes:
    """Key Derivation Function.

    A thin alias for :func:`J` used for explicit key-derivation
    contexts in ML-KEM (e.g. ``KDF(r || H(pk), 32)``).

    Reference:
        FIPS 203, Section 4.4.

    Args:
        s: Input byte string.
        n: Number of output bytes required.

    Returns:
        *n*-byte output.
    """
    return J(s, n)


def PRF(PK_seed: bytes, SK_seed: bytes, ADRS: bytes) -> bytes:
    """PRF for SLH-DSA secret key element derivation.

    Produces a pseudorandom *n*-byte value used to generate WOTS+ and
    FORS secret values.  The domain is separated by the ADRS (Address)
    structure.

    Reference:
        FIPS 205, Algorithm 14.

    Args:
        PK_seed: Public seed from SLH-DSA public key.
        SK_seed: Secret seed from SLH-DSA secret key.
        ADRS: 32-byte address structure encoding the tree position.

    Returns:
        32-byte pseudorandom output.
    """
    shake = hashlib.shake_256()
    shake.update(PK_seed + ADRS + SK_seed)
    return shake.digest(32)


def PRFmsg(SK_prf: bytes, opt_rand: bytes, M: bytes) -> bytes:
    """PRF for SLH-DSA signature randomisation.

    Generates the randomiser *R* used in the ``H_msg`` invocation
    inside the signing process.  ``opt_rand`` may be set to the public
    seed for deterministic signatures or to fresh randomness for
    hedged signatures.

    Reference:
        FIPS 205, Algorithm 16.

    Args:
        SK_prf: *n*-byte PRF key from the SLH-DSA secret key.
        opt_rand: *n*-byte optional random value.
        M: Message to be signed.

    Returns:
        32-byte randomiser *R*.
    """
    shake = hashlib.shake_256()
    shake.update(SK_prf + opt_rand + M)
    return shake.digest(32)


def H_msg(R: bytes, PK_seed: bytes, PK_root: bytes, M: bytes, n: int) -> bytes:
    """Message digest for SLH-DSA.

    Compresses the message into an *n*-byte digest that is then split
    into a FORS message digest and an index.

    Reference:
        FIPS 205, Algorithm 23.

    Args:
        R: *n*-byte randomiser from :func:`PRFmsg`.
        PK_seed: Public seed.
        PK_root: Merkle tree root (top-level XMSS public key).
        M: Message to be signed.
        n: Security parameter (output length in bytes).

    Returns:
        *n*-byte message digest.
    """
    shake = hashlib.shake_256()
    shake.update(R + PK_seed + PK_root + M)
    return shake.digest(n)


def F(PK_seed: bytes, ADRS: bytes, M: bytes) -> bytes:
    """F hash function for SLH-DSA WOTS+ chain.

    Computes the next value in a WOTS+ hash chain by hashing the
    current value together with the address and public seed.

    Reference:
        FIPS 205, Section 5.1.

    Args:
        PK_seed: Public seed.
        ADRS: 32-byte address structure.
        M: *n*-byte input to the chain iteration.

    Returns:
        32-byte chain output.
    """
    shake = hashlib.shake_256()
    shake.update(PK_seed + ADRS + M)
    return shake.digest(32)


def H_slh(PK_seed: bytes, ADRS: bytes, M: bytes) -> bytes:
    """H hash function for SLH-DSA internal hashing.

    Used inside the Merkle tree construction (L-tree and XMSS tree) to
    hash two child nodes together.

    Reference:
        FIPS 205, Section 5.1.

    Args:
        PK_seed: Public seed.
        ADRS: 32-byte address structure.
        M: Concatenation of two sibling *n*-byte node values.

    Returns:
        32-byte parent node digest.
    """
    shake = hashlib.shake_256()
    shake.update(PK_seed + ADRS + M)
    return shake.digest(32)


def T_l(PK_seed: bytes, ADRS: bytes, M: bytes) -> bytes:
    """T_l hash function for SLH-DSA L-tree.

    Compresses a WOTS+ public key (len1 + len2 elements) into a single
    *n*-byte leaf value for the XMSS tree.

    Reference:
        FIPS 205, Section 5.1.

    Args:
        PK_seed: Public seed.
        ADRS: 32-byte address structure for the L-tree.
        M: Serialized WOTS+ public key elements.

    Returns:
        32-byte L-tree root.
    """
    shake = hashlib.shake_256()
    shake.update(PK_seed + ADRS + M)
    return shake.digest(32)
