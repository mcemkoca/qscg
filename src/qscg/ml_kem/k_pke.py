"""K-PKE component of ML-KEM (FIPS 203, Section 5.1).

K-PKE provides the underlying IND-CPA secure public-key encryption that is
converted to an IND-CCA2 secure KEM via the Fujisaki--Okamoto transform
implemented in :mod:`qscg.ml_kem.ml_kem`.

This module implements three algorithms from FIPS 203:

  * :func:`K_PKE_KeyGen`   — Algorithm 12
  * :func:`K_PKE_Encrypt`  — Algorithm 13
  * :func:`K_PKE_Decrypt`  — Algorithm 14

All algorithms are parameterized by a :class:`~qscg.common.constants.SecurityLevel`
and follow the NIST specification exactly.

Example::

    >>> from qscg.common.constants import SecurityLevel
    >>> from qscg.common.utilities import generate_random_bytes
    >>> from qscg.ml_kem.k_pke import K_PKE_KeyGen, K_PKE_Encrypt, K_PKE_Decrypt
    >>> d = generate_random_bytes(32)
    >>> ek, dk = K_PKE_KeyGen(d, SecurityLevel.LEVEL_1)
    >>> m = generate_random_bytes(32)
    >>> r = generate_random_bytes(32)
    >>> c = K_PKE_Encrypt(ek, m, r, SecurityLevel.LEVEL_1)
    >>> m_prime = K_PKE_Decrypt(dk, c, SecurityLevel.LEVEL_1)
    >>> m_prime == m
    True

References:
    - NIST FIPS 203, Section 5.1 — K-PKE Component
"""

from typing import Tuple, List

from ..common.constants import SecurityLevel, MLKEM_PARAMS, MLKEM_Q, MLKEM_N
from ..common.hashing import G
from . import sampling
from . import encode
from . import ntt

Q: int = MLKEM_Q
"""Modulus :math:`q = 3329`."""

N: int = MLKEM_N
"""Polynomial degree :math:`n = 256`."""

# ByteEncode with d=12 produces 384 bytes per polynomial.
_BYTES_PER_POLY_12: int = (N * 12 + 7) // 8  # 384


def _canonical_coeffs(coeffs: List[int]) -> List[int]:
    """Map possibly-negative coefficients into canonical ``[0, q-1]``.

    CBD produces values in ``[-eta, eta]``.  Before any NTT call they must
    be reduced into the standard representative range.

    Args:
        coeffs: List of integer coefficients (may be negative).

    Returns:
        List of coefficients modulo *q* in ``[0, q-1]``.
    """
    return [(c % Q) for c in coeffs]


def _ntt_vec(vec_coeffs: List[List[int]]) -> List[List[int]]:
    """NTT-transform every polynomial in a vector.

    Args:
        vec_coeffs: List of *k* coefficient lists (each length 256).

    Returns:
        List of *k* NTT-domain coefficient lists.
    """
    return [ntt.ntt(_canonical_coeffs(c)) for c in vec_coeffs]


def _intt_vec(vec_ntt: List[List[int]]) -> List[List[int]]:
    """Inverse-NTT every polynomial in a vector.

    Args:
        vec_ntt: List of *k* NTT-domain coefficient lists.

    Returns:
        List of *k* plain coefficient lists.
    """
    return [ntt.ntt_inv(c) for c in vec_ntt]


# ============================================================================
# K-PKE.KeyGen (FIPS 203, Algorithm 12)
# ============================================================================


def K_PKE_KeyGen(d: bytes, level: SecurityLevel) -> Tuple[bytes, bytes]:
    """K-PKE.KeyGen: Generate encryption key pair.

    Algorithm 12 from FIPS 203.

    Steps (paraphrased from the standard)::

        1. (rho, sigma) = G(d || k)                # k encoded as one byte
        2. A_hat = SampleNTT(rho, k)                # k×k NTT-domain matrix
        3. s = CBD(sigma, eta1)   (k polynomials)
           e = CBD(sigma, eta2)   (k polynomials)
        4. s_hat = NTT(s)    (coeff → NTT)
           e_hat = NTT(e)
        5. t_hat = A_hat @ s_hat + e_hat   (all in NTT domain)
        6. ek = ByteEncode(t_hat, 12) || rho
        7. dk = ByteEncode(s_hat, 12)

    .. note::
        Step 7 in the specification writes *dk = ByteEncode(s_hat, 12)*.
        The NIST reference implementations and the Round-3 Kyber submission
        both encode ``s_hat`` (the NTT-domain secret) rather than the plain
        ``s``.  Decrypt reconstructs ``s`` from ``s_hat`` by inverse-NTT.

    Args:
        d: 32-byte random seed.
        level: ML-KEM security level (determines *k*, *eta1*, *eta2*).

    Returns:
        Tuple ``(ek, dk)`` where:

          - ``ek`` is the encryption key (``384*k + 32`` bytes).
          - ``dk`` is the decryption key (``384*k`` bytes).

    Raises:
        ValueError: If *d* is not exactly 32 bytes.
    """
    if len(d) != 32:
        raise ValueError(f"K_PKE_KeyGen: d must be 32 bytes, got {len(d)}")

    params = MLKEM_PARAMS[level]
    k: int = params["k"]
    eta1: int = params["eta1"]
    eta2: int = params["eta2"]

    # Step 1: Expand seed with domain separation
    g_input: bytes = d + bytes([k])
    g_out: bytes = G(g_input)
    rho: bytes = g_out[:32]
    sigma: bytes = g_out[32:64]

    # Step 2: Generate A matrix (already in NTT domain)
    A_hat: List[List[List[int]]] = sampling.generate_matrix_A(rho, k)

    # Step 3: Sample secret s and error e (coefficient domain, centred reps)
    s_coeffs: List[List[int]] = sampling.sample_vector_s(sigma, eta1, k)
    e_coeffs: List[List[int]] = sampling.sample_vector_e(sigma, eta2, k)

    # Step 4: Convert to canonical reps and NTT
    s_hat: List[List[int]] = _ntt_vec(s_coeffs)
    e_hat: List[List[int]] = _ntt_vec(e_coeffs)

    # Step 5: t_hat = A_hat @ s_hat + e_hat  (NTT domain matrix-vector mult)
    t_hat: List[List[int]] = []
    for i in range(k):
        # Compute row i:  Σ_j A_hat[i][j] * s_hat[j]  in NTT domain
        row_sum: List[int] = ntt.ntt_zero()
        for j in range(k):
            prod: List[int] = ntt.ntt_multiply(A_hat[i][j], s_hat[j])
            row_sum = ntt.ntt_add(row_sum, prod)
        # Add e_hat[i]
        row_sum = ntt.ntt_add(row_sum, e_hat[i])
        t_hat.append(row_sum)

    # Step 6: Encode encryption key: ByteEncode(t_hat, 12) || rho
    ek_bytes: bytearray = bytearray()
    for i in range(k):
        # t_hat[i] is NTT-domain; encode directly as 12-bit values
        ek_bytes.extend(encode.ByteEncode(t_hat[i], 12))
    ek_bytes.extend(rho)

    # Step 7: Encode decryption key: ByteEncode(s_hat, 12)
    dk_bytes: bytearray = bytearray()
    for j in range(k):
        dk_bytes.extend(encode.ByteEncode(s_hat[j], 12))

    return bytes(ek_bytes), bytes(dk_bytes)


# ============================================================================
# K-PKE.Encrypt (FIPS 203, Algorithm 13)
# ============================================================================


def K_PKE_Encrypt(ek: bytes, m: bytes, r: bytes, level: SecurityLevel) -> bytes:
    """K-PKE.Encrypt: Encrypt a 32-byte message.

    Algorithm 13 from FIPS 203.

    Steps::

        1. Parse ek  →  t_hat (k polys, d=12)  ||  rho (32 B)
        2. A_hat = SampleNTT(rho, k)
        3. rr = CBD(r, eta1)  (k polys)
           e1 = CBD(r, eta2)  (k polys)
           e2 = CBD(r, eta2)  (1 poly)
        4. rr_hat = NTT(rr)
        5. u = NTT_inv(A_hat^T @ rr_hat) + e1
        6. v = NTT_inv(t_hat^T @ rr_hat) + e2 + Decompress_q(ByteDecode(m,1),1)
        7. c1 = ByteEncode(Compress_q(u, du))
        8. c2 = ByteEncode(Compress_q(v, dv))

    Args:
        ek: Encryption key (``384*k + 32`` bytes).
        m: 32-byte message.
        r: 32-byte randomness seed.
        level: ML-KEM security level.

    Returns:
        Ciphertext ``c1 || c2`` where:

          - ``c1`` is ``32*du*k`` bytes (compressed *u* vector).
          - ``c2`` is ``32*dv`` bytes (compressed *v* scalar).

    Raises:
        ValueError: If *m* or *r* are not exactly 32 bytes, or if *ek* has
            an unexpected length.
    """
    if len(m) != 32:
        raise ValueError(f"K_PKE_Encrypt: m must be 32 bytes, got {len(m)}")
    if len(r) != 32:
        raise ValueError(f"K_PKE_Encrypt: r must be 32 bytes, got {len(r)}")

    params = MLKEM_PARAMS[level]
    k: int = params["k"]
    eta1: int = params["eta1"]
    eta2: int = params["eta2"]
    du: int = params["du"]
    dv: int = params["dv"]

    expected_ek_len: int = k * _BYTES_PER_POLY_12 + 32
    if len(ek) != expected_ek_len:
        raise ValueError(
            f"K_PKE_Encrypt: ek length mismatch for {level.name}: "
            f"expected {expected_ek_len}, got {len(ek)}"
        )

    # ------------------------------------------------------------------
    # Step 1: Parse ek into t_hat and rho
    # ------------------------------------------------------------------
    t_hat_bytes: bytes = ek[: k * _BYTES_PER_POLY_12]
    rho: bytes = ek[k * _BYTES_PER_POLY_12 : k * _BYTES_PER_POLY_12 + 32]

    # Decode t_hat (NTT-domain polynomials, encoded with d=12)
    t_hat: List[List[int]] = []
    for i in range(k):
        start: int = i * _BYTES_PER_POLY_12
        coeffs: List[int] = encode.ByteDecode(
            t_hat_bytes[start : start + _BYTES_PER_POLY_12], 12
        )
        t_hat.append(coeffs)

    # ------------------------------------------------------------------
    # Step 2: Generate A matrix in NTT domain
    # ------------------------------------------------------------------
    A_hat: List[List[List[int]]] = sampling.generate_matrix_A(rho, k)

    # ------------------------------------------------------------------
    # Step 3: Sample rr, e1, e2
    # ------------------------------------------------------------------
    rr_coeffs: List[List[int]] = sampling.sample_vector_s(r, eta1, k)
    e1_coeffs: List[List[int]] = sampling.sample_vector_e(r, eta2, k)
    e2_coeffs: List[List[int]] = sampling.sample_vector_e(r, eta2, 1)
    e2_plain: List[int] = _canonical_coeffs(e2_coeffs[0])

    # ------------------------------------------------------------------
    # Step 4: NTT(rr)
    # ------------------------------------------------------------------
    rr_hat: List[List[int]] = _ntt_vec(rr_coeffs)

    # ------------------------------------------------------------------
    # Step 5: u = NTT_inv(A_hat^T @ rr_hat) + e1  (coefficient domain)
    # ------------------------------------------------------------------
    u_ntt: List[List[int]] = []
    for i in range(k):
        # A_hat^T means we use A_hat[j][i] (column i of A_hat)
        col_sum: List[int] = ntt.ntt_zero()
        for j in range(k):
            prod = ntt.ntt_multiply(A_hat[j][i], rr_hat[j])
            col_sum = ntt.ntt_add(col_sum, prod)
        u_ntt.append(col_sum)

    # Inverse NTT to coefficient domain, then add e1
    u_plain: List[List[int]] = _intt_vec(u_ntt)
    for i in range(k):
        e1_canon: List[int] = _canonical_coeffs(e1_coeffs[i])
        u_plain[i] = [(u_plain[i][idx] + e1_canon[idx]) % Q for idx in range(N)]

    # ------------------------------------------------------------------
    # Step 6: v = NTT_inv(t_hat^T @ rr_hat) + e2 + Decompress_q(m)
    # ------------------------------------------------------------------
    v_ntt_acc: List[int] = ntt.ntt_zero()
    for j in range(k):
        prod = ntt.ntt_multiply(t_hat[j], rr_hat[j])
        v_ntt_acc = ntt.ntt_add(v_ntt_acc, prod)

    v_plain: List[int] = ntt.ntt_inv(v_ntt_acc)
    # Add e2
    v_plain = [(v_plain[idx] + e2_plain[idx]) % Q for idx in range(N)]

    # Decode m and decompress
    m_coeffs: List[int] = encode.ByteDecode(m, 1)
    m_decompressed: List[int] = [encode.Decompress(c, 1) for c in m_coeffs]

    # v = v + m_decompressed
    v_plain = [(v_plain[idx] + m_decompressed[idx]) % Q for idx in range(N)]

    # ------------------------------------------------------------------
    # Steps 7 & 8: Compress and encode u and v
    # ------------------------------------------------------------------
    c1: bytearray = bytearray()
    for i in range(k):
        u_compressed: List[int] = [encode.Compress(c, du) for c in u_plain[i]]
        c1.extend(encode.ByteEncode(u_compressed, du))

    v_compressed: List[int] = [encode.Compress(c, dv) for c in v_plain]
    c2: bytes = encode.ByteEncode(v_compressed, dv)

    return bytes(c1) + c2


# ============================================================================
# K-PKE.Decrypt (FIPS 203, Algorithm 14)
# ============================================================================


def K_PKE_Decrypt(dk: bytes, c: bytes, level: SecurityLevel) -> bytes:
    """K-PKE.Decrypt: Decrypt a ciphertext back to a 32-byte message.

    Algorithm 14 from FIPS 203.

    Steps::

        1. Split c → c1 (k polys, d=du)  ||  c2 (1 poly, d=dv)
        2. u = Decompress_q(ByteDecode(c1, du), du)
           v = Decompress_q(ByteDecode(c2, dv), dv)
        3. s_hat = ByteDecode(dk, 12)
        4. w = v - NTT_inv( s_hat^T @ NTT(u) )
        5. m = ByteEncode(Compress_q(w, 1))

    Args:
        dk: Decryption key (``384*k`` bytes).
        c: Ciphertext ``c1 || c2``.
        level: ML-KEM security level.

    Returns:
        32-byte decrypted message.

    Raises:
        ValueError: If *dk* has an unexpected length for the given level,
            or if *c* has an unexpected length.
    """
    params = MLKEM_PARAMS[level]
    k: int = params["k"]
    du: int = params["du"]
    dv: int = params["dv"]

    expected_dk_len: int = k * _BYTES_PER_POLY_12
    if len(dk) != expected_dk_len:
        raise ValueError(
            f"K_PKE_Decrypt: dk length mismatch for {level.name}: "
            f"expected {expected_dk_len}, got {len(dk)}"
        )

    # Byte sizes for compressed components
    bytes_per_u: int = (N * du + 7) // 8  # 32*du
    bytes_per_v: int = (N * dv + 7) // 8  # 32*dv
    expected_c_len: int = k * bytes_per_u + bytes_per_v
    if len(c) != expected_c_len:
        raise ValueError(
            f"K_PKE_Decrypt: ciphertext length mismatch for {level.name}: "
            f"expected {expected_c_len}, got {len(c)}"
        )

    # ------------------------------------------------------------------
    # Step 1: Parse c → c1 || c2
    # ------------------------------------------------------------------
    c1: bytes = c[: k * bytes_per_u]
    c2: bytes = c[k * bytes_per_u :]

    # ------------------------------------------------------------------
    # Step 2: Decode and decompress u and v
    # ------------------------------------------------------------------
    u_plain: List[List[int]] = []
    for i in range(k):
        start: int = i * bytes_per_u
        u_comp: List[int] = encode.ByteDecode(c1[start : start + bytes_per_u], du)
        u_coeffs: List[int] = [encode.Decompress(val, du) for val in u_comp]
        u_plain.append(u_coeffs)

    v_comp: List[int] = encode.ByteDecode(c2, dv)
    v_plain: List[int] = [encode.Decompress(val, dv) for val in v_comp]

    # ------------------------------------------------------------------
    # Step 3: Decode s_hat from dk
    # ------------------------------------------------------------------
    s_hat: List[List[int]] = []
    for i in range(k):
        start = i * _BYTES_PER_POLY_12
        s_coeffs: List[int] = encode.ByteDecode(
            dk[start : start + _BYTES_PER_POLY_12], 12
        )
        s_hat.append(s_coeffs)

    # ------------------------------------------------------------------
    # Step 4: w = v - NTT_inv( s_hat^T @ NTT(u) )
    # ------------------------------------------------------------------
    # NTT each u polynomial
    u_ntt: List[List[int]] = [ntt.ntt(u_plain[i]) for i in range(k)]

    # Inner product in NTT domain:  Σ_j s_hat[j] * u_ntt[j]
    su_ntt: List[int] = ntt.ntt_zero()
    for j in range(k):
        prod = ntt.ntt_multiply(s_hat[j], u_ntt[j])
        su_ntt = ntt.ntt_add(su_ntt, prod)

    # Inverse NTT
    su_plain: List[int] = ntt.ntt_inv(su_ntt)

    # w = v - su_plain  (mod q)
    w_coeffs: List[int] = [
        (v_plain[idx] - su_plain[idx]) % Q for idx in range(N)
    ]

    # ------------------------------------------------------------------
    # Step 5: Compress to 1 bit per coefficient and encode
    # ------------------------------------------------------------------
    w_compressed: List[int] = [encode.Compress(c, 1) for c in w_coeffs]
    return encode.ByteEncode(w_compressed, 1)
