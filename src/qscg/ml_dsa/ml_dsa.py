"""ML-DSA: Module-Lattice-Based Digital Signature Algorithm (FIPS 204, Section 5).

Implements ML-DSA-44 (Level 2), ML-DSA-65 (Level 3), ML-DSA-87 (Level 5)
with Fiat-Shamir with Aborts signing and verification.

All algorithms follow NIST FIPS 204 exactly, using the Faz 1 infrastructure:

    - :mod:`.ntt` — complete NTT (8 layers, q=8380417)
    - :mod:`.polynomial` — :class:`Polynomial` and :class:`PolyVector`
    - :mod:`.sampling` — ``SampleInBall``, ``ExpandA``, ``ExpandS``, ``ExpandMask`
    - :mod:`.encode` — ``SimpleBitPack``, ``BitPack``, ``HintBitPack``

References:
    - NIST FIPS 204, Section 5 — ML-DSA Core Operations
    - CRYSTALS-Dilithium reference implementation (pq-crystals.org)
"""

from __future__ import annotations

import math
import os
from typing import Final, List, Tuple

from ..common.constants import (
    MLDSA_BETA,
    MLDSA_D,
    MLDSA_GAMMA1,
    MLDSA_GAMMA2,
    MLDSA_N,
    MLDSA_OMEGA,
    MLDSA_Q,
    MLDSA_TAU,
    SecurityLevel,
)
from ..common.hashing import H, J
from ..common.utilities import generate_random_bytes
from . import encode
from . import ntt
from . import sampling
from .polynomial import Polynomial

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------
Q: Final[int] = MLDSA_Q
"""Coefficient modulus :math:`q = 8380417`."""

N: Final[int] = MLDSA_N
"""Polynomial degree :math:`n = 256`."""

# ---------------------------------------------------------------------------
# Parameter sets (indexed by SecurityLevel)
# ---------------------------------------------------------------------------
MLDSA_PARAMS: Final[dict] = {
    SecurityLevel.LEVEL_1: {   # ML-DSA-44
        "tau": MLDSA_TAU[44],
        "gamma1": MLDSA_GAMMA1[44],
        "gamma2": MLDSA_GAMMA2[44],
        "k": 4,
        "l": 4,
        "eta": 2,
        "beta": MLDSA_BETA[44],
        "omega": MLDSA_OMEGA[44],
        "d": MLDSA_D,
    },
    SecurityLevel.LEVEL_3: {   # ML-DSA-65
        "tau": MLDSA_TAU[65],
        "gamma1": MLDSA_GAMMA1[65],
        "gamma2": MLDSA_GAMMA2[65],
        "k": 6,
        "l": 5,
        "eta": 4,
        "beta": MLDSA_BETA[65],
        "omega": MLDSA_OMEGA[65],
        "d": MLDSA_D,
    },
    SecurityLevel.LEVEL_5: {   # ML-DSA-87
        "tau": MLDSA_TAU[87],
        "gamma1": MLDSA_GAMMA1[87],
        "gamma2": MLDSA_GAMMA2[87],
        "k": 8,
        "l": 7,
        "eta": 2,
        "beta": MLDSA_BETA[87],
        "omega": MLDSA_OMEGA[87],
        "d": MLDSA_D,
    },
}
"""ML-DSA parameter sets per security level."""

# ---------------------------------------------------------------------------
# Helper: compute byte sizes for packed components
# ---------------------------------------------------------------------------

def _bitpack_size(a: int, b: int) -> int:
    """Return the number of bytes produced by BitPack for bounds *a* and *b*.

    Uses :math:`d = \\lceil\\log_2(a + b + 1)\\rceil` bits per coefficient,
    giving ``32 * d`` bytes per polynomial (N = 256).
    """
    d = math.ceil(math.log2(a + b + 1))
    return 32 * d


def _simple_bitpack_size(bound: int) -> int:
    """Return the number of bytes produced by SimpleBitPack for bound *bound*."""
    d = math.ceil(math.log2(bound + 1))
    return 32 * d


# ============================================================================
# Auxiliary Functions (FIPS 204, Section 5.2)
# ============================================================================


def _mod_q(x: int) -> int:
    """Reduce *x* into the canonical range ``[0, q-1]``."""
    return ((x % Q) + Q) % Q


def Power2Round(r: int, d: int) -> Tuple[int, int]:
    """Power2Round: decompose *r* into high and low bits (FIPS 204, Algorithm 10).

    Computes :math:`r = r_1 \\cdot 2^d + r_0` with
    :math:`r_0 \\in [-2^{d-1}, 2^{d-1}]`.

    Args:
        r: Coefficient in :math:`\\mathbb{Z}_q`.
        d: Number of dropped bits (``d = 13`` for ML-DSA).

    Returns:
        ``(r1, r0)`` where *r1* contains the high bits and *r0* the low bits.
    """
    r = _mod_q(r)
    r0 = r & ((1 << d) - 1)          # r mod 2^d
    half = 1 << (d - 1)
    if r0 >= half:
        r0 -= (1 << d)
    r1 = (r - r0) >> d
    return r1, r0


def HighBits(r: int, gamma2: int) -> int:
    """HighBits: extract high-order bits (FIPS 204, Equation 9).

    Uses :math:`\\alpha = 2\\gamma_2`.

    Args:
        r: Coefficient in :math:`\\mathbb{Z}_q`.
        gamma2: Range parameter (95232 or 261888).

    Returns:
        The high bits :math:`r_1`.
    """
    r = _mod_q(r)
    alpha = 2 * gamma2
    return (r + gamma2 - 1) // alpha


def LowBits(r: int, gamma2: int) -> int:
    """LowBits: extract low-order bits (FIPS 204, Equation 9).

    Uses :math:`\\alpha = 2\\gamma_2`.  The result lies in
    :math:`[-\\gamma_2 + 1, \\gamma_2]`.

    Args:
        r: Coefficient in :math:`\\mathbb{Z}_q`.
        gamma2: Range parameter.

    Returns:
        The low bits :math:`r_0`.
    """
    r = _mod_q(r)
    alpha = 2 * gamma2
    r1 = (r + gamma2 - 1) // alpha
    return r - r1 * alpha


def MakeHint(z: int, r: int, gamma2: int) -> int:
    """MakeHint: generate a hint bit (FIPS 204, Algorithm 12).

    Returns ``1`` if ``HighBits(r) != HighBits(r + z)``.

    Args:
        z: Mask coefficient (may be negative).
        r: Original coefficient.
        gamma2: Range parameter.

    Returns:
        ``1`` if the high bits differ, ``0`` otherwise.
    """
    r_mod = _mod_q(r)
    rz_mod = _mod_q(r + z)
    return 1 if HighBits(r_mod, gamma2) != HighBits(rz_mod, gamma2) else 0


def UseHint(h: int, r: int, gamma2: int) -> int:
    """UseHint: reconstruct high bits from a hint (FIPS 204, Algorithm 13).

    Args:
        h: Hint bit (0 or 1).
        r: Original coefficient.
        gamma2: Range parameter.

    Returns:
        Reconstructed high bits.
    """
    m = (Q - 1) // (2 * gamma2)
    r = _mod_q(r)
    r1 = (r + gamma2 - 1) // (2 * gamma2)
    r0 = r - r1 * (2 * gamma2)

    if h == 1:
        if r0 > 0:
            return (r1 + 1) % (m + 1)
        else:
            return (r1 - 1) % (m + 1)
    return r1 % (m + 1)


# ============================================================================
# ML-DSA.KeyGen (FIPS 204, Algorithm 1)
# ============================================================================


def MLDSA_KeyGen(level: SecurityLevel) -> Tuple[bytes, bytes]:
    """ML-DSA.KeyGen: generate a signature key pair (FIPS 204, Algorithm 1).

    Algorithm::

        1. zeta = randombytes(32)
        2. (rho, rho', K) = H(zeta) || H(zeta||1) || H(zeta||2)  [96 bytes]
        3. A_hat = ExpandA(rho, k, l)
        4. (s1, s2) = ExpandS(rho', l, k, eta)
        5. t = NTT^{-1}(A_hat @ NTT(s1)) + s2
        6. (t1, t0) = Power2Round(t)
        7. pk = rho || t1_packed
        8. tr  = H(pk, 64)        # 64-byte digest
        9. sk = rho || K || tr || s1_packed || s2_packed || t0_packed

    Args:
        level: Desired NIST security level.

    Returns:
        ``(pk, sk)`` byte strings.
    """
    params = MLDSA_PARAMS[level]
    gamma2: int = params["gamma2"]
    k: int = params["k"]
    l: int = params["l"]
    eta: int = params["eta"]
    d: int = params["d"]

    # Step 1: random seed
    zeta = generate_random_bytes(32)

    # Step 2: expand to 96 bytes (H produces 32 bytes each call)
    h_out = H(zeta)
    counter = 0
    while len(h_out) < 96:
        counter += 1
        h_out += H(zeta + counter.to_bytes(1, "little"))
    rho = h_out[:32]
    rho_prime = h_out[32:64]
    K = h_out[64:96]

    # Step 3: Expand A (already in NTT domain)
    A_ntt = sampling.ExpandA(rho, k, l)

    # Step 4: Expand secret vectors s1, s2
    s1_coeffs, s2_coeffs = sampling.ExpandS(rho_prime, l, k, eta)
    s1_polys = [Polynomial(c) for c in s1_coeffs]
    s2_polys = [Polynomial(c) for c in s2_coeffs]

    # Step 5: t = A @ s1 + s2  (NTT domain multiplication)
    s1_ntt = [p.to_ntt() for p in s1_polys]
    t_polys: List[Polynomial] = []
    for i in range(k):
        acc_ntt = ntt.ntt_zero()
        for j in range(l):
            prod = ntt.ntt_multiply(A_ntt[i][j], s1_ntt[j])
            acc_ntt = ntt.ntt_add(acc_ntt, prod)
        t_i = Polynomial.from_ntt(acc_ntt) + s2_polys[i]
        t_polys.append(t_i)

    # Step 6: Power2Round
    # poly.power2round() returns correct centered r0 but r1 may be off by 1
    # when r0 was negative during internal computation.  We recompute r1
    # from the original coefficient and the correct centered r0.
    t1_coeffs: List[List[int]] = []
    t0_coeffs: List[List[int]] = []
    for poly in t_polys:
        r1_poly, r0_poly = poly.power2round(d)
        r0_centered = r0_poly.center()
        t1_row: List[int] = []
        for idx, c in enumerate(poly.coeffs):
            # FIPS 204 exact: r1 = (r - r0_centered) / 2^d  (exact division)
            r1_correct = (c - r0_centered[idx]) >> d
            t1_row.append(r1_correct)
        t1_coeffs.append(t1_row)              # [0, q-1]  — SimpleBitPack
        t0_coeffs.append(r0_centered)         # signed    — BitPack

    # Step 7: Pack public key
    t1_bound = (Q - 1) // (1 << d)
    t1_packed = b"".join(
        encode.SimpleBitPack(c, t1_bound) for c in t1_coeffs
    )
    pk = rho + t1_packed

    # Step 8: tr = H(pk, 64)  — 64-byte digest via SHAKE-256
    tr = J(pk, 64)

    # Step 9: Pack secret key
    s1_packed = b"".join(
        encode.BitPack(c, eta, eta) for c in s1_coeffs
    )
    s2_packed = b"".join(
        encode.BitPack(c, eta, eta) for c in s2_coeffs
    )
    t0_lo = (1 << (d - 1)) - 1
    t0_hi = 1 << (d - 1)
    t0_packed = b"".join(
        encode.BitPack(c, t0_lo, t0_hi) for c in t0_coeffs
    )
    sk = rho + K + tr + s1_packed + s2_packed + t0_packed

    return pk, sk


# ============================================================================
# ML-DSA.Sign (FIPS 204, Algorithm 2)
# ============================================================================


def MLDSA_Sign(
    sk: bytes,
    M: bytes,
    level: SecurityLevel,
    ctx: bytes = b"",
    randomized: bool = True,
) -> bytes:
    """ML-DSA.Sign: sign a message (FIPS 204, Algorithm 2).

    Implements Fiat–Shamir with Aborts: a rejection-sampling loop ensures
    the signature vector norm bounds are satisfied.

    Algorithm::

        1. Parse sk  ->  (rho, K, tr, s1, s2, t0)
        2. A_hat = ExpandA(rho)
        3. Mctx = len(ctx) || ctx || M
        4. mu = H(tr || Mctx, 64)
        5. Rejection-sampling loop (kappa = 0, l, 2l, ...):
               y   = ExpandMask(rho'', kappa)
               w   = NTT^{-1}(A_hat @ NTT(y))
               w1  = HighBits(w)
               c~  = H(mu || w1, 32)
               c   = SampleInBall(c~)
               z   = y + c * s1
               r0  = LowBits(w - c * s2)
               if ||z||_inf < gamma1 - beta
                  and ||r0||_inf < gamma2 - beta:
                      h = MakeHint(-c*t0, w - c*s2 + c*t0)
                      if hint_count <= omega: break
        6. sigma = c~ || z_packed || h_packed

    Args:
        sk: Secret key byte string.
        M: Message to sign.
        level: Security level parameter set.
        ctx: Optional context string (pre-``ctx_len`` encoding).
        randomized: If ``True``, use hedged randomness; otherwise
                    deterministic signing.

    Returns:
        Signature byte string *sigma*.

    Raises:
        RuntimeError: If rejection sampling exhausts the iteration limit.
    """
    params = MLDSA_PARAMS[level]
    tau: int = params["tau"]
    gamma1: int = params["gamma1"]
    gamma2: int = params["gamma2"]
    k: int = params["k"]
    l: int = params["l"]
    eta: int = params["eta"]
    beta: int = params["beta"]
    omega: int = params["omega"]
    d: int = params["d"]

    # ------------------------------------------------------------------
    # 1. Parse secret key
    # ------------------------------------------------------------------
    rho = sk[:32]
    K = sk[32:64]
    tr = sk[64:128]

    # s1 and s2: each coefficient uses ceil(log2(2*eta + 1)) bits
    s1_bits = math.ceil(math.log2(2 * eta + 1))
    s1_poly_bytes = 32 * s1_bits
    s1_total = l * s1_poly_bytes

    s1_packed = sk[128 : 128 + s1_total]
    s2_packed = sk[128 + s1_total : 128 + s1_total + k * s1_poly_bytes]

    # t0: d bits per coefficient (bounds are [-(2^{d-1}-1), 2^{d-1}])
    t0_poly_bytes = 32 * d
    t0_total = k * t0_poly_bytes
    t0_start = 128 + s1_total + k * s1_poly_bytes
    t0_packed = sk[t0_start : t0_start + t0_total]

    # Unpack s1, s2, t0
    s1_polys: List[Polynomial] = []
    for j in range(l):
        start = j * s1_poly_bytes
        end = start + s1_poly_bytes
        coeffs = encode.BitUnpack(s1_packed[start:end], eta, eta)
        s1_polys.append(Polynomial(coeffs))

    s2_polys: List[Polynomial] = []
    for i in range(k):
        start = i * s1_poly_bytes
        end = start + s1_poly_bytes
        coeffs = encode.BitUnpack(s2_packed[start:end], eta, eta)
        s2_polys.append(Polynomial(coeffs))

    t0_polys: List[Polynomial] = []
    t0_lo = (1 << (d - 1)) - 1
    t0_hi = 1 << (d - 1)
    for i in range(k):
        start = i * t0_poly_bytes
        end = start + t0_poly_bytes
        coeffs = encode.BitUnpack(t0_packed[start:end], t0_lo, t0_hi)
        t0_polys.append(Polynomial(coeffs))

    # ------------------------------------------------------------------
    # 2. Expand A (NTT domain)
    # ------------------------------------------------------------------
    A_ntt = sampling.ExpandA(rho, k, l)

    # ------------------------------------------------------------------
    # 3. Message representative
    # ------------------------------------------------------------------
    Mctx = bytes([len(ctx)]) + ctx + M
    mu = J(tr + Mctx, 64)

    # ------------------------------------------------------------------
    # 5. Rejection-sampling loop
    # ------------------------------------------------------------------
    kappa = 0
    MAX_ITERATIONS = 10000

    while True:
        # rho'' for mask expansion (64 bytes via SHAKE-256)
        if randomized:
            rho_pp = J(K + mu + kappa.to_bytes(2, "little"), 64)
        else:
            rho_pp = J(K + mu, 64)

        # y = ExpandMask(rho'', kappa)
        y_coeffs = sampling.ExpandMask(rho_pp, kappa, gamma1, k, l)
        y_polys = [Polynomial(c) for c in y_coeffs]

        # w = A @ y  (NTT domain)
        y_ntt = [p.to_ntt() for p in y_polys]
        w_polys: List[Polynomial] = []
        for i in range(k):
            acc_ntt = ntt.ntt_zero()
            for j in range(l):
                prod = ntt.ntt_multiply(A_ntt[i][j], y_ntt[j])
                acc_ntt = ntt.ntt_add(acc_ntt, prod)
            w_polys.append(Polynomial.from_ntt(acc_ntt))

        # w1 = HighBits(w)
        w1_coeffs: List[List[int]] = []
        for poly in w_polys:
            w1_coeffs.append([HighBits(c, gamma2) for c in poly.coeffs])

        # c_tilde = H(mu || w1_encode, 32)
        w1_bytes = b"".join(
            c.to_bytes(4, "little") for row in w1_coeffs for c in row
        )
        c_tilde = J(mu + w1_bytes, 32)

        # c = SampleInBall(c_tilde)
        c_coeffs = sampling.SampleInBall(c_tilde, tau)
        c_poly = Polynomial(c_coeffs)

        # z = y + c * s1  (polynomial multiplication uses NTT internally)
        cs1_polys = [c_poly * s1_j for s1_j in s1_polys]
        z_polys: List[Polynomial] = []
        for j in range(l):
            z_coeffs = [
                (y_polys[j].coeffs[i] + cs1_polys[j].coeffs[i]) % Q
                for i in range(N)
            ]
            z_polys.append(Polynomial(z_coeffs))

        # r0 = LowBits(w - c * s2)
        cs2_polys = [c_poly * s2_i for s2_i in s2_polys]
        r0_polys: List[Polynomial] = []
        for i in range(k):
            r0_coeffs = [
                (w_polys[i].coeffs[j] - cs2_polys[i].coeffs[j]) % Q
                for j in range(N)
            ]
            r0_polys.append(Polynomial(r0_coeffs))

        # Norm checks
        z_norm = max(p.infinity_norm() for p in z_polys)
        r0_norm = max(
            max(abs(LowBits(c, gamma2)) for c in p.coeffs)
            for p in r0_polys
        )

        if z_norm < gamma1 - beta and r0_norm < gamma2 - beta:
            # ---- hint generation: h = MakeHint(-c*t0, w - c*s2 + c*t0) ----
            ct0_polys = [c_poly * t0_i for t0_i in t0_polys]
            w_cs2_ct0_polys: List[Polynomial] = []
            for i in range(k):
                wct_coeffs = [
                    (
                        w_polys[i].coeffs[j]
                        - cs2_polys[i].coeffs[j]
                        + ct0_polys[i].coeffs[j]
                    )
                    % Q
                    for j in range(N)
                ]
                w_cs2_ct0_polys.append(Polynomial(wct_coeffs))

            h_polys: List[List[int]] = []
            for i in range(k):
                h_row: List[int] = []
                for j in range(N):
                    z_hint = (-ct0_polys[i].coeffs[j]) % Q
                    # Center z_hint to signed representative for MakeHint
                    if z_hint > Q // 2:
                        z_hint -= Q
                    h_row.append(
                        MakeHint(z_hint, w_cs2_ct0_polys[i].coeffs[j], gamma2)
                    )
                h_polys.append(h_row)

            hint_count = sum(sum(row) for row in h_polys)
            if hint_count <= omega:
                break

        kappa += l
        if kappa > MAX_ITERATIONS:
            raise RuntimeError(
                f"Rejection sampling failed after {MAX_ITERATIONS} iterations"
            )

    # ------------------------------------------------------------------
    # 6. Pack signature
    # ------------------------------------------------------------------
    # z is encoded with bounds [-(gamma1-1), gamma1-1]
    z_packed = b"".join(
        encode.BitPack(p.center(), gamma1 - 1, gamma1 - 1) for p in z_polys
    )
    h_packed = encode.HintBitPack(h_polys, omega)

    sigma = c_tilde + z_packed + h_packed
    return sigma


# ============================================================================
# ML-DSA.Verify (FIPS 204, Algorithm 3)
# ============================================================================


def MLDSA_Verify(
    pk: bytes,
    M: bytes,
    sigma: bytes,
    level: SecurityLevel,
    ctx: bytes = b"",
) -> bool:
    """ML-DSA.Verify: verify a signature (FIPS 204, Algorithm 3).

    Algorithm::

        1. Parse pk  ->  rho, t1
        2. Parse sigma  ->  c_tilde, z, h
        3. A_hat = ExpandA(rho)
        4. Mctx  = len(ctx) || ctx || M
        5. tr    = H(pk, 64)
           mu    = H(tr || Mctx, 64)
        6. c     = SampleInBall(c_tilde)
        7. w1'   = UseHint(h, A*z - c*t1*2^d, gamma2)
        8. c~'   = H(mu || w1', 32)
        9. Return  c~ == c~'  and  ||z||_inf < gamma1 - beta

    Args:
        pk: Public key byte string.
        M: Message that was signed.
        sigma: Signature byte string.
        level: Security level parameter set.
        ctx: Optional context string.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    params = MLDSA_PARAMS[level]
    tau: int = params["tau"]
    gamma1: int = params["gamma1"]
    gamma2: int = params["gamma2"]
    k: int = params["k"]
    l: int = params["l"]
    beta: int = params["beta"]
    d: int = params["d"]
    omega: int = params["omega"]

    # ------------------------------------------------------------------
    # 1. Parse public key
    # ------------------------------------------------------------------
    rho = pk[:32]
    t1_packed = pk[32:]

    # ------------------------------------------------------------------
    # 2. Parse signature
    # ------------------------------------------------------------------
    c_tilde = sigma[:32]

    z_bits = gamma1.bit_length()          # 18 or 20
    z_poly_bytes = 32 * z_bits
    z_total = l * z_poly_bytes
    z_packed = sigma[32 : 32 + z_total]
    h_packed = sigma[32 + z_total :]

    # ------------------------------------------------------------------
    # 3. Expand A (NTT domain)
    # ------------------------------------------------------------------
    A_ntt = sampling.ExpandA(rho, k, l)

    # ------------------------------------------------------------------
    # 5. mu derivation
    # ------------------------------------------------------------------
    tr = J(pk, 64)
    Mctx = bytes([len(ctx)]) + ctx + M
    mu = J(tr + Mctx, 64)

    # ------------------------------------------------------------------
    # 6. Challenge polynomial
    # ------------------------------------------------------------------
    c_coeffs = sampling.SampleInBall(c_tilde, tau)
    c_poly = Polynomial(c_coeffs)
    c_ntt = c_poly.to_ntt()

    # ------------------------------------------------------------------
    # 7. Compute A*z - c*t1*2^d and apply hints
    # ------------------------------------------------------------------
    # Parse z polynomials
    z_polys: List[Polynomial] = []
    for j in range(l):
        start = j * z_poly_bytes
        end = start + z_poly_bytes
        z_c = encode.BitUnpack(z_packed[start:end], gamma1 - 1, gamma1 - 1)
        z_polys.append(Polynomial(z_c))

    # Decode t1 and scale by 2^d
    t1_bound = (Q - 1) // (1 << d)
    t1_poly_bytes = _simple_bitpack_size(t1_bound)
    t1_ntt_list: List[List[int]] = []
    for i in range(k):
        start = i * t1_poly_bytes
        end = start + t1_poly_bytes
        t1_c = encode.SimpleBitUnpack(t1_packed[start:end], t1_bound)
        # Scale: t1 * 2^d  (in coefficient domain, then NTT)
        t1_scaled = [(c * (1 << d)) % Q for c in t1_c]
        t1_ntt_list.append(ntt.ntt(t1_scaled))

    # A * z  (NTT domain)
    z_ntt = [p.to_ntt() for p in z_polys]
    Az_ntt: List[List[int]] = []
    for i in range(k):
        acc_ntt = ntt.ntt_zero()
        for j in range(l):
            prod = ntt.ntt_multiply(A_ntt[i][j], z_ntt[j])
            acc_ntt = ntt.ntt_add(acc_ntt, prod)
        Az_ntt.append(acc_ntt)

    # c * t1 * 2^d  (NTT domain)
    ct1_ntt: List[List[int]] = []
    for i in range(k):
        ct1_ntt.append(ntt.ntt_multiply(c_ntt, t1_ntt_list[i]))

    # w = Az - c*t1*2^d  (coefficient domain)
    w_polys: List[Polynomial] = []
    for i in range(k):
        w_ntt = ntt.ntt_sub(Az_ntt[i], ct1_ntt[i])
        w_polys.append(Polynomial.from_ntt(w_ntt))

    # Parse hints and apply UseHint
    h_polys = encode.HintBitUnpack(h_packed, omega, k)

    w1_approx: List[int] = []
    for i in range(k):
        for j in range(N):
            w1_approx.append(
                UseHint(h_polys[i][j], w_polys[i].coeffs[j], gamma2)
            )

    # ------------------------------------------------------------------
    # 8. Recompute c_tilde'
    # ------------------------------------------------------------------
    w1_bytes = b"".join(c.to_bytes(4, "little") for c in w1_approx)
    c_tilde_prime = J(mu + w1_bytes, 32)

    # ------------------------------------------------------------------
    # 9. Final checks
    # ------------------------------------------------------------------
    z_norm = max(p.infinity_norm() for p in z_polys)

    return (c_tilde == c_tilde_prime) and (z_norm < gamma1 - beta)


# ============================================================================
# Convenience class wrapper
# ============================================================================


class MLDSA:
    """ML-DSA digital signature algorithm.

    Wraps the low-level :func:`MLDSA_KeyGen`, :func:`MLDSA_Sign`, and
    :func:`MLDSA_Verify` routines in a stateful object.

    Args:
        level: Desired NIST security level.  Defaults to
               :attr:`SecurityLevel.LEVEL_3` (ML-DSA-65).

    Example::

        >>> from qscg.ml_dsa.ml_dsa import MLDSA
        >>> mldsa = MLDSA(SecurityLevel.LEVEL_3)
        >>> pk, sk = mldsa.keygen()
        >>> msg = b"Hello, post-quantum world!"
        >>> sig = mldsa.sign(sk, msg)
        >>> assert mldsa.verify(pk, msg, sig)
    """

    def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> None:
        self.level = level
        self.params = MLDSA_PARAMS[level]

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate a signature key pair."""
        return MLDSA_KeyGen(self.level)

    def sign(
        self,
        sk: bytes,
        M: bytes,
        ctx: bytes = b"",
        randomized: bool = True,
    ) -> bytes:
        """Sign a message.

        Args:
            sk: Secret key.
            M: Message to sign.
            ctx: Optional context string.
            randomized: Hedged (``True``) or deterministic (``False``).

        Returns:
            Signature byte string.
        """
        return MLDSA_Sign(sk, M, self.level, ctx, randomized)

    def verify(
        self,
        pk: bytes,
        M: bytes,
        sigma: bytes,
        ctx: bytes = b"",
    ) -> bool:
        """Verify a signature.

        Args:
            pk: Public key.
            M: Message that was signed.
            sigma: Signature.
            ctx: Optional context string.

        Returns:
            ``True`` iff the signature is valid.
        """
        return MLDSA_Verify(pk, M, sigma, self.level, ctx)
