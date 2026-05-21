"""Focused debug: compare sign and verify w1 values."""
from src.qscg.ml_dsa.ml_dsa import MLDSA, _pk_decode, _sk_decode, N, D
from src.qscg.common.constants import SecurityLevel
from src.qscg.ml_dsa import sampling, encode, ntt
from src.qscg.ml_dsa.polynomial import Polynomial, PolyVector
import hashlib, struct

dsa = MLDSA(SecurityLevel.LEVEL_1)

# KeyGen
zeta = __import__('src.qscg.common.utilities', fromlist=['generate_random_bytes']).generate_random_bytes(32)
hash_out = hashlib.sha3_512(zeta).digest()
rho, rho_prime, K = hash_out[:32], hash_out[32:64], hashlib.sha3_256(zeta + b'K').digest()[:32]

A_ntt = sampling.ExpandA(rho, dsa.k, dsa.l)
A = []
for i in range(dsa.k):
    row = []
    for j in range(dsa.l):
        coeffs = ntt.ntt_inv(A_ntt[i][j])
        row.append(Polynomial(coeffs))
    A.append(row)

s1_coeffs, s2_coeffs = sampling.ExpandS(rho_prime, dsa.l, dsa.k, dsa.eta)
s1 = PolyVector([Polynomial(c) for c in s1_coeffs])
s2 = PolyVector([Polynomial(c) for c in s2_coeffs])

t = dsa._matrix_vector_mul(A, s1) + s2
t1_polys, t0_polys = t.power2round(D)
t1 = PolyVector(t1_polys)
t0 = PolyVector(t0_polys)

pk = _pk_encode(rho, t1, dsa.k, D)
tr = hashlib.sha3_256(rho + pk).digest()
sk = _sk_encode(rho, K, tr, s1, s2, t0, dsa.l, dsa.k, dsa.eta, D)

print(f"pk={len(pk)}, sk={len(sk)}")

# Sign
M_prime = bytes([0]) + bytes([0]) + b'test'
mu = hashlib.sha3_256(tr + M_prime).digest()
rho_prime_sign = hashlib.shake_256(K + mu).digest(64)

# Do one signing attempt
kappa = 0
y_polys = []
for i in range(dsa.l):
    seed = rho_prime_sign + struct.pack("<H", kappa) + bytes([i])
    shake = hashlib.shake_256()
    shake.update(seed)
    data = shake.digest(N * 4)
    coeffs = []
    idx = 0
    while len(coeffs) < N and idx < len(data) - 1:
        val = int.from_bytes(data[idx:idx + 2], "little")
        idx += 2
        if val < 2 * dsa.gamma1:
            coeffs.append(val - dsa.gamma1 + 1)
    while len(coeffs) < N:
        coeffs.append(0)
    y_polys.append(Polynomial(coeffs))
y = PolyVector(y_polys)

w = dsa._matrix_vector_mul(A, y)
w1_polys = []
for poly in w.polys:
    r1, _ = poly.decompose(dsa.gamma2)
    w1_polys.append(r1)
w1 = PolyVector(w1_polys)

w1_bytes = b"".join(
    encode.SimpleBitPack(p.coeffs, (8380417 - 1) // (2 * dsa.gamma2))
    for p in w1_polys
)
c_tilde = hashlib.sha3_256(mu + w1_bytes).digest()

c_coeffs = sampling.SampleInBall(c_tilde, dsa.tau)
c = Polynomial(c_coeffs)

# Compute z
z_polys = [y.polys[i] + (c * s1.polys[i]) for i in range(dsa.l)]
z = PolyVector(z_polys)
print(f"z.inf_norm={z.infinity_norm()}, limit={dsa.gamma1 - dsa.beta}")

# Compute r0
for i in range(dsa.k):
    cs2 = c * s2.polys[i]
    w_minus_cs2 = w.polys[i] - cs2
    _, r0 = w_minus_cs2.decompose(dsa.gamma2)
    r0_norm = max(abs(x) for x in r0.center())
    print(f"r0[{i}].norm={r0_norm}, limit={dsa.gamma2 - dsa.beta}")

# Compute hints
for i in range(dsa.k):
    ct0 = c * t0.polys[i]
    ct0_norm = ct0.infinity_norm()
    w_minus_cs2 = w.polys[i] - (c * s2.polys[i])
    hint_poly = w_minus_cs2.make_hint(-ct0, dsa.gamma2)
    hint_count = sum(1 for x in hint_poly.coeffs if x != 0)
    print(f"ct0[{i}].norm={ct0_norm}, limit={dsa.gamma2}, hints={hint_count}")

# Now verify side: reconstruct w1' from Az - ct1·2^d
Az = dsa._matrix_vector_mul(A, z)
for i in range(dsa.k):
    scaled = t1.polys[i] * (1 << D)
    ct1_poly = c * scaled
    Az_minus_ct1 = Az.polys[i] - ct1_poly
    
    w_minus_cs2 = w.polys[i] - (c * s2.polys[i])
    ct0 = c * t0.polys[i]
    hint_poly = w_minus_cs2.make_hint(-ct0, dsa.gamma2)
    h_i = [1 if x != 0 else 0 for x in hint_poly.coeffs]
    hint_poly2 = Polynomial([h_i[j] for j in range(N)])
    w1_prime = Az_minus_ct1.use_hint(hint_poly2, dsa.gamma2)
    
    print(f"w1[{i}].inf_norm={w1_polys[i].infinity_norm()}, w1_prime[{i}].inf_norm={w1_prime.infinity_norm()}")
    
    # Check if they match coefficient by coefficient
    match = all(w1_polys[i].coeffs[j] == w1_prime.coeffs[j] for j in range(min(10, N)))
    print(f"  first 10 coeffs match: {match}")
    if not match:
        for j in range(min(10, N)):
            if w1_polys[i].coeffs[j] != w1_prime.coeffs[j]:
                print(f"    diff at j={j}: w1={w1_polys[i].coeffs[j]}, w1_prime={w1_prime.coeffs[j]}")
                break

from src.qscg.common.utilities import center_reduce

def _pk_encode(rho, t1, k, d):
    t1_bits = (8380417 - 1).bit_length() - d
    max_val = (1 << t1_bits) - 1
    packed = b"".join(encode.SimpleBitPack(p.coeffs, max_val) for p in t1.polys)
    return rho + packed

# Check c_tilde match
w1_prime_polys = []
for i in range(dsa.k):
    scaled = t1.polys[i] * (1 << D)
    ct1_poly = c * scaled
    Az_minus_ct1 = Az.polys[i] - ct1_poly
    w_minus_cs2 = w.polys[i] - (c * s2.polys[i])
    ct0 = c * t0.polys[i]
    hint_poly = w_minus_cs2.make_hint(-ct0, dsa.gamma2)
    h_i = [1 if x != 0 else 0 for x in hint_poly.coeffs]
    hint_poly2 = Polynomial([h_i[j] for j in range(N)])
    w1_prime = Az_minus_ct1.use_hint(hint_poly2, dsa.gamma2)
    w1_prime_polys.append(w1_prime)

w1_prime_bytes = b"".join(
    encode.SimpleBitPack(p.coeffs, (8380417 - 1) // (2 * dsa.gamma2))
    for p in w1_prime_polys
)
c_tilde_prime = hashlib.sha3_256(mu + w1_prime_bytes).digest()

print(f"\nc_tilde      ={c_tilde.hex()[:16]}...")
print(f"c_tilde_prime={c_tilde_prime.hex()[:16]}...")
print(f"MATCH: {c_tilde == c_tilde_prime}")

# Check w1 encode match
print(f"\nw1_bytes_len={len(w1_bytes)}, w1_prime_bytes_len={len(w1_prime_bytes)}")
print(f"w1_bytes == w1_prime_bytes: {w1_bytes == w1_prime_bytes}")
if w1_bytes != w1_prime_bytes:
    print(f"diff at first byte: {w1_bytes[0]} vs {w1_prime_bytes[0]}")
