"""Minimal verify debug."""
import time
from src.qscg.ml_dsa.ml_dsa import MLDSA, _pk_decode, _sig_decode, N, D
from src.qscg.common.constants import SecurityLevel
from src.qscg.ml_dsa import sampling, encode, ntt
from src.qscg.ml_dsa.polynomial import Polynomial, PolyVector
import hashlib

dsa = MLDSA(SecurityLevel.LEVEL_1)
pk, sk = dsa.keygen()
sig = dsa.sign(sk, b'test')

print("Decode pk...")
t0 = time.time()
rho, t1 = _pk_decode(pk, dsa.k, D)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Decode sig...")
t0 = time.time()
decoded = _sig_decode(sig, dsa.l, dsa.k, dsa.gamma1, dsa.omega, dsa.tau)
c_tilde, z, h = decoded
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Check z norm...")
t0 = time.time()
z_norm = z.infinity_norm()
t1 = time.time()
print(f"  done in {t1-t0:.3f}s, z_norm={z_norm}")

print("Check hint count...")
t0 = time.time()
hint_count = sum(sum(x) for x in h)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s, hints={hint_count}")

print("Recompute tr, mu...")
t0 = time.time()
tr = hashlib.sha3_256(rho + pk).digest()
M_prime = bytes([0]) + bytes([0]) + b'test'
mu = hashlib.sha3_256(tr + M_prime).digest()
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Reconstruct c...")
t0 = time.time()
c_coeffs = sampling.SampleInBall(c_tilde, dsa.tau)
c = Polynomial(c_coeffs)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Expand A...")
t0 = time.time()
A_ntt = sampling.ExpandA(rho, dsa.k, dsa.l)
A = []
for i in range(dsa.k):
    row = []
    for j in range(dsa.l):
        coeffs = ntt.ntt_inv(A_ntt[i][j])
        row.append(Polynomial(coeffs))
    A.append(row)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Compute Az...")
t0 = time.time()
Az = dsa._matrix_vector_mul(A, z)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Compute ct1*2^d...")
t0 = time.time()
ct1_scaled = []
for i in range(dsa.k):
    scaled = t1.polys[i] * (1 << D)
    ct1_poly = c * scaled
    ct1_scaled.append(ct1_poly)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Compute Az-ct1...")
t0 = time.time()
Az_minus_ct1 = PolyVector([Az.polys[i] - ct1_scaled[i] for i in range(dsa.k)])
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("UseHint...")
t0 = time.time()
w1_prime_polys = []
for i in range(dsa.k):
    hint_poly = Polynomial([h[i][j] for j in range(N)])
    w1_prime = Az_minus_ct1.polys[i].use_hint(hint_poly, dsa.gamma2)
    w1_prime_polys.append(w1_prime)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Encode w1_prime...")
t0 = time.time()
w1_bytes = b"".join(
    encode.SimpleBitPack(p.coeffs, (8380417 - 1) // (2 * dsa.gamma2))
    for p in w1_prime_polys
)
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print("Hash to get c_tilde_prime...")
t0 = time.time()
c_tilde_prime = hashlib.sha3_256(mu + w1_bytes).digest()
t1 = time.time()
print(f"  done in {t1-t0:.3f}s")

print(f"\nc_tilde       = {c_tilde.hex()[:16]}...")
print(f"c_tilde_prime = {c_tilde_prime.hex()[:16]}...")
print(f"MATCH: {c_tilde == c_tilde_prime}")
