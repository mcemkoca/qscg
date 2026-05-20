"""HQC - Hamming Quasi-Cyclic Key Encapsulation Mechanism (v2, mathematical).

Based on NIST IR 8545 (2025) selection.
Uses GF(2) polynomial arithmetic and QC-MDPC codes.

Reference implementation: liboqs/src/kem/hqc/pqclean_hqc-128_clean
"""

import hashlib
import os
from typing import Tuple

from .gf2poly import GF2Poly, gf2_mul, gf2_mul_sparse
from .qcmdpc import QCMDPC, BitFlippingDecoder, generate_hqc_parity_checks


class HQC_KEM:
    """Hamming Quasi-Cyclic (HQC) Key Encapsulation.

    Security parameters per NIST IR 8545:
        Level 1 (128-bit): n=17669, w=66, w_e=75, w_r=75
        Level 3 (192-bit): n=35851, w=100, w_e=100, w_r=100
        Level 5 (256-bit): n=57637, w=131, w_e=131, w_r=131

    Mathematical structure:
        Secret key: (x, y) - sparse polynomials in GF(2)[x]/(x^n-1)
        Public key: (h, s=y*h+x) - h is random dense, s is syndrome
        Encryption: u = r1 + r2*h, v = m*G + s*r2 + e
        Decryption: decode v - u*y to recover m
    """

    PARAMS = {
        1: {"n": 17669, "w": 66, "w_e": 75, "w_r": 75, "k": 16},
        3: {"n": 35851, "w": 100, "w_e": 100, "w_r": 100, "k": 24},
        5: {"n": 57637, "w": 131, "w_e": 131, "w_r": 131, "k": 32},
    }

    def __init__(self, security_level: int):
        if security_level not in self.PARAMS:
            raise ValueError("security_level must be 1, 3, or 5")
        self.level = security_level
        self.p = self.PARAMS[security_level]
        self.n = self.p["n"]
        self.w = self.p["w"]        # secret key weight
        self.w_e = self.p["w_e"]    # error weight
        self.w_r = self.p["w_r"]    # randomness weight
        self.k = self.p["k"]        # message size in bytes

        # QC-MDPC decoder for error correction
        self.decoder = BitFlippingDecoder(max_iterations=20)

    def _derive_theta(self, m: bytes, pk_bytes: bytes, salt: bytes) -> bytes:
        """Derive randomness seed theta from message, public key, and salt."""
        shake_input = m + pk_bytes + salt
        return hashlib.shake_128(shake_input).digest(64)

    def keygen(self) -> Tuple[bytes, bytes]:
        """Generate (public_key, secret_key).

        Secret key: seed_sk || sigma || pk (NIST API requires pk in sk)
        Public key: pk_seed || s (where s = y*h + x)
        """
        import random

        # Generate seeds
        sk_seed = os.urandom(40)   # seed for x, y
        sigma = os.urandom(self.k)  # message recovery helper
        pk_seed = os.urandom(40)   # seed for h

        # Generate sparse secret polynomials x, y
        random.seed(sk_seed)
        x = GF2Poly.random_sparse(self.n, self.w)
        y = GF2Poly.random_sparse(self.n, self.w)

        # Generate random dense h
        random.seed(pk_seed)
        h = GF2Poly.random_dense(self.n)

        # Compute public syndrome: s = y*h + x (in GF(2)[x]/(x^n-1))
        yh = gf2_mul_sparse(y, h, self.n)
        s = yh ^ x

        # Pack keys
        pk = pk_seed + s.to_bytes()

        # Secret key: sk_seed || sigma || pk (NIST format)
        sk = sk_seed + sigma + pk

        return pk, sk

    def encaps(self, pk: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate: returns (ciphertext, shared_secret).

        Ciphertext: u || v || salt
        where:
            u = r1 + r2*h  (in GF(2)[x])
            v = m*G + s*r2 + e  (concatenated code encoding + noise)
        """
        import random

        # Random message m
        m = os.urandom(self.k)

        # Random salt
        salt = os.urandom(16)

        # Derive theta (randomness seed)
        theta = self._derive_theta(m, pk, salt)

        # Generate sparse random polynomials r1, r2, e
        random.seed(theta)
        r1 = GF2Poly.random_sparse(self.n, self.w_r)
        r2 = GF2Poly.random_sparse(self.n, self.w_r)
        e = GF2Poly.random_sparse(self.n, self.w_e)

        # Parse public key
        pk_seed = pk[:40]
        s_bytes = pk[40:]
        s = GF2Poly.from_bits(self.n, s_bytes)

        # Regenerate h from pk_seed
        random.seed(pk_seed)
        h = GF2Poly.random_dense(self.n)

        # Compute u = r1 + r2*h
        r2h = gf2_mul_sparse(r2, h, self.n)
        u = r1 ^ r2h

        # Compute v = m*G + s*r2 + e
        # Use real HQC concatenated code: RS + RM
        from quantum_safe_crypto.reed_muller import HQCCode
        hqc_code = HQCCode(self.level)
        
        # Encode message to bit vector
        m_encoded = hqc_code.encode(m)
        m_poly = GF2Poly(self.n)
        for j in range(min(self.n, m_encoded.bit_length())):
            m_poly.set_bit(j, (m_encoded >> j) & 1)

        sr2 = gf2_mul_sparse(s, r2, self.n)
        v = m_poly ^ sr2 ^ e

        # Ciphertext: u || v || salt
        ct = u.to_bytes() + v.to_bytes() + salt

        # Shared secret: SHAKE-256(m || u || v)
        ss_input = m + u.to_bytes() + v.to_bytes()
        ss = hashlib.shake_256(ss_input).digest(32)

        return ct, ss

    def decaps(self, sk: bytes, ct: bytes) -> bytes:
        """Decapsulate shared secret from ciphertext.

        Steps:
            1. Extract u, v, salt from ct
            2. Recover x, y from sk_seed
            3. Compute m' = decode(v - u*y)
            4. Re-encapsulate to verify
            5. Return shared secret
        """
        import random

        # Parse secret key
        sk_seed = sk[:40]
        sigma = sk[40:40+self.k]
        pk = sk[40+self.k:]

        # Parse ciphertext
        vec_n_bytes = (self.n + 7) // 8
        u_bytes = ct[:vec_n_bytes]
        v_bytes = ct[vec_n_bytes:2*vec_n_bytes]
        salt = ct[2*vec_n_bytes:2*vec_n_bytes+16]

        u = GF2Poly.from_bits(self.n, u_bytes)
        v = GF2Poly.from_bits(self.n, v_bytes)

        # Recover x, y from sk_seed
        random.seed(sk_seed)
        x = GF2Poly.random_sparse(self.n, self.w)
        y = GF2Poly.random_sparse(self.n, self.w)

        # Compute u*y (for decoding)
        uy = gf2_mul_sparse(u, y, self.n)
        
        # Debug: check x*r2, r1*y, e weights
        # (for understanding noise structure during development)

        # Recover noisy message: v - u*y = m*G + s*r2 + e - (r1 + r2*h)*y
        # = m*G + s*r2 + e - r1*y - r2*h*y
        # = m*G + (y*h+x)*r2 + e - r1*y - r2*h*y
        # = m*G + x*r2 + e - r1*y
        noisy = v ^ uy

        # Decode using real HQC concatenated code
        from quantum_safe_crypto.reed_muller import HQCCode
        hqc_code = HQCCode(self.level)
        
        # Convert noisy polynomial to integer
        noisy_int = 0
        for j in range(self.n):
            noisy_int |= (noisy.bit(j) << j)
        
        m_recovered = hqc_code.decode(noisy_int, self.n)

        # Re-derive theta and re-encapsulate to verify (Fujisaki-Okamoto transform)
        theta = self._derive_theta(m_recovered, pk, salt)

        random.seed(theta)
        r1_prime = GF2Poly.random_sparse(self.n, self.w_r)
        r2_prime = GF2Poly.random_sparse(self.n, self.w_r)
        e_prime = GF2Poly.random_sparse(self.n, self.w_e)

        pk_seed = pk[:40]
        s_bytes = pk[40:]
        s = GF2Poly.from_bits(self.n, s_bytes)

        random.seed(pk_seed)
        h = GF2Poly.random_dense(self.n)

        r2h = gf2_mul_sparse(r2_prime, h, self.n)
        u2 = r1_prime ^ r2h

        # Encode recovered message with HQC code
        m_encoded2 = hqc_code.encode(m_recovered)
        m_poly2 = GF2Poly(self.n)
        for j in range(min(self.n, m_encoded2.bit_length())):
            m_poly2.set_bit(j, (m_encoded2 >> j) & 1)

        sr2 = gf2_mul_sparse(s, r2_prime, self.n)
        v2 = m_poly2 ^ sr2 ^ e_prime

        # Verify: if (u,v) matches (u2,v2), accept; otherwise use sigma (implicit rejection)
        u_match = u.to_bytes() == u2.to_bytes()
        v_match = v.to_bytes() == v2.to_bytes()

        if u_match and v_match:
            ss_input = m_recovered + u.to_bytes() + v.to_bytes()
        else:
            # Implicit rejection: use sigma (from secret key)
            ss_input = sigma + u.to_bytes() + v.to_bytes()

        ss = hashlib.shake_256(ss_input).digest(32)
        return ss
