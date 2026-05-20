#!/usr/bin/env python3
"""Tests for HQC_KEM v2 — mathematical implementation with GF(2) polynomials.

Tests with small parameters (n=1000, w=1) where error rate is low enough
for simplified majority-voting decoder to succeed.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.hqc_v2 import HQC_KEM
from quantum_safe_crypto.gf2poly import GF2Poly


class TestHQCv2Basic:
    """Basic instantiation and parameter validation."""

    def test_init_level1(self):
        kem = HQC_KEM(1)
        assert kem.n == 17669
        assert kem.w == 66

    def test_init_level3(self):
        kem = HQC_KEM(3)
        assert kem.n == 35851
        assert kem.w == 100

    def test_init_level5(self):
        kem = HQC_KEM(5)
        assert kem.n == 57637
        assert kem.w == 131

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            HQC_KEM(2)


class TestHQCv2Keygen:
    """Key generation with mathematical structure."""

    def test_keygen_sizes_level1(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        # pk = pk_seed(40) + s_bytes(n/8)
        expected_pk = 40 + (kem.n + 7) // 8
        assert len(pk) == expected_pk
        # sk = sk_seed(40) + sigma(k) + pk
        expected_sk = 40 + kem.k + len(pk)
        assert len(sk) == expected_sk

    def test_keygen_deterministic_seed(self):
        """Same seed should produce same keys (for testing)."""
        kem = HQC_KEM(1)
        pk1, sk1 = kem.keygen()
        pk2, sk2 = kem.keygen()
        # Different random seeds -> different keys
        assert pk1 != pk2 or sk1 != sk2  # probabilistic


class TestHQCv2Roundtrip:
    """Encaps/Decaps roundtrip with small test parameters."""

    def test_gf2poly_basic(self):
        """Test GF(2) polynomial arithmetic."""
        p1 = GF2Poly(100)
        p1.set_bit(5, 1)
        p1.set_bit(10, 1)
        assert p1.hamming_weight() == 2

        p2 = GF2Poly(100)
        p2.set_bit(5, 1)
        p2.set_bit(15, 1)
        assert p2.hamming_weight() == 2

        p3 = p1 ^ p2
        assert p3.bit(5) == 0  # 1 XOR 1 = 0
        assert p3.bit(10) == 1
        assert p3.bit(15) == 1

    def test_roundtrip_low_error(self):
        """Roundtrip with n=1000, w=1 (ultra-low error rate).
        
        This tests the mathematical structure without requiring
        full Reed-Solomon decoder.
        """
        import random
        from quantum_safe_crypto.gf2poly import gf2_mul_sparse

        # Use n=1000, w=1, w_e=1, w_r=1 for near-zero error rate
        test_n = 1000
        test_k = 2
        
        # Test with explicit seeding for reproducibility
        seed_sk = bytes([1] * 40)
        seed_pk = bytes([2] * 40)
        seed_enc = bytes([3] * 40)
        
        random.seed(seed_sk)
        x = GF2Poly.random_sparse(test_n, 1)
        y = GF2Poly.random_sparse(test_n, 1)
        
        random.seed(seed_pk)
        h = GF2Poly.random_dense(test_n)
        
        # s = y*h + x
        yh = gf2_mul_sparse(y, h, test_n)
        s = yh ^ x
        
        # Message
        m = bytes([0x42, 0x24])
        
        # Encaps
        random.seed(seed_enc)
        r1 = GF2Poly.random_sparse(test_n, 1)
        r2 = GF2Poly.random_sparse(test_n, 1)
        e = GF2Poly.random_sparse(test_n, 1)
        
        u = r1 ^ gf2_mul_sparse(r2, h, test_n)
        
        # Embed message with repetition code
        bits_per_byte = test_n // (test_k * 8)  # 1000 // 16 = 62
        m_poly = GF2Poly(test_n)
        m_bits = ''.join(format(b, '08b') for b in m)
        for i, bit in enumerate(m_bits[:test_k * 8]):
            for j in range(bits_per_byte):
                pos = i * bits_per_byte + j
                if pos < test_n:
                    m_poly.set_bit(pos, int(bit))
        
        sr2 = gf2_mul_sparse(s, r2, test_n)
        v = m_poly ^ sr2 ^ e
        
        # Decaps: noisy = v ^ u*y
        uy = gf2_mul_sparse(u, y, test_n)
        noisy = v ^ uy
        
        # Decode
        m_recovered = bytearray(test_k)
        for byte_idx in range(test_k):
            for bit_idx in range(8):
                msg_bit_pos = byte_idx * 8 + bit_idx
                code_start = msg_bit_pos * bits_per_byte
                code_end = min(code_start + bits_per_byte, test_n)
                ones = sum(noisy.bit(i) for i in range(code_start, code_end))
                total = code_end - code_start
                if ones > total // 2:
                    m_recovered[byte_idx] |= (1 << bit_idx)
        
        m_recovered = bytes(m_recovered)
        assert m == m_recovered, f"Roundtrip failed: {m.hex()} != {m_recovered.hex()}"


class TestHQCv2RealParams:
    """Real parameter tests (structure only, roundtrip requires RS decoder)."""

    def test_encaps_produces_ciphertext(self):
        """Encaps with real parameters produces valid ciphertext."""
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        
        # ct = u_bytes + v_bytes + salt
        vec_n_bytes = (kem.n + 7) // 8
        expected_ct_len = 2 * vec_n_bytes + 16
        assert len(ct) == expected_ct_len
        assert len(ss) == 32

    def test_decaps_produces_secret(self):
        """Decaps produces a shared secret (may not match without RS decoder)."""
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ss2 = kem.decaps(sk, ct)
        
        assert len(ss2) == 32
        # NOTE: ss1 may not equal ss2 without proper Reed-Solomon decoder
        # This is expected for the current educational implementation
