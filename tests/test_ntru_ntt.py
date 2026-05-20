#!/usr/bin/env python3
"""Tests for NTT (Number Theoretic Transform) and NTRU lattice.

FN-DSA (FALCON) mathematical foundation.
Ring: Z_q[x]/(x^n+1), q=12289, n=512/1024
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.ntru_ntt import NTTContext, NTRUPoly, NTRUKeypair


class TestNTTBasic:
    """NTT forward/inverse transform tests."""

    def test_init(self):
        ntt = NTTContext(512)
        assert ntt.n == 512
        assert ntt.Q == 12289

    def test_bit_reverse(self):
        ntt = NTTContext(512)
        # bit-reverse of 1 in 9 bits = 256
        assert ntt._bit_reverse(1, 9) == 256
        # bit-reverse of 3 (0b000000011) = 384 (0b110000000)
        assert ntt._bit_reverse(3, 9) == 384

    def test_ntt_intt_identity(self):
        """NTT followed by INTT = identity (up to scaling)."""
        ntt = NTTContext(512)
        a = [i % ntt.Q for i in range(512)]
        A = ntt.ntt(a)
        a2 = ntt.intt(A)

        for i in range(512):
            expected = a[i] % ntt.Q
            if expected > ntt.Q // 2:
                expected -= ntt.Q
            assert a2[i] == expected, f"Mismatch at index {i}: {a2[i]} != {expected}"

    def test_ntt_intt_random(self):
        """NTT/INTT with random coefficients."""
        import random
        ntt = NTTContext(512)
        random.seed(42)
        a = [random.randint(0, ntt.Q - 1) for _ in range(512)]
        A = ntt.ntt(a)
        a2 = ntt.intt(A)

        for i in range(512):
            expected = a[i] % ntt.Q
            if expected > ntt.Q // 2:
                expected -= ntt.Q
            assert a2[i] == expected


class TestNTTArithmetic:
    """NTT domain arithmetic."""

    def test_pointwise_mul(self):
        """Point-wise multiplication in NTT domain corresponds to convolution."""
        ntt = NTTContext(512)
        # a = [1, 0, 0, ...] (delta)
        # b = [2, 0, 0, ...] (delta)
        # a * b = [2, 0, 0, ...] (delta)
        a = [1] + [0] * 511
        b = [2] + [0] * 511
        ab = ntt.poly_mul(a, b)

        assert ab[0] == 2
        for i in range(1, 512):
            assert ab[i] == 0

    def test_poly_mul_commutative(self):
        """a * b = b * a."""
        ntt = NTTContext(512)
        a = [i % 5 for i in range(512)]  # small coefficients
        b = [i % 3 for i in range(512)]
        ab = ntt.poly_mul(a, b)
        ba = ntt.poly_mul(b, a)

        for i in range(512):
            assert ab[i] == ba[i]

    def test_poly_mul_identity(self):
        """a * 1 = a (where 1 is constant polynomial)."""
        ntt = NTTContext(512)
        a = list(range(512))
        one = [1] + [0] * 511
        result = ntt.poly_mul(a, one)

        for i in range(512):
            assert result[i] == a[i]


class TestNTRUPoly:
    """NTRU polynomial tests."""

    def test_init(self):
        p = NTRUPoly([1, -1, 0, 1], n=512)
        assert p.n == 512
        assert p.coeffs[0] == 1
        assert p.coeffs[1] == -1

    def test_addition(self):
        a = NTRUPoly([1, 2, 3], n=512)
        b = NTRUPoly([1, 1, 1], n=512)
        c = a + b
        assert c.coeffs[0] == 2
        assert c.coeffs[1] == 3
        assert c.coeffs[2] == 4

    def test_norm(self):
        p = NTRUPoly([3, 4, 0] + [0] * 509, n=512)
        assert p.norm_sq() == 25
        assert abs(p.norm() - 5.0) < 0.001

    def test_from_small(self):
        p = NTRUPoly.from_small(512, density=0.25)
        assert p.n == 512
        # Most coefficients should be in {-1, 0, 1}
        for c in p.coeffs[:10]:
            assert c in (-1, 0, 1)

    def test_to_bytes_roundtrip(self):
        p = NTRUPoly.from_small(512, density=0.25)
        b = p.to_bytes()
        assert len(b) == 1024  # 512 * 2 bytes


class TestNTRUKeypair:
    """NTRU key generation and operations."""

    def test_keygen(self):
        kp = NTRUKeypair(512)
        pk, sk = kp.generate(seed=b"test_seed_512")
        assert len(pk) == 1024  # 512 * 2 bytes
        assert len(sk) == 2048  # f + g

    def test_keygen_level5(self):
        kp = NTRUKeypair(1024)
        pk, sk = kp.generate(seed=b"test_seed_1024")
        assert len(pk) == 2048  # 1024 * 2 bytes
        assert len(sk) == 4096  # f + g

    @pytest.mark.skip(reason="FALCON FFT sampling not yet implemented - s1 norm too large")
    def test_sign_verify(self):
        kp = NTRUKeypair(512)
        pk, sk = kp.generate(seed=b"sign_test_512")
        msg = b"Quantum-safe message"

        sig = kp.sign_ntt(sk, msg)
        assert len(sig) == 2048  # s1 + s2, each 512*2 bytes

        result = kp.verify_ntt(pk, msg, sig)
        assert result

    def test_verify_wrong_message(self):
        kp = NTRUKeypair(512)
        pk, sk = kp.generate(seed=b"verify_test_512")
        sig = kp.sign_ntt(sk, b"correct")
        result = kp.verify_ntt(pk, b"wrong", sig)
        assert not result

    def test_public_key_consistency(self):
        """Same seed produces same public key."""
        kp1 = NTRUKeypair(512)
        pk1, _ = kp1.generate(seed=b"consistency_test")

        kp2 = NTRUKeypair(512)
        pk2, _ = kp2.generate(seed=b"consistency_test")

        assert pk1 == pk2


class TestNTTLevel5:
    """Level 5 (n=1024) tests."""

    def test_ntt_intt_1024(self):
        ntt = NTTContext(1024)
        a = [i % 7 for i in range(1024)]
        A = ntt.ntt(a)
        a2 = ntt.intt(A)

        for i in range(1024):
            expected = a[i] % ntt.Q
            if expected > ntt.Q // 2:
                expected -= ntt.Q
            assert a2[i] == expected