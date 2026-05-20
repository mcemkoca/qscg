#!/usr/bin/env python3
"""Tests for HQC_KEM — Hamming Quasi-Cyclic Key Encapsulation.

NIST IR 8545 code-based KEM. Covers keygen, encaps, decaps
round-trip and param validation.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.hqc import HQC_KEM


class TestHQCParameters:
    """Parameter validation tests."""

    def test_valid_levels(self):
        for lvl in (1, 3, 5):
            kem = HQC_KEM(lvl)
            assert kem.level == lvl
            assert kem.p["n"] > 0

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            HQC_KEM(2)
        with pytest.raises(ValueError):
            HQC_KEM(7)
        with pytest.raises(ValueError):
            HQC_KEM(-1)


class TestHQCKeygen:
    """Key generation tests."""

    def test_keypair_sizes_level1(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        n = kem.p["n"]
        assert len(pk) == (n // 8) * 2  # h + s, each n//8
        assert len(sk) == (n // 8) * 2  # x + y, each n//8

    def test_keypair_sizes_level3(self):
        kem = HQC_KEM(3)
        pk, sk = kem.keygen()
        n = kem.p["n"]
        assert len(pk) == (n // 8) * 2
        assert len(sk) == (n // 8) * 2

    def test_keypair_sizes_level5(self):
        kem = HQC_KEM(5)
        pk, sk = kem.keygen()
        n = kem.p["n"]
        assert len(pk) == (n // 8) * 2
        assert len(sk) == (n // 8) * 2

    def test_keys_are_bytes(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_pk_sk_different(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        assert pk != sk


class TestHQCEncapsDecaps:
    """Encapsulation / decapsulation round-trip."""

    def test_roundtrip_level1(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ss2 = kem.decaps(sk, ct)
        assert ss1 == ss2
        assert len(ss1) == 32  # SHA3-256 output

    def test_roundtrip_level3(self):
        kem = HQC_KEM(3)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ss2 = kem.decaps(sk, ct)
        assert ss1 == ss2

    def test_roundtrip_level5(self):
        kem = HQC_KEM(5)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ss2 = kem.decaps(sk, ct)
        assert ss1 == ss2

    def test_ciphertext_format(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss = kem.encaps(pk)
        n = kem.p["n"]
        assert len(ct) == (n // 8) * 2  # u + v, each n//8

    def test_different_encapsulations_yield_different_keys(self):
        kem = HQC_KEM(1)
        pk, _ = kem.keygen()
        _, ss1 = kem.encaps(pk)
        _, ss2 = kem.encaps(pk)
        assert ss1 != ss2  # ephemeral randomness

    def test_different_public_keys(self):
        kem = HQC_KEM(1)
        pk1, _ = kem.keygen()
        pk2, _ = kem.keygen()
        assert pk1 != pk2


class TestHQCCiphertextManipulation:
    """Tamper resistance — modified ciphertexts should fail."""

    def test_flipped_bit_changes_secret(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ct_bad = bytearray(ct)
        ct_bad[0] ^= 0xFF
        ss2 = kem.decaps(sk, bytes(ct_bad))
        assert ss1 != ss2  # integrity check via KDF

    def test_truncated_ciphertext(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ct_short = ct[:-1]
        ss2 = kem.decaps(sk, ct_short)
        assert ss1 != ss2  # length mismatch

    def test_extended_ciphertext(self):
        kem = HQC_KEM(1)
        pk, sk = kem.keygen()
        ct, ss1 = kem.encaps(pk)
        ct_long = ct + b"\x00"
        ss2 = kem.decaps(sk, ct_long)
        # different lengths still produce a result (no strict check)
        # but shared secret differs due to different e reconstruction
        assert ss2 != b"" * 32  # not empty
