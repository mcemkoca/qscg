#!/usr/bin/env python3
"""Tests for FN_DSA — FALCON-based NTRU lattice signatures.

NIST FIPS 206 draft. Covers keygen, sign, verify round-trip
and param validation.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.fndsa import FN_DSA


class TestFNDSAParameters:
    """Parameter validation."""

    def test_valid_levels(self):
        for lvl in (1, 5):
            d = FN_DSA(lvl)
            assert d.level == lvl

    def test_invalid_level(self):
        with pytest.raises(ValueError):
            FN_DSA(2)
        with pytest.raises(ValueError):
            FN_DSA(3)
        with pytest.raises(ValueError):
            FN_DSA(-1)

    def test_level1_params(self):
        d = FN_DSA(1)
        assert d.p["n"] == 512
        assert d.p["sig_bytes"] == 666

    def test_level5_params(self):
        d = FN_DSA(5)
        assert d.p["n"] == 1024
        assert d.p["sig_bytes"] == 1280


class TestFNDSAKeygen:
    """Key generation."""

    def test_keypair_level1(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_keypair_level5(self):
        d = FN_DSA(5)
        pk, sk = d.keygen()
        assert isinstance(pk, bytes)
        assert isinstance(sk, bytes)

    def test_pk_sk_different(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        assert pk != sk

    def test_deterministic_different_keys(self):
        d = FN_DSA(1)
        pk1, _ = d.keygen()
        pk2, _ = d.keygen()
        assert pk1 != pk2


class TestFNDSASignVerify:
    """Signature generation and verification."""

    def test_sign_verify_level1(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        msg = b"Quantum-safe document"
        sig = d.sign(sk, msg)
        assert d.verify(pk, msg, sig)

    def test_sign_verify_level5(self):
        d = FN_DSA(5)
        pk, sk = d.keygen()
        msg = b"Level 5 secure message"
        sig = d.sign(sk, msg)
        assert d.verify(pk, msg, sig)

    def test_signature_size_level1(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        sig = d.sign(sk, b"test")
        assert len(sig) == 666

    def test_signature_size_level5(self):
        d = FN_DSA(5)
        pk, sk = d.keygen()
        sig = d.sign(sk, b"test")
        assert len(sig) == 1280

    def test_different_messages_different_sigs(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        sig1 = d.sign(sk, b"message A")
        sig2 = d.sign(sk, b"message B")
        assert sig1 != sig2


class TestFNDSATamperResistance:
    """Verify tampered messages/signatures are rejected."""

    def test_verify_wrong_message(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        sig = d.sign(sk, b"original")
        assert not d.verify(pk, b"tampered", sig)

    def test_verify_corrupted_signature(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        sig = d.sign(sk, b"test")
        sig_bad = bytearray(sig)
        if len(sig_bad) > 0:
            sig_bad[0] ^= 0xFF
        assert not d.verify(pk, b"test", bytes(sig_bad))

    def test_verify_empty_signature(self):
        d = FN_DSA(1)
        pk, sk = d.keygen()
        assert not d.verify(pk, b"test", b"")

    def test_verify_wrong_key(self):
        d = FN_DSA(1)
        pk1, sk1 = d.keygen()
        pk2, _ = d.keygen()
        sig = d.sign(sk1, b"test")
        assert not d.verify(pk2, b"test", sig)
