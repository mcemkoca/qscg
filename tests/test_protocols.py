#!/usr/bin/env python3
"""Tests for PQC protocol extensions.

QUIC, Signal, WireGuard PQC handshake mocks.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.protocols.quic_pqc import QUIC_PQC
from quantum_safe_crypto.protocols.signal_pqc import Signal_PQC
from quantum_safe_crypto.protocols.wireguard_pqc import WireGuard_PQC


class TestQUICPQC:
    """QUIC PQC extension tests."""

    def test_init(self):
        q = QUIC_PQC()
        assert q.version == "v3.0.0"

    def test_handshake_outputs(self):
        q = QUIC_PQC()
        ch, ss = q.handshake()
        assert isinstance(ch, bytes)
        assert isinstance(ss, bytes)
        assert len(ss) == 32  # SHA3-256

    def test_handshake_different_each_time(self):
        q = QUIC_PQC()
        ch1, ss1 = q.handshake()
        ch2, ss2 = q.handshake()
        assert ss1 != ss2  # ephemeral randomness

    def test_encrypt_extensions(self):
        q = QUIC_PQC()
        ss = b"\x00" * 32
        ext = b"some quic extensions"
        enc = q.encrypt_extensions(ss, ext)
        assert len(enc) == len(ext)
        assert isinstance(enc, bytes)


class TestSignalPQC:
    """Signal Protocol v4 PQC tests."""

    def test_init(self):
        s = Signal_PQC()
        assert len(s.identity_key) == 32

    def test_x3dh_init(self):
        s = Signal_PQC()
        ss = s.x3dh_init(b"pq_prekey_32_bytes_or_more")
        assert isinstance(ss, bytes)
        assert len(ss) == 32

    def test_x3dh_different_prekeys(self):
        s = Signal_PQC()
        ss1 = s.x3dh_init(b"pk1")
        ss2 = s.x3dh_init(b"pk2")
        assert ss1 != ss2

    def test_double_ratchet_step(self):
        s = Signal_PQC()
        rk = b"\x00" * 32
        pq = b"\x01" * 32
        ck, mk = s.double_ratchet_step(rk, pq)
        assert isinstance(ck, bytes)
        assert isinstance(mk, bytes)
        assert len(ck) == 32
        assert len(mk) == 32

    def test_ratchet_different_inputs(self):
        s = Signal_PQC()
        ck1, mk1 = s.double_ratchet_step(b"a", b"x")
        ck2, mk2 = s.double_ratchet_step(b"b", b"y")
        assert mk1 != mk2


class TestWireGuardPQC:
    """WireGuard PQC handshake tests."""

    def test_init(self):
        w = WireGuard_PQC()
        assert len(w.static_key) == 32

    def test_handshake_init(self):
        w = WireGuard_PQC()
        ck, ss = w.handshake_init(b"pq_public_key")
        assert isinstance(ck, bytes)
        assert isinstance(ss, bytes)
        assert len(ck) == 32
        assert len(ss) == 32

    def test_handshake_respond(self):
        w = WireGuard_PQC()
        sk = b"\x00" * 32
        resp = w.handshake_respond(b"initiator_msg", sk)
        assert isinstance(resp, bytes)
        assert len(resp) == 32

    def test_handshake_init_different_pk(self):
        w = WireGuard_PQC()
        ck1, ss1 = w.handshake_init(b"pk1")
        ck2, ss2 = w.handshake_init(b"pk2")
        assert ss1 != ss2

    def test_static_key_random(self):
        w1 = WireGuard_PQC()
        w2 = WireGuard_PQC()
        assert w1.static_key != w2.static_key
