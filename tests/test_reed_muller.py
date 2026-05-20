#!/usr/bin/env python3
"""Tests for Reed-Muller and Reed-Solomon codes.

HQC concatenated code: RS outer + RM inner.
"""

import pytest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from quantum_safe_crypto.reed_muller import ReedMuller, ReedSolomon, HQCCode


class TestReedMullerBasic:
    """RM(1,7) basic tests."""

    def test_init(self):
        rm = ReedMuller(m=7, n_copies=3)
        assert rm.n == 128
        assert rm.k == 8
        assert rm.d == 64
        assert rm.total_n == 384

    def test_codeword_count(self):
        rm = ReedMuller(m=7, n_copies=3)
        assert len(rm._codewords) == 256  # 2^8

    def test_encode_byte(self):
        rm = ReedMuller(m=7, n_copies=3)
        # Encode byte 0: all-zero message produces all-zero codeword
        cw0 = rm.encode_byte(0)
        # Encode byte 42
        cw42 = rm.encode_byte(42)
        assert cw42 != cw0
        # Encode byte 255
        cw255 = rm.encode_byte(255)
        assert cw255 != cw42

    def test_decode_no_noise(self):
        """Decode noiseless codeword."""
        rm = ReedMuller(m=7, n_copies=3)
        for msg in [0, 42, 128, 255]:
            cw = rm.encode_byte(msg)
            decoded = rm.decode(cw)
            assert decoded == msg

    def test_decode_with_noise(self):
        """Decode with small number of bit flips (within capacity)."""
        rm = ReedMuller(m=7, n_copies=3)
        msg = 0x42
        cw = rm.encode_byte(msg)

        # Flip 10 bits (capacity per copy: ~31, total: ~93)
        noisy = cw ^ 0x3FF  # flip 10 bits in first positions
        decoded = rm.decode(noisy)
        assert decoded == msg

    def test_decode_many_errors(self):
        """Decode with errors exceeding single copy capacity."""
        rm = ReedMuller(m=7, n_copies=3)
        msg = 0xAB
        cw = rm.encode_byte(msg)

        # Flip 50 bits in one copy (still within total capacity ~93)
        noisy = cw ^ ((1 << 50) - 1)
        decoded = rm.decode(noisy)
        assert decoded == msg


class TestReedMullerEncodeBytes:
    """Multi-byte encoding."""

    def test_encode_decode_bytes(self):
        rm = ReedMuller(m=7, n_copies=3)
        message = bytes([0x42, 0x24, 0xAB, 0xCD])
        encoded = rm.encode(message)
        decoded = rm.decode_bytes(encoded, num_bytes=4)
        assert decoded == message

    def test_encode_decode_with_noise(self):
        rm = ReedMuller(m=7, n_copies=3)
        message = bytes([0x01, 0x02, 0x03, 0x04])
        encoded = rm.encode(message)

        # Add noise to each byte's section
        noisy = encoded
        for i in range(4):
            byte_start = i * rm.total_n
            # Flip 5 bits in this byte's section
            noise_mask = 0x1F << byte_start
            noisy ^= noise_mask

        decoded = rm.decode_bytes(noisy, num_bytes=4)
        assert decoded == message


class TestReedSolomonStub:
    """RS stub tests (full BM decoder not yet implemented)."""

    def test_init_level1(self):
        rs = ReedSolomon(46, 16)
        assert rs.n == 46
        assert rs.k == 16
        assert rs.t == 15

    def test_encode_stub(self):
        rs = ReedSolomon(46, 16)
        msg = bytes(range(16))
        cw = rs.encode(msg)
        assert len(cw) == 46
        assert cw[:16] == msg


class TestHQCCode:
    """Concatenated HQC code tests."""

    def test_init_level1(self):
        code = HQCCode(1)
        assert code.rs.n == 46
        assert code.rm.total_n == 384

    def test_encode_decode_structure(self):
        """Test encode/decode pipeline structure."""
        code = HQCCode(1)
        message = bytes(range(16))
        encoded = code.encode(message)
        assert encoded > 0  # Non-zero integer

        # Decode (with RS stub, just returns first k bytes)
        # This is structure test only
        n_bits = 46 * 384
        decoded = code.decode(encoded, n_bits)
        assert isinstance(decoded, bytes)


class TestGFTables:
    """GF(256) table tests."""

    def test_gf_mul_identity(self):
        rs = ReedSolomon(46, 16)
        assert rs._gf_mul(1, 1) == 1
        assert rs._gf_mul(0, 42) == 0
        assert rs._gf_mul(42, 0) == 0

    def test_gf_inv(self):
        rs = ReedSolomon(46, 16)
        assert rs._gf_inv(1) == 1
        # a * a^-1 = 1 for any non-zero a
        for a in [2, 3, 5, 7, 11, 42, 128, 255]:
            inv = rs._gf_inv(a)
            prod = rs._gf_mul(a, inv)
            assert prod == 1

    def test_gf_log_alog_cycle(self):
        rs = ReedSolomon(46, 16)
        # alog[0] through alog[254] should all be distinct non-zero
        seen = set()
        for i in range(255):
            val = rs._gf_alog[i]
            assert val != 0
            assert val not in seen
            seen.add(val)
        assert len(seen) == 255

    def test_gf_mul_commutative(self):
        rs = ReedSolomon(46, 16)
        for a in [3, 5, 7, 11]:
            for b in [2, 4, 8, 16]:
                assert rs._gf_mul(a, b) == rs._gf_mul(b, a)
