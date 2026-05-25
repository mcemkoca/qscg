"""QSCG Benchmark Suite — Performance testing for post-quantum algorithms.

Run with:
    pytest benchmarks/ --benchmark-only
    python -m pytest benchmarks/ -v --benchmark-sort=mean

Or with JSON output for CI:
    pytest benchmarks/ --benchmark-only --benchmark-json=benchmark-results.json
"""

import pytest
import os
import sys
import time

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qscg_v2_1_final import MLKEM, MLDSA, AES256GCM, SecurityLevel


# ---------------------------------------------------------------------------
# Benchmark Configuration
# ---------------------------------------------------------------------------

# pytest-benchmark default rounds/time are usually fine; override if needed:
# @pytest.mark.benchmark(min_rounds=5, warmup=True)


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203) Benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarkMLKEM:
    """Performance benchmarks for ML-KEM key encapsulation mechanism."""

    @pytest.mark.benchmark(group="ML-KEM", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-KEM-512", SecurityLevel.LEVEL_1),
        ("ML-KEM-768", SecurityLevel.LEVEL_3),
        ("ML-KEM-1024", SecurityLevel.LEVEL_5),
    ])
    def test_keygen(self, benchmark, level_name, level):
        """Benchmark ML-KEM keypair generation."""
        kem = MLKEM(level=level)
        result = benchmark(kem.keygen)
        assert result.public_key is not None

    @pytest.mark.benchmark(group="ML-KEM", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-KEM-512", SecurityLevel.LEVEL_1),
        ("ML-KEM-768", SecurityLevel.LEVEL_3),
        ("ML-KEM-1024", SecurityLevel.LEVEL_5),
    ])
    def test_encapsulate(self, benchmark, level_name, level):
        """Benchmark ML-KEM encapsulation."""
        kem = MLKEM(level=level)
        kp = kem.keygen()
        benchmark(kem.encapsulate, kp.public_key)

    @pytest.mark.benchmark(group="ML-KEM", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-KEM-512", SecurityLevel.LEVEL_1),
        ("ML-KEM-768", SecurityLevel.LEVEL_3),
        ("ML-KEM-1024", SecurityLevel.LEVEL_5),
    ])
    def test_decapsulate(self, benchmark, level_name, level):
        """Benchmark ML-KEM decapsulation."""
        kem = MLKEM(level=level)
        kp = kem.keygen()
        ct, secret = kem.encapsulate(kp.public_key)
        result = benchmark(kem.decapsulate, ct, kp.secret_key)
        assert result == secret

    @pytest.mark.benchmark(group="ML-KEM", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-KEM-512", SecurityLevel.LEVEL_1),
        ("ML-KEM-768", SecurityLevel.LEVEL_3),
        ("ML-KEM-1024", SecurityLevel.LEVEL_5),
    ])
    def test_full_roundtrip(self, benchmark, level_name, level):
        """Benchmark complete ML-KEM keygen + encaps + decaps cycle."""
        def roundtrip():
            kem = MLKEM(level=level)
            kp = kem.keygen()
            ct, secret = kem.encapsulate(kp.public_key)
            recovered = kem.decapsulate(ct, kp.secret_key)
            assert secret == recovered
        benchmark(roundtrip)


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204) Benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarkMLDSA:
    """Performance benchmarks for ML-DSA digital signatures."""

    TEST_MESSAGE = b"Benchmark message for ML-DSA signing operations"

    @pytest.mark.benchmark(group="ML-DSA", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-DSA-44", SecurityLevel.LEVEL_1),
        ("ML-DSA-65", SecurityLevel.LEVEL_3),
        ("ML-DSA-87", SecurityLevel.LEVEL_5),
    ])
    def test_keygen(self, benchmark, level_name, level):
        """Benchmark ML-DSA keypair generation."""
        dsa = MLDSA(level=level)
        result = benchmark(dsa.keygen)
        assert result.public_key is not None

    @pytest.mark.benchmark(group="ML-DSA", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-DSA-44", SecurityLevel.LEVEL_1),
        ("ML-DSA-65", SecurityLevel.LEVEL_3),
        ("ML-DSA-87", SecurityLevel.LEVEL_5),
    ])
    def test_sign(self, benchmark, level_name, level):
        """Benchmark ML-DSA signing."""
        dsa = MLDSA(level=level)
        keys = dsa.keygen()
        benchmark(dsa.sign, keys.secret_key, self.TEST_MESSAGE)

    @pytest.mark.benchmark(group="ML-DSA", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-DSA-44", SecurityLevel.LEVEL_1),
        ("ML-DSA-65", SecurityLevel.LEVEL_3),
        ("ML-DSA-87", SecurityLevel.LEVEL_5),
    ])
    def test_verify(self, benchmark, level_name, level):
        """Benchmark ML-DSA verification."""
        dsa = MLDSA(level=level)
        keys = dsa.keygen()
        sig = dsa.sign(keys.secret_key, self.TEST_MESSAGE)
        benchmark(dsa.verify, keys.public_key, self.TEST_MESSAGE, sig)

    @pytest.mark.benchmark(group="ML-DSA", timer=time.perf_counter)
    @pytest.mark.parametrize("level_name,level", [
        ("ML-DSA-44", SecurityLevel.LEVEL_1),
        ("ML-DSA-65", SecurityLevel.LEVEL_3),
        ("ML-DSA-87", SecurityLevel.LEVEL_5),
    ])
    def test_full_roundtrip(self, benchmark, level_name, level):
        """Benchmark complete ML-DSA keygen + sign + verify cycle."""
        def roundtrip():
            dsa = MLDSA(level=level)
            keys = dsa.keygen()
            sig = dsa.sign(keys.secret_key, self.TEST_MESSAGE)
            dsa.verify(keys.public_key, self.TEST_MESSAGE, sig)
        benchmark(roundtrip)


# ---------------------------------------------------------------------------
# AES-256-GCM Benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarkAES:
    """Performance benchmarks for AES-256-GCM symmetric encryption."""

    @pytest.mark.benchmark(group="AES-256-GCM", timer=time.perf_counter)
    @pytest.mark.parametrize("size_kb", [1, 64, 1024])
    def test_encrypt(self, benchmark, size_kb):
        """Benchmark AES-256-GCM encryption at various payload sizes."""
        key = AES256GCM.generate_key()
        aes = AES256GCM(key)
        plaintext = b"A" * (size_kb * 1024)
        benchmark(aes.encrypt, plaintext)

    @pytest.mark.benchmark(group="AES-256-GCM", timer=time.perf_counter)
    @pytest.mark.parametrize("size_kb", [1, 64, 1024])
    def test_decrypt(self, benchmark, size_kb):
        """Benchmark AES-256-GCM decryption at various payload sizes."""
        key = AES256GCM.generate_key()
        aes = AES256GCM(key)
        plaintext = b"A" * (size_kb * 1024)
        ciphertext = aes.encrypt(plaintext)
        result = benchmark(aes.decrypt, ciphertext)
        assert result == plaintext

    @pytest.mark.benchmark(group="AES-256-GCM", timer=time.perf_counter)
    @pytest.mark.parametrize("size_kb", [1, 64, 1024])
    def test_encrypt_with_aad(self, benchmark, size_kb):
        """Benchmark AES-256-GCM encryption with AAD (Authenticated Additional Data)."""
        key = AES256GCM.generate_key()
        aes = AES256GCM(key)
        plaintext = b"A" * (size_kb * 1024)
        aad = b"metadata" * 100
        benchmark(aes.encrypt, plaintext, aad)


# ---------------------------------------------------------------------------
# Cross-Algorithm Comparison Benchmarks
# ---------------------------------------------------------------------------

class TestBenchmarkComparison:
    """Head-to-head benchmarks for algorithm selection decisions."""

    @pytest.mark.benchmark(group="Comparison", timer=time.perf_counter)
    def test_keygen_mlkem768_vs_mldsa65(self, benchmark):
        """Compare key generation speed: ML-KEM-768 vs ML-DSA-65."""
        kem = MLKEM(level=SecurityLevel.LEVEL_3)
        dsa = MLDSA(level=SecurityLevel.LEVEL_3)
        benchmark.pedantic(kem.keygen, rounds=5, warmup_rounds=1)
        benchmark.pedantic(dsa.keygen, rounds=5, warmup_rounds=1)

    @pytest.mark.benchmark(group="Comparison", timer=time.perf_counter)
    def test_sign_vs_encaps(self, benchmark):
        """Compare ML-DSA-65 sign vs ML-KEM-768 encapsulate speed."""
        dsa = MLDSA(level=SecurityLevel.LEVEL_3)
        keys = dsa.keygen()
        kem = MLKEM(level=SecurityLevel.LEVEL_3)
        kp = kem.keygen()
        benchmark.pedantic(dsa.sign, args=(keys.secret_key, b"test"), rounds=5, warmup_rounds=1)
        benchmark.pedantic(kem.encapsulate, args=(kp.public_key,), rounds=5, warmup_rounds=1)
