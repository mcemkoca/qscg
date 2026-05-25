"""QSCG Benchmark Suite — Performance testing for post-quantum algorithms.

Run with:
    pytest benchmarks/ --benchmark-only

Or:
    python -m pytest benchmarks/ -v --benchmark-sort=mean
"""

import pytest
import os
import sys

# Ensure src/ is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from qscg.common.constants import SecurityLevel
from qscg_v2_1_final import MLKEM, MLDSA, AES256GCM


# ---------------------------------------------------------------------------
# Benchmark Configuration
# ---------------------------------------------------------------------------

BENCHMARK_ROUNDS = 10       # iterations per test (warmup + measured)
BENCHMARK_WARMUP = True


# ---------------------------------------------------------------------------
# ML-KEM (FIPS 203) Benchmarks
# ---------------------------------------------------------------------------

class BenchmarkMLKEM:
    """Performance benchmarks for ML-KEM key encapsulation mechanism."""

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_keygen(self, benchmark, level):
        """Benchmark ML-KEM keypair generation."""
        kem = MLKEM(level=level)
        result = benchmark(kem.keygen)
        # Verify result is usable
        assert result.public_key is not None

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_encapsulate(self, benchmark, level):
        """Benchmark ML-KEM encapsulation."""
        kem = MLKEM(level=level)
        kp = kem.keygen()
        benchmark(kem.encapsulate, kp.public_key)

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_decapsulate(self, benchmark, level):
        """Benchmark ML-KEM decapsulation."""
        kem = MLKEM(level=level)
        kp = kem.keygen()
        ct, secret = kem.encapsulate(kp.public_key)
        result = benchmark(kem.decapsulate, ct, kp.secret_key)
        assert result == secret

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_full_roundtrip(self, benchmark, level):
        """Benchmark complete ML-KEM keygen + encaps + decaps cycle."""
        def roundtrip():
            kem = MLKEM(level=level)
            kp = kem.keygen()
            ct, secret = kem.encapsulate(kp.public_key)
            recovered = kem.decapsulate(ct, kp.secret_key)
            assert secret == recovered
            return recovered

        benchmark(roundtrip)


# ---------------------------------------------------------------------------
# ML-DSA (FIPS 204) Benchmarks
# ---------------------------------------------------------------------------

class BenchmarkMLDSA:
    """Performance benchmarks for ML-DSA digital signatures.
    
    NOTE: Uses the monolithic implementation (qscg_v2_1_final.py) which has
    working sign/verify. The modular implementation is pending a fix for the
    rejection-sampling loop (see issue #?).
    """

    TEST_MESSAGE = b"Benchmark message for ML-DSA signing operations"

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_keygen(self, benchmark, level):
        """Benchmark ML-DSA keypair generation."""
        dsa = MLDSA(level=level)
        result = benchmark(dsa.keygen)
        assert result.public_key is not None

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_sign(self, benchmark, level):
        """Benchmark ML-DSA signing."""
        dsa = MLDSA(level=level)
        keys = dsa.keygen()
        benchmark(dsa.sign, keys.secret_key, self.TEST_MESSAGE)

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_verify(self, benchmark, level):
        """Benchmark ML-DSA verification."""
        dsa = MLDSA(level=level)
        keys = dsa.keygen()
        sig = dsa.sign(keys.secret_key, self.TEST_MESSAGE)
        result = benchmark(dsa.verify, keys.public_key, self.TEST_MESSAGE, sig)
        assert result is True  # Educational impl: may return False — see note

    @pytest.mark.parametrize("level", [
        SecurityLevel.LEVEL_1,
        SecurityLevel.LEVEL_3,
        SecurityLevel.LEVEL_5,
    ])
    def bench_full_roundtrip(self, benchmark, level):
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

class BenchmarkAES:
    """Performance benchmarks for AES-256-GCM symmetric encryption."""

    @pytest.mark.parametrize("size_kb", [1, 64, 1024])
    def bench_encrypt(self, benchmark, size_kb):
        """Benchmark AES-256-GCM encryption at various payload sizes."""
        key = AES256GCM.generate_key()
        aes = AES256GCM(key)
        plaintext = b"A" * (size_kb * 1024)
        benchmark(aes.encrypt, plaintext)

    @pytest.mark.parametrize("size_kb", [1, 64, 1024])
    def bench_decrypt(self, benchmark, size_kb):
        """Benchmark AES-256-GCM decryption at various payload sizes."""
        key = AES256GCM.generate_key()
        aes = AES256GCM(key)
        plaintext = b"A" * (size_kb * 1024)
        ciphertext = aes.encrypt(plaintext)
        result = benchmark(aes.decrypt, ciphertext)
        assert result == plaintext


# ---------------------------------------------------------------------------
# Comparison Benchmarks (cross-algorithm)
# ---------------------------------------------------------------------------

class BenchmarkComparison:
    """Head-to-head benchmarks for algorithm selection decisions."""

    def bench_ml_kem_vs_ml_dsa_keygen(self, benchmark):
        """Compare key generation speed: ML-KEM-768 vs ML-DSA-65."""
        kem = MLKEM(level=SecurityLevel.LEVEL_3)
        dsa = MLDSA(level=SecurityLevel.LEVEL_3)
        benchmark.pedantic(kem.keygen, rounds=5, warmup_rounds=2)
        benchmark.pedantic(dsa.keygen, rounds=5, warmup_rounds=2)

    # TODO: Add memory usage benchmarks via tracemalloc / memory_profiler
    # TODO: Add throughput benchmarks (ops/sec at steady state)
    # TODO: Add hybrid KEM benchmarks once X25519Kyber768 is implemented (#4)
    # TODO: Add LMS/XMSS benchmarks once implemented (#3)
