"""
NTT Cross-Validation Tests
==========================
Tests QSCG v4.0 KyberNTT against:
1. kyber-py reference implementation (GiacomoPope)
2. FIPS 203 mathematical properties
3. Original QSCG NTT (shows bugs)

Run: python -m pytest tests/test_ntt.py -v
"""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src', 'core'))

import pytest
from ntt_kyber import KyberNTT, NTT, _bit_reverse
import secrets

# Try to import kyber-py for reference comparison
try:
    sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'qscg-research', 'kyber-py', 'src'))
    from kyber_py.polynomials.polynomials import PolynomialRing
    KYPY_AVAILABLE = True
except ImportError:
    KYPY_AVAILABLE = False

Q = 3329
N = 256


def test_kyber_ntt_round_trip():
    """KyberNTT: INTT(NTT(x)) == x"""
    ntt = KyberNTT()
    for _ in range(10):
        coeffs = [secrets.randbelow(Q) for _ in range(N)]
        ntt_result = ntt.ntt(coeffs)
        intt_result = ntt.intt(ntt_result)
        assert intt_result == coeffs, f"Round-trip failed for random polynomial"


def test_kyber_ntt_reverse_round_trip():
    """KyberNTT: NTT(INTT(x)) == x"""
    ntt = KyberNTT()
    for _ in range(10):
        ntt_coeffs = [secrets.randbelow(Q) for _ in range(N)]
        intt_result = ntt.intt(ntt_coeffs)
        ntt_after = ntt.ntt(intt_result)
        assert ntt_after == ntt_coeffs


def test_kyber_ntt_multiplication():
    """KyberNTT: a * b == INTT(NTT(a) ○ NTT(b))"""
    ntt = KyberNTT()
    
    # Test with small polynomials for manual verification
    a = [1] + [0] * (N - 1)  # delta function
    b = [2] + [0] * (N - 1)
    
    c_naive = [0] * N
    for i in range(N):
        for j in range(N):
            if i + j < N:
                c_naive[i + j] = (c_naive[i + j] + a[i] * b[j]) % Q
            else:
                c_naive[i + j - N] = (c_naive[i + j - N] - a[i] * b[j]) % Q
    
    c_ntt = ntt.multiply(a, b)
    assert c_naive == c_ntt, f"Naive: {c_naive[:5]}... vs NTT: {c_ntt[:5]}..."


def test_kyber_ntt_random_multiplication():
    """KyberNTT: random polynomial multiplication consistency"""
    ntt = KyberNTT()
    
    for _ in range(5):
        a = [secrets.randbelow(Q) for _ in range(N)]
        b = [secrets.randbelow(Q) for _ in range(N)]
        
        # Naive O(n^2) multiplication (slow but correct reference)
        c_naive = [0] * N
        for i in range(N):
            for j in range(N):
                if i + j < N:
                    c_naive[i + j] = (c_naive[i + j] + a[i] * b[j]) % Q
                else:
                    c_naive[i + j - N] = (c_naive[i + j - N] - a[i] * b[j]) % Q
        
        c_ntt = ntt.multiply(a, b)
        assert c_naive == c_ntt


def test_kyber_ntt_zetas_correctness():
    """KyberNTT: zetas match FIPS 203 expected values"""
    ntt = KyberNTT()
    
    # First few zetas should match known FIPS 203 values
    # zeta[0] = pow(17, br(0,7), 3329) = pow(17, 0, 3329) = 1
    assert ntt.zetas[0] == 1
    
    # zeta[1] = pow(17, br(1,7), 3329) = pow(17, 64, 3329)
    # br(1, 7) = 64 (binary: 0000001 -> 1000000)
    expected_zeta_1 = pow(17, 64, 3329)
    assert ntt.zetas[1] == expected_zeta_1


def test_kyber_ntt_verify_builtin():
    """KyberNTT: built-in verification passes"""
    ntt = KyberNTT()
    assert ntt.verify_correctness()


def test_original_qscg_ntt_bugs():
    """
    Demonstrate original QSCG NTT bugs.
    
    Original NTT:
    - zetas[256] (should be 128)
    - No bit-reversal
    - Produces incorrect results for some inputs
    """
    old_ntt = NTT()
    new_ntt = KyberNTT()
    
    # Bug 1: zetas size
    assert len(old_ntt.zetas) == 256, "Original has 256 zetas"
    assert len(new_ntt.zetas) == 128, "Fixed has 128 zetas"
    
    # Bug 2: zetas values differ
    assert old_ntt.zetas[0] == new_ntt.zetas[0] == 1  # Both start with 1
    assert old_ntt.zetas[1] != new_ntt.zetas[1]  # But diverge immediately
    
    # Bug 3: Original fails round-trip for most inputs
    test_poly = [secrets.randbelow(Q) for _ in range(N)]
    old_ntt_result = old_ntt.transform(test_poly)
    old_intt_result = old_ntt.inverse_transform(old_ntt_result)
    
    # Original may or may not work for specific inputs, but zetas are wrong
    # We just document the structural bug here


@pytest.mark.skipif(not KYPY_AVAILABLE, reason="kyber-py not installed")
def test_against_kyber_py_reference():
    """Compare QSCG KyberNTT against kyber-py PolynomialRing NTT"""
    if not KYPY_AVAILABLE:
        return
    
    qscg_ntt = KyberNTT()
    ring = PolynomialRing()
    
    for _ in range(5):
        coeffs = [secrets.randbelow(Q) for _ in range(N)]
        
        # kyber-py NTT
        poly = ring(coeffs, is_ntt=False)
        poly_ntt = poly.to_ntt()
        kypy_ntt = poly_ntt.coeffs
        
        # QSCG NTT
        qscg_ntt_result = qscg_ntt.ntt(coeffs)
        
        assert qscg_ntt_result == kypy_ntt, \
            f"NTT mismatch at position {next(i for i, (a, b) in enumerate(zip(qscg_ntt_result, kypy_ntt)) if a != b)}"


@pytest.mark.skipif(not KYPY_AVAILABLE, reason="kyber-py not installed")
def test_against_kyber_py_intt():
    """Compare QSCG KyberNTT INTT against kyber-py"""
    if not KYPY_AVAILABLE:
        return
    
    qscg_ntt = KyberNTT()
    ring = PolynomialRing()
    
    for _ in range(5):
        ntt_coeffs = [secrets.randbelow(Q) for _ in range(N)]
        
        # kyber-py INTT
        poly_ntt = ring(ntt_coeffs, is_ntt=True)
        poly = poly_ntt.from_ntt()
        kypy_intt = poly.coeffs
        
        # QSCG INTT
        qscg_intt = qscg_ntt.intt(ntt_coeffs)
        
        assert qscg_intt == kypy_intt


@pytest.mark.skipif(not KYPY_AVAILABLE, reason="kyber-py not installed")
def test_against_kyber_py_multiplication():
    """Compare multiplication against kyber-py"""
    if not KYPY_AVAILABLE:
        return
    
    qscg_ntt = KyberNTT()
    ring = PolynomialRing()
    
    for _ in range(5):
        a = [secrets.randbelow(Q) for _ in range(N)]
        b = [secrets.randbelow(Q) for _ in range(N)]
        
        # kyber-py multiplication
        poly_a = ring(a, is_ntt=False)
        poly_b = ring(b, is_ntt=False)
        poly_c = poly_a * poly_b
        kypy_result = poly_c.coeffs
        
        # QSCG multiplication
        qscg_result = qscg_ntt.multiply(a, b)
        
        assert qscg_result == kypy_result


def test_zeta_properties():
    """Mathematical properties of zetas"""
    ntt = KyberNTT()
    
    # zeta[0] = 1 (identity)
    assert ntt.zetas[0] == 1
    
    # zetas length = 128
    assert len(ntt.zetas) == 128
    
    # Each zeta is computed as 17^(bit_reverse(i, 7)) mod 3329
    for i in range(128):
        expected = pow(17, _bit_reverse(i, 7), 3329)
        assert ntt.zetas[i] == expected, f"zeta[{i}] mismatch"
    
    # All zetas are in valid range [0, 3328]
    for z in ntt.zetas:
        assert 0 <= z < 3329
    
    # zeta[127] is a primitive root (order > 1)
    assert ntt.zetas[127] != 1
    
    # Verify inverse zetas: zeta * zeta_inv == 1 mod 3329
    for i in range(128):
        assert (ntt.zetas[i] * ntt.zetas_inv[i]) % 3329 == 1


def test_performance_comparison():
    """Benchmark KyberNTT vs original QSCG NTT"""
    import time
    
    old_ntt = NTT()
    new_ntt = KyberNTT()
    
    a = [secrets.randbelow(Q) for _ in range(N)]
    b = [secrets.randbelow(Q) for _ in range(N)]
    
    # Warm-up
    old_ntt.multiply(a, b)
    new_ntt.multiply(a, b)
    
    # Benchmark original
    start = time.perf_counter()
    for _ in range(100):
        old_ntt.multiply(a, b)
    old_time = time.perf_counter() - start
    
    # Benchmark new
    start = time.perf_counter()
    for _ in range(100):
        new_ntt.multiply(a, b)
    new_time = time.perf_counter() - start
    
    print(f"\nPerformance: Old={old_time:.4f}s, New={new_time:.4f}s, Speedup={old_time/new_time:.2f}x")


if __name__ == "__main__":
    print("Running NTT Cross-Validation Tests...")
    print("=" * 50)
    
    try:
        import pytest
        pytest.main([__file__, "-v"])
    except ImportError:
        # Run tests manually
        tests = [
            test_kyber_ntt_round_trip,
            test_kyber_ntt_reverse_round_trip,
            test_kyber_ntt_multiplication,
            test_kyber_ntt_random_multiplication,
            test_kyber_ntt_zetas_correctness,
            test_kyber_ntt_verify_builtin,
            test_original_qscg_ntt_bugs,
        ]
        
        for test in tests:
            try:
                test()
                print(f"✅ {test.__name__}")
            except AssertionError as e:
                print(f"❌ {test.__name__}: {e}")
            except Exception as e:
                print(f"💥 {test.__name__}: {e}")
        
        if KYPY_AVAILABLE:
            print("\nkyber-py cross-validation tests available")
        else:
            print("\n⚠️ kyber-py not available for cross-validation")
            
        test_performance_comparison()
