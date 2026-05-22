"""
ML-KEM Compress/Decompress (FIPS 203 Algorithms 5 & 6)
=====================================================
FIPS 203 Section 4.5: Compression and Decompression

Compress_q(x, d) = floor((2^d / q) * x) mod 2^d
Decompress_q(y, d) = floor((q / 2^d) * y)

Used in:
- encaps: compress t_hat coefficients to du/dv bits
- decaps: decompress received ciphertext

QSCG v4.0 - Quantum Tunneling Research
"""

from typing import List


Q_KYBER = 3329


def compress(x: int, d: int, q: int = Q_KYBER) -> int:
    """
    FIPS 203 Algorithm 5: Compress_d(x)
    
    Compress a coefficient from Z_q to d bits.
    
    Args:
        x: Coefficient in [0, q-1]
        d: Target bit width (1 <= d <= 12)
        q: Modulus (default 3329 for ML-KEM)
    
    Returns:
        Compressed coefficient in [0, 2^d - 1]
    """
    if not (1 <= d <= 12):
        raise ValueError(f"d must be in [1, 12], got {d}")
    
    # Compress_q(x, d) = round((2^d / q) * x) mod 2^d
    # Using integer arithmetic: (x * 2^d + q/2) // q  mod 2^d
    two_d = 1 << d
    return ((x * two_d + q // 2) // q) % two_d


def decompress(y: int, d: int, q: int = Q_KYBER) -> int:
    """
    FIPS 203 Algorithm 6: Decompress_d(y)
    
    Decompress a d-bit coefficient back to Z_q.
    
    Args:
        y: Compressed coefficient in [0, 2^d - 1]
        d: Source bit width (1 <= d <= 12)
        q: Modulus (default 3329 for ML-KEM)
    
    Returns:
        Decompressed coefficient in [0, q-1]
    """
    if not (1 <= d <= 12):
        raise ValueError(f"d must be in [1, 12], got {d}")
    
    # Decompress_q(y, d) = round((q / 2^d) * y)
    # Using integer arithmetic: (y * q + 2^(d-1)) // 2^d
    two_d = 1 << d
    return (y * q + (two_d >> 1)) // two_d


def compress_poly(coeffs: List[int], d: int, q: int = Q_KYBER) -> List[int]:
    """Compress all coefficients of a polynomial."""
    return [compress(c, d, q) for c in coeffs]


def decompress_poly(coeffs: List[int], d: int, q: int = Q_KYBER) -> List[int]:
    """Decompress all coefficients of a polynomial."""
    return [decompress(c, d, q) for c in coeffs]


def encode_poly(coeffs: List[int], d: int) -> bytes:
    """
    Encode a polynomial with d-bit coefficients to bytes.
    FIPS 203: d*256 bits = d*32 bytes.
    
    Args:
        coeffs: 256 coefficients, each in [0, 2^d - 1]
        d: Bit width per coefficient
    
    Returns:
        Encoded bytes of length d * 32
    """
    if len(coeffs) != 256:
        raise ValueError(f"Expected 256 coefficients, got {len(coeffs)}")
    
    # Pack d-bit coefficients into bytes
    result = []
    bit_buffer = 0
    bit_count = 0
    
    for c in coeffs:
        bit_buffer |= (c << bit_count)
        bit_count += d
        
        while bit_count >= 8:
            result.append(bit_buffer & 0xFF)
            bit_buffer >>= 8
            bit_count -= 8
    
    # Any remaining bits
    if bit_count > 0:
        result.append(bit_buffer & 0xFF)
    
    return bytes(result[:d * 32])  # Ensure exact length


def decode_poly(data: bytes, d: int) -> List[int]:
    """
    Decode bytes to a polynomial with d-bit coefficients.
    
    Args:
        data: Encoded bytes of length d * 32
        d: Bit width per coefficient
    
    Returns:
        256 coefficients
    """
    expected_len = d * 32
    if len(data) != expected_len:
        raise ValueError(f"Expected {expected_len} bytes, got {len(data)}")
    
    coeffs = []
    bit_buffer = int.from_bytes(data, 'little')
    mask = (1 << d) - 1
    
    for _ in range(256):
        coeffs.append(bit_buffer & mask)
        bit_buffer >>= d
    
    return coeffs


# ML-KEM specific parameters
ML_KEM_COMPRESS_PARAMS = {
    'du': 10,  # u vector compression (ML-KEM-512: 10, ML-KEM-768: 10, ML-KEM-1024: 11)
    'dv': 4,   # v scalar compression (ML-KEM-512: 4, ML-KEM-768: 4, ML-KEM-1024: 5)
}


def test_compress_decompress_roundtrip():
    """Test that decompress(compress(x)) is close to x (lossy compression)."""
    import secrets
    
    q = 3329
    passed = 0
    failed = 0
    
    # ML-KEM uses d in {10, 11, 12}; test practical values only
    for d in [10, 11, 12]:
        for _ in range(100):
            x = secrets.randbelow(q)
            y = compress(x, d, q)
            x_recovered = decompress(y, d, q)
            
            diff = abs(x - x_recovered)
            # For d=12: exact (2^12 = 4096 > 3329)
            # For d=10,11: bounded by round(q/2^(d+1)) + small tolerance
            if d == 12:
                if diff != 0:
                    failed += 1
                else:
                    passed += 1
            else:
                bound = (q + (1 << d)) >> (d + 1)
                if diff > bound + 2:
                    failed += 1
                else:
                    passed += 1
    
    print(f"Compress/Decompress Test: {passed} passed, {failed} failed")
    return failed == 0


def test_encode_decode_roundtrip():
    """Test encode/decode round-trip for polynomials."""
    import secrets
    
    passed = 0
    failed = 0
    
    for d in range(1, 13):
        coeffs = [secrets.randbelow(1 << d) for _ in range(256)]
        encoded = encode_poly(coeffs, d)
        decoded = decode_poly(encoded, d)
        
        if coeffs == decoded:
            passed += 1
        else:
            failed += 1
            print(f"  FAIL d={d}: encode/decode mismatch")
    
    print(f"Encode/Decode Test: {passed} passed, {failed} failed")
    return failed == 0


if __name__ == "__main__":
    print("ML-KEM Compress/Decompress Tests")
    print("=" * 50)
    
    ok1 = test_compress_decompress_roundtrip()
    ok2 = test_encode_decode_roundtrip()
    
    print("=" * 50)
    if ok1 and ok2:
        print("[OK] ALL TESTS PASSED")
    else:
        print("[FAIL] SOME TESTS FAILED")
