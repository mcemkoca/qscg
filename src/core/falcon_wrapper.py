"""
FN-DSA (Falcon) Wrapper via liboqs
====================================
QSCG v4.0 wrapper for NIST FIPS 206 (draft) Falcon signatures.

Uses liboqs C library via ctypes for production-ready FN-DSA.
Pure Python fallback documented but not implemented (complex lattice math).

Security Levels:
- FN-DSA-512: NIST Level 1 (≈ AES-128)
- FN-DSA-1024: NIST Level 5 (≈ AES-256)

Advantages over ML-DSA:
- 5-10x faster signing
- 5x smaller signatures
- 2x smaller public keys

QSCG v4.0 - Quantum Tunneling Research
"""

from typing import Tuple, Optional
import secrets

from liboqs_backend import LiboqsSIG, LIBOQS_AVAILABLE, LIBOQS_SIG_ALGORITHMS


class FN_DSA:
    """
    NIST FIPS 206 (draft) Falcon Digital Signature Algorithm.
    
    Uses liboqs backend for production use.
    """
    
    LEVEL_1 = "FN-DSA-512"   # NIST Level 1
    LEVEL_5 = "FN-DSA-1024"  # NIST Level 5
    
    def __init__(self, security_level: str = LEVEL_1):
        """
        Initialize FN-DSA.
        
        Args:
            security_level: "FN-DSA-512" or "FN-DSA-1024"
        """
        self.security_level = security_level
        
        if LIBOQS_AVAILABLE:
            # Map NIST name to liboqs name
            liboqs_name = LIBOQS_SIG_ALGORITHMS.get(security_level, security_level)
            self._backend = LiboqsSIG(liboqs_name)
            self._mode = "liboqs"
        else:
            self._backend = None
            self._mode = "unavailable"
            raise RuntimeError(
                "FN-DSA requires liboqs.\n"
                "Falcon pure Python implementation not yet available.\n"
                "Install liboqs to use FN-DSA."
            )
    
    def keygen(self) -> Tuple[bytes, bytes]:
        """
        Generate keypair.
        
        Returns:
            (public_key, secret_key)
        """
        return self._backend.keypair()
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """
        Sign a message.
        
        Args:
            message: Message to sign
            secret_key: Secret key
        
        Returns:
            Signature
        """
        return self._backend.sign(message, secret_key)
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """
        Verify a signature.
        
        Args:
            message: Original message
            signature: Signature to verify
            public_key: Public key
        
        Returns:
            True if valid
        """
        return self._backend.verify(message, signature, public_key)
    
    @property
    def public_key_size(self) -> int:
        """Public key size in bytes."""
        return self._backend.pk_len
    
    @property
    def secret_key_size(self) -> int:
        """Secret key size in bytes."""
        return self._backend.sk_len
    
    @property
    def signature_size(self) -> int:
        """Maximum signature size in bytes."""
        return self._backend.sig_len
    
    @property
    def mode(self) -> str:
        """Current backend mode."""
        return self._mode
    
    def __repr__(self) -> str:
        return (
            f"FN_DSA({self.security_level}, "
            f"pk={self.public_key_size}B, "
            f"sk={self.secret_key_size}B, "
            f"sig={self.signature_size}B, "
            f"mode={self._mode})"
        )


class FalconBenchmark:
    """Benchmark FN-DSA vs ML-DSA."""
    
    @staticmethod
    def benchmark(fn_dsa: FN_DSA, ml_dsa, iterations: int = 100) -> dict:
        """
        Compare FN-DSA with ML-DSA performance.
        
        Args:
            fn_dsa: FN-DSA instance
            ml_dsa: ML-DSA instance (from qscg_v4_core)
            iterations: Number of iterations
        
        Returns:
            Benchmark results dict
        """
        import time
        
        message = b"Benchmark message for signature testing"
        
        # FN-DSA benchmark
        fn_pk, fn_sk = fn_dsa.keygen()
        
        start = time.perf_counter()
        for _ in range(iterations):
            sig = fn_dsa.sign(message, fn_sk)
        fn_sign_time = time.perf_counter() - start
        
        start = time.perf_counter()
        for _ in range(iterations):
            fn_dsa.verify(message, sig, fn_pk)
        fn_verify_time = time.perf_counter() - start
        
        # ML-DSA benchmark (if available)
        ml_sign_time = None
        ml_verify_time = None
        if ml_dsa:
            try:
                ml_keypair = ml_dsa.generate_dsa_keypair()
                
                start = time.perf_counter()
                for _ in range(iterations):
                    ml_sig = ml_dsa.sign(ml_keypair.secret_key, message)
                ml_sign_time = time.perf_counter() - start
                
                start = time.perf_counter()
                for _ in range(iterations):
                    ml_dsa.verify(ml_keypair.public_key, message, ml_sig)
                ml_verify_time = time.perf_counter() - start
            except Exception as e:
                print(f"ML-DSA benchmark error: {e}")
        
        return {
            "fn_dsa": {
                "keygen": None,  # Not measured
                "sign_ms": (fn_sign_time / iterations) * 1000,
                "verify_ms": (fn_verify_time / iterations) * 1000,
                "sig_size": len(sig),
                "pk_size": len(fn_pk),
            },
            "ml_dsa": {
                "sign_ms": (ml_sign_time / iterations) * 1000 if ml_sign_time else None,
                "verify_ms": (ml_verify_time / iterations) * 1000 if ml_verify_time else None,
            },
            "speedup": {
                "sign": (ml_sign_time / fn_sign_time) if ml_sign_time else None,
                "verify": (ml_verify_time / fn_verify_time) if ml_verify_time else None,
            }
        }


def test_falcon_basic():
    """Basic FN-DSA test."""
    if not LIBOQS_AVAILABLE:
        print("[SKIP] liboqs not available")
        return True
    
    try:
        falcon = FN_DSA(FN_DSA.LEVEL_1)
        print(f"Initialized: {falcon}")
        
        message = b"Hello, Falcon!"
        pk, sk = falcon.keygen()
        
        print(f"KeyGen OK: pk={len(pk)}B, sk={len(sk)}B")
        
        sig = falcon.sign(message, sk)
        print(f"Sign OK: sig={len(sig)}B")
        
        valid = falcon.verify(message, sig, pk)
        print(f"Verify OK: {valid}")
        assert valid, "Signature verification failed"
        
        # Test tampered message
        tampered = b"Tampered message"
        invalid = falcon.verify(tampered, sig, pk)
        assert not invalid, "Tampered message should fail verification"
        print("Tamper resistance OK")
        
        print("[OK] FN-DSA Basic Test Passed")
        return True
        
    except Exception as e:
        print(f"[FAIL] FN-DSA test error: {e}")
        return False


if __name__ == "__main__":
    test_falcon_basic()
