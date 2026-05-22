"""
liboqs ctypes Backend - High-Performance PQC
=============================================
QSCG v4.0 backend using liboqs C library via ctypes.

Provides 10-50x performance boost over pure Python.
Supports 18+ algorithms: ML-KEM, ML-DSA, FN-DSA, SLH-DSA, NTRU, etc.

Requirements:
- liboqs installed (https://github.com/open-quantum-safe/liboqs)
- Linux: apt install liboqs-dev
- macOS: brew install liboqs
- Windows: Prebuilt binary or build from source

QSCG v4.0 - Quantum Tunneling Research
"""

import ctypes
import os
import sys
from typing import Optional, Tuple, List


# =============================================================================
# liboqs Detection and Loading
# =============================================================================

_liboqs_path = None
_liboqs = None

# Try to find liboqs
_possible_paths = [
    "liboqs.so",                    # Linux
    "liboqs.dylib",                 # macOS
    "oqs.dll",                      # Windows
    "/usr/local/lib/liboqs.so",     # Linux local install
    "/opt/homebrew/lib/liboqs.dylib",  # macOS Homebrew (Apple Silicon)
    "/usr/lib/liboqs.so",           # Linux system
    # Prebuilt binary from sub-agent download
    r"C:\Users\spqr_\.kimi_openclaw\workspace\qscg-research\liboqs-prebuilt\bin\oqs.dll",
    r"C:\Users\spqr_\.kimi_openclaw\workspace\qscg-research\liboqs-prebuilt\bin\liboqs.dll",
    os.path.join(os.path.dirname(__file__), "..", "..", "lib", "liboqs.so"),
    os.path.join(os.path.dirname(__file__), "..", "..", "lib", "oqs.dll"),
]

for path in _possible_paths:
    try:
        _liboqs = ctypes.CDLL(path)
        _liboqs_path = path
        break
    except OSError:
        continue

LIBOQS_AVAILABLE = _liboqs is not None

if LIBOQS_AVAILABLE:
    # OQS_STATUS type
    _liboqs.OQS_SUCCESS = 0
    _liboqs.OQS_ERROR = -1
    
    # Define minimal OQS_KEM structure (we only need length fields)
    class OQS_KEM(ctypes.Structure):
        pass
    
    OQS_KEM._fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_ubyte),
        ("ind_cca", ctypes.c_ubyte),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_ciphertext", ctypes.c_size_t),
        ("length_shared_secret", ctypes.c_size_t),
    ]
    
    # Define minimal OQS_SIG structure
    class OQS_SIG(ctypes.Structure):
        pass
    
    OQS_SIG._fields_ = [
        ("method_name", ctypes.c_char_p),
        ("alg_version", ctypes.c_char_p),
        ("claimed_nist_level", ctypes.c_ubyte),
        ("euf_cma", ctypes.c_ubyte),
        ("length_public_key", ctypes.c_size_t),
        ("length_secret_key", ctypes.c_size_t),
        ("length_signature", ctypes.c_size_t),
    ]
    
    # Set function signatures
    _liboqs.OQS_KEM_new.restype = ctypes.POINTER(OQS_KEM)
    _liboqs.OQS_KEM_new.argtypes = [ctypes.c_char_p]
    _liboqs.OQS_KEM_free.restype = None
    _liboqs.OQS_KEM_free.argtypes = [ctypes.POINTER(OQS_KEM)]
    _liboqs.OQS_KEM_keypair.restype = ctypes.c_int
    _liboqs.OQS_KEM_keypair.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
    _liboqs.OQS_KEM_encaps.restype = ctypes.c_int
    _liboqs.OQS_KEM_encaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
    _liboqs.OQS_KEM_decaps.restype = ctypes.c_int
    _liboqs.OQS_KEM_decaps.argtypes = [ctypes.POINTER(OQS_KEM), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
    _liboqs.OQS_KEM_alg_identifier.restype = ctypes.c_char_p
    _liboqs.OQS_KEM_alg_identifier.argtypes = [ctypes.c_size_t]
    _liboqs.OQS_KEM_alg_count.restype = ctypes.c_int
    
    _liboqs.OQS_SIG_new.restype = ctypes.POINTER(OQS_SIG)
    _liboqs.OQS_SIG_new.argtypes = [ctypes.c_char_p]
    _liboqs.OQS_SIG_free.restype = None
    _liboqs.OQS_SIG_free.argtypes = [ctypes.POINTER(OQS_SIG)]
    _liboqs.OQS_SIG_keypair.restype = ctypes.c_int
    _liboqs.OQS_SIG_keypair.argtypes = [ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_ubyte)]
    _liboqs.OQS_SIG_sign.restype = ctypes.c_int
    _liboqs.OQS_SIG_sign.argtypes = [
        ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_ubyte), ctypes.POINTER(ctypes.c_size_t),
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)
    ]
    _liboqs.OQS_SIG_verify.restype = ctypes.c_int
    _liboqs.OQS_SIG_verify.argtypes = [
        ctypes.POINTER(OQS_SIG), ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t,
        ctypes.POINTER(ctypes.c_ubyte), ctypes.c_size_t, ctypes.POINTER(ctypes.c_ubyte)
    ]
    _liboqs.OQS_SIG_alg_identifier.restype = ctypes.c_char_p
    _liboqs.OQS_SIG_alg_identifier.argtypes = [ctypes.c_size_t]
    _liboqs.OQS_SIG_alg_count.restype = ctypes.c_int


# =============================================================================
# liboqs Algorithm Names (liboqs naming convention)
# =============================================================================

LIBOQS_KEM_ALGORITHMS = {
    "ML-KEM-512": "Kyber512",
    "ML-KEM-768": "Kyber768",
    "ML-KEM-1024": "Kyber1024",
    "NTRU-HPS-2048-509": "NTRU-HPS-2048-509",
    "NTRU-HPS-2048-677": "NTRU-HPS-2048-677",
    "NTRU-HRSS-701": "NTRU-HRSS-701",
    "Classic-McEliece-348864": "Classic-McEliece-348864",
    "FrodoKEM-640-AES": "FrodoKEM-640-AES",
    "BIKE-L1": "BIKE-L1",
    "HQC-128": "HQC-128",
}

LIBOQS_SIG_ALGORITHMS = {
    "ML-DSA-44": "ML-DSA-44",
    "ML-DSA-65": "ML-DSA-65",
    "ML-DSA-87": "ML-DSA-87",
    "FN-DSA-512": "Falcon-512",
    "FN-DSA-1024": "Falcon-1024",
    "SLH-DSA-SHA2-128s": "SPHINCS+-SHA2-128s-simple",
    "SLH-DSA-SHA2-128f": "SPHINCS+-SHA2-128f-simple",
}


# =============================================================================
# liboqs Backend Classes
# =============================================================================

class LiboqsKEM:
    """High-performance KEM via liboqs ctypes."""
    
    def __init__(self, algorithm: str = "Kyber768"):
        """Initialize liboqs KEM."""
        if not LIBOQS_AVAILABLE:
            raise RuntimeError(
                "liboqs not available. Install:\n"
                "  Linux: sudo apt install liboqs-dev\n"
                "  macOS: brew install liboqs\n"
                "  Windows: Download prebuilt binary\n"
                "  Then restart Python."
            )
        
        self._kem = _liboqs.OQS_KEM_new(algorithm.encode())
        if not self._kem:
            available = self.list_algorithms()
            raise ValueError(
                f"Algorithm '{algorithm}' not available in liboqs.\n"
                f"Available: {', '.join(available[:10])}..."
            )
        
        self.algorithm = algorithm
        self.pk_len = self._kem.contents.length_public_key
        self.sk_len = self._kem.contents.length_secret_key
        self.ct_len = self._kem.contents.length_ciphertext
        self.ss_len = self._kem.contents.length_shared_secret
    
    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate keypair."""
        pk = ctypes.create_string_buffer(self.pk_len)
        sk = ctypes.create_string_buffer(self.sk_len)
        
        result = _liboqs.OQS_KEM_keypair(self._kem, 
            ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte)))
        if result != 0:
            raise RuntimeError("Key generation failed")
        
        return bytes(pk), bytes(sk)
    
    def encaps(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate."""
        if len(public_key) != self.pk_len:
            raise ValueError(f"Public key must be {self.pk_len} bytes, got {len(public_key)}")
        
        ct = ctypes.create_string_buffer(self.ct_len)
        ss = ctypes.create_string_buffer(self.ss_len)
        pk_buf = ctypes.create_string_buffer(public_key, self.pk_len)
        
        result = _liboqs.OQS_KEM_encaps(self._kem, 
            ctypes.cast(ct, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte)))
        if result != 0:
            raise RuntimeError("Encapsulation failed")
        
        return bytes(ct), bytes(ss)
    
    def decaps(self, ciphertext: bytes, secret_key: bytes) -> bytes:
        """Decapsulate."""
        if len(ciphertext) != self.ct_len:
            raise ValueError(f"Ciphertext must be {self.ct_len} bytes")
        if len(secret_key) != self.sk_len:
            raise ValueError(f"Secret key must be {self.sk_len} bytes")
        
        ss = ctypes.create_string_buffer(self.ss_len)
        ct_buf = ctypes.create_string_buffer(ciphertext, self.ct_len)
        sk_buf = ctypes.create_string_buffer(secret_key, self.sk_len)
        
        result = _liboqs.OQS_KEM_decaps(self._kem, 
            ctypes.cast(ss, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(ct_buf, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte)))
        if result != 0:
            raise RuntimeError("Decapsulation failed")
        
        return bytes(ss)
    
    def __del__(self):
        if hasattr(self, '_kem') and self._kem:
            _liboqs.OQS_KEM_free(self._kem)
    
    @staticmethod
    def list_algorithms() -> List[str]:
        """List available KEM algorithms."""
        if not LIBOQS_AVAILABLE:
            return []
        
        algorithms = []
        count = _liboqs.OQS_KEM_alg_count()
        for i in range(count):
            name = _liboqs.OQS_KEM_alg_identifier(i)
            if name:
                algorithms.append(name.decode())
        
        return algorithms


class LiboqsSIG:
    """High-performance Signature via liboqs ctypes."""
    
    def __init__(self, algorithm: str = "ML-DSA-65"):
        """Initialize liboqs Signature."""
        if not LIBOQS_AVAILABLE:
            raise RuntimeError("liboqs not available")
        
        self._sig = _liboqs.OQS_SIG_new(algorithm.encode())
        if not self._sig:
            available = self.list_algorithms()
            raise ValueError(
                f"Algorithm '{algorithm}' not available.\n"
                f"Available: {', '.join(available[:10])}..."
            )
        
        self.algorithm = algorithm
        self.pk_len = self._sig.contents.length_public_key
        self.sk_len = self._sig.contents.length_secret_key
        self.sig_len = self._sig.contents.length_signature
    
    def keypair(self) -> Tuple[bytes, bytes]:
        """Generate keypair."""
        pk = ctypes.create_string_buffer(self.pk_len)
        sk = ctypes.create_string_buffer(self.sk_len)
        
        result = _liboqs.OQS_SIG_keypair(self._sig, 
            ctypes.cast(pk, ctypes.POINTER(ctypes.c_ubyte)),
            ctypes.cast(sk, ctypes.POINTER(ctypes.c_ubyte)))
        if result != 0:
            raise RuntimeError("Key generation failed")
        
        return bytes(pk), bytes(sk)
    
    def sign(self, message: bytes, secret_key: bytes) -> bytes:
        """Sign message."""
        if len(secret_key) != self.sk_len:
            raise ValueError(f"Secret key must be {self.sk_len} bytes")
        
        sig = ctypes.create_string_buffer(self.sig_len)
        sig_len = ctypes.c_size_t()
        
        sk_buf = ctypes.create_string_buffer(secret_key, self.sk_len)
        result = _liboqs.OQS_SIG_sign(
            self._sig, 
            ctypes.cast(sig, ctypes.POINTER(ctypes.c_ubyte)), 
            ctypes.byref(sig_len),
            ctypes.cast(ctypes.create_string_buffer(message, len(message)), ctypes.POINTER(ctypes.c_ubyte)),
            len(message),
            ctypes.cast(sk_buf, ctypes.POINTER(ctypes.c_ubyte))
        )
        if result != 0:
            raise RuntimeError("Signing failed")
        
        return bytes(sig)[:sig_len.value]
    
    def verify(self, message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify signature."""
        if len(public_key) != self.pk_len:
            raise ValueError(f"Public key must be {self.pk_len} bytes")
        
        pk_buf = ctypes.create_string_buffer(public_key, self.pk_len)
        sig_buf = ctypes.create_string_buffer(signature, len(signature))
        
        result = _liboqs.OQS_SIG_verify(
            self._sig,
            ctypes.cast(ctypes.create_string_buffer(message, len(message)), ctypes.POINTER(ctypes.c_ubyte)),
            len(message),
            ctypes.cast(sig_buf, ctypes.POINTER(ctypes.c_ubyte)),
            len(signature),
            ctypes.cast(pk_buf, ctypes.POINTER(ctypes.c_ubyte))
        )
        
        return result == 0
    
    def __del__(self):
        if hasattr(self, '_sig') and self._sig:
            _liboqs.OQS_SIG_free(self._sig)
    
    @staticmethod
    def list_algorithms() -> List[str]:
        """List available signature algorithms."""
        if not LIBOQS_AVAILABLE:
            return []
        
        algorithms = []
        count = _liboqs.OQS_SIG_alg_count()
        for i in range(count):
            name = _liboqs.OQS_SIG_alg_identifier(i)
            if name:
                algorithms.append(name.decode())
        
        return algorithms


# =============================================================================
# Diagnostics
# =============================================================================

def diagnose():
    """Print liboqs diagnostic information."""
    print("liboqs Backend Diagnostics")
    print("=" * 50)
    
    if not LIBOQS_AVAILABLE:
        print("[NOT FOUND] liboqs library not detected")
        print("  Searched paths:")
        for path in _possible_paths:
            print(f"    - {path}")
        print("\nInstall:")
        print("  Linux: sudo apt install liboqs-dev")
        print("  macOS: brew install liboqs")
        print("  Windows: Download prebuilt binary")
        return
    
    print(f"[FOUND] {_liboqs_path}")
    
    print("\nKEM Algorithms:")
    for alg in LiboqsKEM.list_algorithms()[:15]:
        print(f"  - {alg}")
    
    print("\nSignature Algorithms:")
    for alg in LiboqsSIG.list_algorithms()[:15]:
        print(f"  - {alg}")
    
    print("\n[OK] liboqs ready")


if __name__ == "__main__":
    diagnose()
