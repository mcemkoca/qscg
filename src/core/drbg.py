"""
AES-256-CTR DRBG (NIST SP 800-90A)
====================================
Deterministic Random Bit Generator for NIST KAT testing.

Used in:
- NIST Known Answer Tests (KAT)
- Deterministic key generation for reproducibility
- Cross-validation with reference implementations

QSCG v4.0 - Quantum Tunneling Research
"""

from typing import Optional
import secrets


try:
    from Crypto.Cipher import AES
    from Crypto.Util import Counter
    PYCryptodome_AVAILABLE = True
except ImportError:
    PYCryptodome_AVAILABLE = False


class AES256_CTR_DRBG:
    """
    NIST SP 800-90A AES-256-CTR DRBG.
    
    Based on kyber-py implementation (GiacomoPope).
    Used for deterministic testing and NIST KAT vectors.
    """
    
    def __init__(self, seed: bytes, personalization_string: bytes = b""):
        """
        Initialize DRBG with a seed.
        
        Args:
            seed: 48 bytes (entropy_input + nonce)
            personalization_string: Optional personalization string
        """
        if len(seed) != 48:
            raise ValueError(f"Seed must be 48 bytes, got {len(seed)}")
        
        if not PYCryptodome_AVAILABLE:
            raise ImportError(
                "pycryptodome required for DRBG. "
                "Install: pip install pycryptodome"
            )
        
        self.seed = seed
        self.personalization_string = personalization_string
        
        # Initialize key and V
        self.key = b"\x00" * 32
        self.V = b"\x00" * 16
        
        # Initial update with seed
        self._update(seed + personalization_string)
    
    def _update(self, provided_data: bytes) -> None:
        """
        DRBG_Update function (NIST SP 800-90A Section 10.2.1.2).
        
        Updates key and V using provided_data.
        """
        temp = b""
        
        # Generate 48 bytes (32 for key + 16 for V)
        while len(temp) < 48:
            # V = V + 1 mod 2^128
            self.V = (int.from_bytes(self.V, 'big') + 1).to_bytes(16, 'big')
            
            # AES-256-CTR encrypt
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted = cipher.encrypt(self.V)
            temp += encrypted
        
        temp = temp[:48]
        
        # key = leftmost 32 bytes of temp
        # V = rightmost 16 bytes of temp
        self.key = bytes([a ^ b for a, b in zip(temp[:32], provided_data[:32])])
        self.V = bytes([a ^ b for a, b in zip(temp[32:48], provided_data[32:48])])
    
    def random_bytes(self, n: int) -> bytes:
        """
        Generate n random bytes.
        
        Args:
            n: Number of bytes to generate
        
        Returns:
            n random bytes
        """
        temp = b""
        
        while len(temp) < n:
            # V = V + 1 mod 2^128
            self.V = (int.from_bytes(self.V, 'big') + 1).to_bytes(16, 'big')
            
            cipher = AES.new(self.key, AES.MODE_ECB)
            encrypted = cipher.encrypt(self.V)
            temp += encrypted
        
        # Update state
        self._update(b"\x00" * 48)
        
        return temp[:n]
    
    def reseed(self, entropy_input: bytes) -> None:
        """
        Reseed the DRBG with new entropy.
        
        Args:
            entropy_input: 48 bytes of new entropy
        """
        if len(entropy_input) != 48:
            raise ValueError(f"Entropy must be 48 bytes, got {len(entropy_input)}")
        
        self._update(entropy_input)


def test_drbg():
    """Test DRBG with NIST test vectors (if available)."""
    if not PYCryptodome_AVAILABLE:
        print("[SKIP] pycryptodome not installed")
        return True
    
    # Test 1: Basic operation
    seed = secrets.token_bytes(48)
    drbg = AES256_CTR_DRBG(seed)
    
    r1 = drbg.random_bytes(32)
    r2 = drbg.random_bytes(32)
    
    assert len(r1) == 32
    assert len(r2) == 32
    assert r1 != r2, "Consecutive outputs should differ"
    
    # Test 2: Determinism with same seed
    drbg_a = AES256_CTR_DRBG(seed)
    drbg_b = AES256_CTR_DRBG(seed)
    
    a1 = drbg_a.random_bytes(32)
    b1 = drbg_b.random_bytes(32)
    
    assert a1 == b1, "Same seed must produce same output"
    
    # Test 3: Different seeds produce different outputs
    seed2 = secrets.token_bytes(48)
    drbg_c = AES256_CTR_DRBG(seed2)
    c1 = drbg_c.random_bytes(32)
    
    assert c1 != a1, "Different seeds must produce different output"
    
    print("[OK] DRBG Tests Passed")
    return True


if __name__ == "__main__":
    test_drbg()
