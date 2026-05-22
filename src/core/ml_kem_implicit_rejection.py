"""
ML-KEM Implicit Rejection (FIPS 203 Alg 16-17)
===============================================
FIPS 203 Section 7.3: Decapsulation with implicit rejection.

When ciphertext fails validation, return pseudorandom shared secret
instead of explicit error. This prevents chosen-ciphertext attacks.

QSCG v4.0 - Quantum Tunneling Research
"""

import hashlib
import hmac
from typing import Tuple


def ml_kem_implicit_rejection(
    decrypted_message: bytes,
    ciphertext: bytes,
    public_key: bytes,
    secret_key_z: bytes,
    expected_ciphertext: bytes = None
) -> bytes:
    """
    ML-KEM Implicit Rejection (FIPS 203 Algorithm 17).
    
    If ciphertext is valid: return shared secret from decrypted message.
    If ciphertext is invalid: return H(z || c, 32) - pseudorandom value.
    
    Args:
        decrypted_message: The decrypted message (m') from decapsulation
        ciphertext: The actual ciphertext received
        public_key: The public key (pk)
        secret_key_z: The 32-byte random value z from secret key
        expected_ciphertext: Expected ciphertext for validation (optional)
    
    Returns:
        32-byte shared secret (always, even on invalid ciphertext)
    
    Security:
        - No timing side-channel on valid/invalid (Python limitation noted)
        - Invalid ciphertexts produce pseudorandom output, not error
        - Prevents adaptive chosen-ciphertext attacks
    """
    if len(secret_key_z) != 32:
        raise ValueError(f"secret_key_z must be 32 bytes, got {len(secret_key_z)}")
    
    # Validate ciphertext if expected provided
    if expected_ciphertext is not None:
        valid = hmac.compare_digest(ciphertext, expected_ciphertext)
    else:
        # Without explicit expected ciphertext, we assume valid
        # (Caller should validate before calling)
        valid = True
    
    if valid:
        # Valid ciphertext: derive shared secret from message
        # K = H(m' || H(pk), 32)
        pk_hash = hashlib.sha3_256(public_key).digest()
        K = hashlib.sha3_256(decrypted_message + pk_hash).digest()
        return K
    else:
        # Invalid ciphertext: implicit rejection
        # K = H(z || c, 32) - pseudorandom, independent of message
        K = hashlib.sha3_256(secret_key_z + ciphertext).digest()
        return K


def ml_kem_validate_and_decaps(
    u: bytes,
    v: bytes,
    s: bytes,
    public_key: bytes,
    secret_key_z: bytes,
    original_ciphertext: bytes
) -> bytes:
    """
    Full ML-KEM decapsulation with implicit rejection (FIPS 203 Algorithm 16).
    
    Combines decryption, validation, and implicit rejection in one flow.
    
    Args:
        u: Ciphertext vector u (compressed)
        v: Ciphertext polynomial v (compressed)
        s: Secret key vector s
        public_key: Public key bytes
        secret_key_z: 32-byte z value from secret key
        original_ciphertext: Full original ciphertext for re-encryption validation
    
    Returns:
        32-byte shared secret (always)
    """
    # Step 1: Compute m' = v - s^T · u (simplified - actual NTT math in caller)
    # This function assumes m' already computed by caller
    
    # For complete implementation, see qscg_v4_core.py MLKEM.decapsulate()
    # This module provides the implicit rejection logic separately
    
    raise NotImplementedError(
        "Use MLKEM.decapsulate() in qscg_v4_core.py for full decapsulation. "
        "This module provides the implicit_rejection() helper for custom implementations."
    )


def constant_time_select(
    condition: bool,
    value_if_true: bytes,
    value_if_false: bytes
) -> bytes:
    """
    Constant-time selection of shared secret.
    
    WARNING: Python is NOT constant-time. This is best-effort only.
    For production side-channel resistance, use liboqs backend.
    
    Args:
        condition: True for valid ciphertext, False for invalid
        value_if_true: Shared secret for valid case
        value_if_false: Shared secret for invalid case (H(z||c))
    
    Returns:
        Selected shared secret (32 bytes)
    """
    if len(value_if_true) != 32 or len(value_if_false) != 32:
        raise ValueError("Both values must be 32 bytes")
    
    # Best-effort: use hmac.compare_digest for comparison
    # But selection itself in Python is NOT constant-time
    if condition:
        return value_if_true
    else:
        return value_if_false


# =============================================================================
# Test Vectors (FIPS 203 Appendix A style)
# =============================================================================

def test_implicit_rejection():
    """Test implicit rejection with known values."""
    # Test vectors
    m = b'\x00' * 32  # Decrypted message (32 bytes)
    c = b'\x01' * 1088  # Ciphertext (ML-KEM-768 size)
    pk = b'\x02' * 1184  # Public key (ML-KEM-768 size)
    z = b'\x03' * 32  # Secret z value
    
    # Valid case
    K_valid = ml_kem_implicit_rejection(m, c, pk, z, expected_ciphertext=c)
    assert len(K_valid) == 32, "Valid case must produce 32 bytes"
    
    # Invalid case
    c_bad = b'\xff' * 1088
    K_invalid = ml_kem_implicit_rejection(m, c_bad, pk, z, expected_ciphertext=c)
    assert len(K_invalid) == 32, "Invalid case must produce 32 bytes"
    
    # Valid and invalid must differ (with high probability)
    assert K_valid != K_invalid, "Valid and invalid outputs must differ"
    
    # Invalid must be deterministic (same input = same output)
    K_invalid2 = ml_kem_implicit_rejection(m, c_bad, pk, z, expected_ciphertext=c)
    assert K_invalid == K_invalid2, "Invalid output must be deterministic"
    
    print("[PASS] Implicit rejection tests")
    return True


if __name__ == "__main__":
    test_implicit_rejection()
