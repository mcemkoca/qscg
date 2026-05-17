# API Documentation

> **Complete Python API Reference for QSCG v2.2.0**
>
> This page documents all public classes, methods, functions, enums, and type hints available in the QSCG library.

---

## Table of Contents

1. [Module Overview](#module-overview)
2. [SecurityLevel Enum](#securitylevel-enum)
3. [MLKEM Class](#mlkem-class)
4. [MLDSA Class](#mldsa-class)
5. [SLHDSA Class](#slhdsa-class)
6. [AES256GCM Class](#aes256gcm-class)
7. [HybridKEM Class](#hybridkem-class)
8. [Utility Functions](#utility-functions)
9. [Type Hints Reference](#type-hints-reference)
10. [Exception Classes](#exception-classes)

---

## Module Overview

The QSCG library is organized into the following import structure:

```python
# Core algorithm classes
from qscg import MLKEM, MLDSA, SLHDSA

# Symmetric encryption
from qscg import AES256GCM

# Hybrid encryption
from qscg import HybridKEM

# Utilities and types
from qscg import SecurityLevel, QSCGError
from qscg.utils import constant_time_compare, secure_random_bytes
```

---

## SecurityLevel Enum

```python
from enum import IntEnum

class SecurityLevel(IntEnum):
    """NIST-defined post-quantum security levels."""
    
    LEVEL_1 = 1   # AES-128 equivalent
    LEVEL_3 = 3   # AES-192 equivalent
    LEVEL_5 = 5   # AES-256 equivalent
```

### Usage

```python
from qscg import MLKEM, SecurityLevel

# Explicit level selection
kem = MLKEM(level=SecurityLevel.LEVEL_3)

# Integer values also accepted
kem = MLKEM(level=3)
```

---

## MLKEM Class

**Module-Lattice-Based Key Encapsulation Mechanism**

Implements FIPS 203: ML-KEM for secure key exchange resistant to quantum attacks.

### Constructor

```python
class MLKEM:
    def __init__(self, level: SecurityLevel | int = 3) -> None:
        """
        Initialize ML-KEM instance.
        
        Args:
            level: NIST security level (1, 3, or 5). Default is 3.
        
        Raises:
            ValueError: If level is not 1, 3, or 5.
        
        Example:
            >>> kem = MLKEM(level=3)
        """
```

### Methods

#### `generate_keypair()`

```python
def generate_keypair(self) -> tuple[bytes, bytes]:
    """
    Generate a new ML-KEM keypair.
    
    Returns:
        tuple: (public_key, private_key)
            - public_key (bytes): The public encapsulation key
            - private_key (bytes): The private decapsulation key
    
    Raises:
        QSCGError: If key generation fails.
    
    Example:
        >>> kem = MLKEM(level=3)
        >>> pk, sk = kem.generate_keypair()
        >>> len(pk)
        1184
        >>> len(sk)
        2400
    """
```

#### `encapsulate()`

```python
def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
    """
    Encapsulate a shared secret using the recipient's public key.
    
    Args:
        public_key: The recipient's public encapsulation key.
    
    Returns:
        tuple: (ciphertext, shared_secret)
            - ciphertext (bytes): The encapsulation ciphertext
            - shared_secret (bytes): The 32-byte shared secret
    
    Raises:
        ValueError: If public_key has incorrect length.
        QSCGError: If encapsulation fails internally.
    
    Example:
        >>> kem = MLKEM(level=3)
        >>> pk, sk = kem.generate_keypair()
        >>> ct, ss = kem.encapsulate(pk)
        >>> len(ss)
        32
    """
```

#### `decapsulate()`

```python
def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
    """
    Decapsulate a shared secret using the private key.
    
    Args:
        ciphertext: The encapsulation ciphertext.
        private_key: The private decapsulation key.
    
    Returns:
        bytes: The 32-byte shared secret.
    
    Raises:
        ValueError: If ciphertext or private_key has incorrect length.
        QSCGError: If decapsulation fails.
    
    Example:
        >>> kem = MLKEM(level=3)
        >>> pk, sk = kem.generate_keypair()
        >>> ct, ss_enc = kem.encapsulate(pk)
        >>> ss_dec = kem.decapsulate(ct, sk)
        >>> assert ss_enc == ss_dec
    """
```

#### `get_key_sizes()`

```python
def get_key_sizes(self) -> dict[str, int]:
    """
    Return the key sizes for the configured security level.
    
    Returns:
        dict: Dictionary containing:
            - 'public_key': Public key size in bytes
            - 'private_key': Private key size in bytes
            - 'ciphertext': Ciphertext size in bytes
            - 'shared_secret': Shared secret size in bytes
    
    Example:
        >>> kem = MLKEM(level=3)
        >>> kem.get_key_sizes()
        {'public_key': 1184, 'private_key': 2400, 
         'ciphertext': 1088, 'shared_secret': 32}
    """
```

### MLKEM Complete Example

```python
from qscg import MLKEM, SecurityLevel

# Initialize with NIST Level 3 security
kem = MLKEM(level=SecurityLevel.LEVEL_3)

# Generate keypair
public_key, private_key = kem.generate_keyprint("Key generation successful!")
print(f"Public key size: {len(public_key)} bytes")
print(f"Private key size: {len(private_key)} bytes")

# Key sizes by level
for level in [1, 3, 5]:
    k = MLKEM(level=level)
    sizes = k.get_key_sizes()
    print(f"\nLevel {level}:")
    print(f"  Public key:  {sizes['public_key']:>5} bytes")
    print(f"  Private key: {sizes['private_key']:>5} bytes")
    print(f"  Ciphertext:  {sizes['ciphertext']:>5} bytes")

# Encapsulation
print("\n--- Encapsulation ---")
ciphertext, shared_secret = kem.encapsulate(public_key)
print(f"Ciphertext size: {len(ciphertext)} bytes")
print(f"Shared secret: {shared_secret.hex()}")

# Decapsulation
print("\n--- Decapsulation ---")
recovered_secret = kem.decapsulate(ciphertext, private_key)
print(f"Recovered secret: {recovered_secret.hex()}")

# Verify
assert shared_secret == recovered_secret
print("\n✓ Key encapsulation cycle verified!")
```

---

## MLDSA Class

**Module-Lattice-Based Digital Signature Algorithm**

Implements FIPS 204: ML-DSA for quantum-resistant digital signatures.

### Constructor

```python
class MLDSA:
    def __init__(self, level: SecurityLevel | int = 3) -> None:
        """
        Initialize ML-DSA instance.
        
        Args:
            level: NIST security level (2, 3, or 5). Default is 3.
                   Note: Level 2 corresponds to ML-DSA-44.
        
        Raises:
            ValueError: If level is not 2, 3, or 5.
        
        Example:
            >>> dsa = MLDSA(level=3)
        """
```

### Methods

#### `generate_keypair()`

```python
def generate_keypair(self) -> tuple[bytes, bytes]:
    """
    Generate a new ML-DSA signing keypair.
    
    Returns:
        tuple: (public_key, private_key)
            - public_key (bytes): The public verification key
            - private_key (bytes): The private signing key
    
    Raises:
        QSCGError: If key generation fails.
    """
```

#### `sign()`

```python
def sign(self, message: bytes, private_key: bytes, 
         ctx: bytes = b'') -> bytes:
    """
    Sign a message using ML-DSA.
    
    Args:
        message: The message to sign (arbitrary length bytes).
        private_key: The private signing key.
        ctx: Optional context string for domain separation.
             Max length: 255 bytes.
    
    Returns:
        bytes: The signature.
    
    Raises:
        ValueError: If ctx exceeds 255 bytes.
        ValueError: If private_key has incorrect length.
        QSCGError: If signing fails.
    
    Example:
        >>> dsa = MLDSA(level=3)
        >>> pk, sk = dsa.generate_keypair()
        >>> sig = dsa.sign(b"Hello World", sk)
    """
```

#### `verify()`

```python
def verify(self, message: bytes, signature: bytes, 
           public_key: bytes, ctx: bytes = b'') -> bool:
    """
    Verify an ML-DSA signature.
    
    Args:
        message: The original message.
        signature: The signature to verify.
        public_key: The public verification key.
        ctx: Optional context string (must match signing context).
    
    Returns:
        bool: True if signature is valid, False otherwise.
    
    Raises:
        ValueError: If ctx exceeds 255 bytes.
        ValueError: If public_key has incorrect length.
    
    Example:
        >>> is_valid = dsa.verify(b"Hello World", sig, pk)
        >>> assert is_valid
    """
```

#### `get_key_sizes()`

```python
def get_key_sizes(self) -> dict[str, int]:
    """
    Return the key and signature sizes for the configured level.
    
    Returns:
        dict: Dictionary containing:
            - 'public_key': Public key size in bytes
            - 'private_key': Private key size in bytes
            - 'signature': Maximum signature size in bytes
    """
```

### MLDSA Complete Example

```python
from qscg import MLDSA, SecurityLevel

# Initialize with Level 3 security
dsa = MLDSA(level=SecurityLevel.LEVEL_3)

# Generate keypair
public_key, private_key = dsa.generate_keypair()
print(f"Public key size: {len(public_key)} bytes")
print(f"Private key size: {len(private_key)} bytes")

# Sign a message
message = b"This is a quantum-safe signed message."
context = b"application-v1"
signature = dsa.sign(message, private_key, ctx=context)
print(f"Signature size: {len(signature)} bytes")

# Verify signature
is_valid = dsa.verify(message, signature, public_key, ctx=context)
print(f"Signature valid: {is_valid}")

# Try with wrong context
is_invalid = dsa.verify(message, signature, public_key, ctx=b"wrong")
print(f"With wrong context: {is_invalid}")

# Try with tampered message
tampered = message + b"X"
is_invalid = dsa.verify(tampered, signature, public_key, ctx=context)
print(f"With tampered message: {is_invalid}")

# Signature sizes by level
for level in [2, 3, 5]:
    d = MLDSA(level=level)
    sizes = d.get_key_sizes()
    print(f"\nLevel {level}:")
    print(f"  Public key:  {sizes['public_key']:>5} bytes")
    print(f"  Private key: {sizes['private_key']:>5} bytes")
    print(f"  Signature:   {sizes['signature']:>5} bytes")

print("\n✓ ML-DSA operations verified!")
```

---

## SLHDSA Class

**Stateless Hash-Based Digital Signature Algorithm**

Implements FIPS 205: SLH-DSA for conservative, hash-based digital signatures.

### Constructor

```python
class SLHDSA:
    def __init__(self, level: SecurityLevel | int = 1, 
                 hash_type: str = 'shake') -> None:
        """
        Initialize SLH-DSA instance.
        
        Args:
            level: NIST security level (1, 3, or 5). Default is 1.
            hash_type: Hash function family. 'shake' (default) or 'sha2'.
        
        Raises:
            ValueError: If level is not 1, 3, or 5.
            ValueError: If hash_type is not 'shake' or 'sha2'.
        
        Example:
            >>> slh = SLHDSA(level=1, hash_type='shake')
        """
```

### Methods

#### `generate_keypair()`

```python
def generate_keypair(self) -> tuple[bytes, bytes]:
    """
    Generate a new SLH-DSA keypair.
    
    Returns:
        tuple: (public_key, private_key)
            - public_key (bytes): The public key (n bytes)
            - private_key (bytes): The private key (2n bytes)
    
    Raises:
        QSCGError: If key generation fails.
    """
```

#### `sign()`

```python
def sign(self, message: bytes, private_key: bytes,
         ctx: bytes = b'', ph: str = '') -> bytes:
    """
    Sign a message using SLH-DSA.
    
    Args:
        message: The message to sign.
        private_key: The private signing key.
        ctx: Optional context string (max 255 bytes).
        ph: Pre-hash function. '' (default), 'sha256', 'sha512',
            'shake128', or 'shake256'.
    
    Returns:
        bytes: The signature.
    
    Raises:
        ValueError: If ctx exceeds 255 bytes.
        ValueError: If ph is not a valid option.
    """
```

#### `verify()`

```python
def verify(self, message: bytes, signature: bytes,
           public_key: bytes, ctx: bytes = b'',
           ph: str = '') -> bool:
    """
    Verify an SLH-DSA signature.
    
    Args:
        message: The original message.
        signature: The signature to verify.
        public_key: The public verification key.
        ctx: Context string (must match signing context).
        ph: Pre-hash function (must match signing option).
    
    Returns:
        bool: True if signature is valid.
    """
```

#### `get_key_sizes()`

```python
def get_key_sizes(self) -> dict[str, int]:
    """
    Return key and signature sizes.
    
    Returns:
        dict: Dictionary containing:
            - 'public_key': Public key size
            - 'private_key': Private key size
            - 'signature': Signature size
    """
```

### SLHDSA Complete Example

```python
from qscg import SLHDSA, SecurityLevel

# Initialize with Level 1, SHAKE variant
slh = SLHDSA(level=SecurityLevel.LEVEL_1, hash_type='shake')

# Generate keypair
pk, sk = slh.generate_keypair()
print(f"SLH-DSA-128s public key: {len(pk)} bytes")
print(f"SLH-DSA-128s private key: {len(sk)} bytes")

# Sign a message
message = b"Important document to sign"
signature = slh.sign(message, sk)
print(f"Signature size: {len(signature)} bytes")

# Verify
is_valid = slh.verify(message, signature, pk)
print(f"Verification result: {is_valid}")

# Try SHA2 variant
slh_sha2 = SLHDSA(level=1, hash_type='sha2')
pk2, sk2 = slh_sha2.generate_keypair()
sig2 = slh_sha2.sign(message, sk2)
print(f"\nSHA2-128s signature: {len(sig2)} bytes")
print(f"SHA2-128s verify: {slh_sha2.verify(message, sig2, pk2)}")

# Compare levels
for level in [1, 3, 5]:
    s = SLHDSA(level=level, hash_type='shake')
    sizes = s.get_key_sizes()
    print(f"\nSLH-DSA Level {level}:")
    print(f"  Public key:  {sizes['public_key']:>4} bytes")
    print(f"  Private key: {sizes['private_key']:>4} bytes")
    print(f"  Signature:   {sizes['signature']:>5} bytes")

print("\n✓ SLH-DSA operations verified!")
```

---

## AES256GCM Class

**AES-256-GCM Symmetric Encryption**

Classical symmetric cipher used in hybrid encryption constructions.

### Constructor

```python
class AES256GCM:
    def __init__(self, key: bytes | None = None) -> None:
        """
        Initialize AES-256-GCM instance.
        
        Args:
            key: Optional 32-byte key. If None, generates random key.
        
        Raises:
            ValueError: If key is not exactly 32 bytes.
        """
```

### Methods

#### `encrypt()`

```python
def encrypt(self, plaintext: bytes, 
            associated_data: bytes = b'') -> dict[str, bytes]:
    """
        - 'ciphertext': The encrypted data
        - 'nonce': The 12-byte IV
        - 'tag': The 16-byte authentication tag
    """

```

#### `decrypt()`

```python
def decrypt(self, ciphertext: bytes, nonce: bytes,
            tag: bytes, associated_data: bytes = b'') -> bytes:
    """
    Decrypt and authenticate ciphertext.
    
    Args:
        ciphertext: The encrypted data.
        nonce: The 12-byte nonce used during encryption.
        tag: The 16-byte authentication tag.
        associated_data: Additional authenticated data.
    
    Returns:
        bytes: The decrypted plaintext.
    
    Raises:
        ValueError: If authentication fails (tampered data).
    """
```

#### `generate_key()` (static)

```python
@staticmethod
def generate_key() -> bytes:
    """
    Generate a random 32-byte AES-256 key.
    
    Returns:
        bytes: 32-byte random key.
    """
```

### AES256GCM Complete Example

```python
from qscg import AES256GCM

# Generate or provide a key
key = AES256GCM.generate_key()
cipher = AES256GCM(key)

# Encrypt
plaintext = b"Sensitive data to protect"
aad = b"authenticated metadata"

result = cipher.encrypt(plaintext, associated_data=aad)
print(f"Ciphertext: {result['ciphertext'].hex()[:32]}...")
print(f"Nonce:      {result['nonce'].hex()}")
print(f"Tag:        {result['tag'].hex()}")

# Decrypt
decrypted = cipher.decrypt(
    result['ciphertext'],
    result['nonce'],
    result['tag'],
    associated_data=aad
)
print(f"Decrypted:  {decrypted.decode()}")
assert decrypted == plaintext

# Decryption with wrong AAD will fail
try:
    cipher.decrypt(
        result['ciphertext'],
        result['nonce'],
        result['tag'],
        associated_data=b"wrong"
    )
except ValueError as e:
    print(f"Authentication failed as expected: {e}")

print("\n✓ AES-256-GCM operations verified!")
```

---

## HybridKEM Class

**Hybrid Post-Quantum + Classical Key Encapsulation**

Combines ML-KEM with classical X25519 for defense-in-depth.

### Constructor

```python
class HybridKEM:
    def __init__(self, pq_level: SecurityLevel | int = 3) -> None:
        """
        Initialize hybrid KEM.
        
        Args:
            pq_level: Post-quantum security level (1, 3, or 5).
        """
```

### Methods

| Method | Signature | Returns |
|--------|-----------|---------|
| `generate_keypair()` | `()` | `(pq_pk, pq_sk, cl_pk, cl_sk)` |
| `encapsulate()` | `(pq_pk, cl_pk)` | `(ct_pq, ct_cl, ss)` |
| `decapsulate()` | `(ct_pq, ct_cl, pq_sk, cl_sk)` | `ss` |

### HybridKEM Example

```python
from qscg import HybridKEM

hybrid = HybridKEM(pq_level=3)

# Generate combined keypair
pq_pk, pq_sk, cl_pk, cl_sk = hybrid.generate_keypair()

# Encapsulate
ct_pq, ct_cl, shared_secret = hybrid.encapsulate(pq_pk, cl_pk)

# Decapsulate
recovered = hybrid.decapsulate(ct_pq, ct_cl, pq_sk, cl_sk)

assert shared_secret == recovered
print("✓ Hybrid encapsulation verified!")
```

---

## Utility Functions

### `secure_random_bytes()`

```python
def secure_random_bytes(n: int) -> bytes:
    """
    Generate n cryptographically secure random bytes.
    
    Args:
        n: Number of bytes to generate.
    
    Returns:
        bytes: Secure random bytes.
    """
```

### `constant_time_compare()`

```python
def constant_time_compare(a: bytes, b: bytes) -> bool:
    """
    Compare two byte strings in constant time.
    Prevents timing attacks on sensitive comparisons.
    
    Args:
        a: First byte string.
        b: Second byte string.
    
    Returns:
        bool: True if equal, False otherwise.
    """
```

### `encode_base64()` / `decode_base64()`

```python
def encode_base64(data: bytes) -> str:
    """Encode bytes to URL-safe base64 string."""

def decode_base64(data: str) -> bytes:
    """Decode URL-safe base64 string to bytes."""
```

---

## Type Hints Reference

| Type Alias | Definition | Used In |
|------------|-----------|---------|
| `PublicKey` | `bytes` | `generate_keypair()` return |
| `PrivateKey` | `bytes` | `generate_keypair()` return |
| `Ciphertext` | `bytes` | `encapsulate()` return |
| `SharedSecret` | `bytes` | Encapsulation operations |
| `Signature` | `bytes` | `sign()` return |
| `Message` | `bytes` | Sign/verify operations |
| `Context` | `bytes` | Domain separation string |
| `SecurityLevelType` | `int` | Constructor parameter |

### Complete Type Signatures

```python
# MLKEM
def __init__(self, level: SecurityLevelType = 3) -> None: ...
def generate_keypair(self) -> tuple[PublicKey, PrivateKey]: ...
def encapsulate(self, public_key: PublicKey) -> tuple[Ciphertext, SharedSecret]: ...
def decapsulate(self, ciphertext: Ciphertext, private_key: PrivateKey) -> SharedSecret: ...

# MLDSA
def __init__(self, level: SecurityLevelType = 3) -> None: ...
def generate_keypair(self) -> tuple[PublicKey, PrivateKey]: ...
def sign(self, message: Message, private_key: PrivateKey, ctx: Context = b'') -> Signature: ...
def verify(self, message: Message, signature: Signature, public_key: PublicKey, ctx: Context = b'') -> bool: ...

# SLHDSA
def __init__(self, level: SecurityLevelType = 1, hash_type: str = 'shake') -> None: ...
def generate_keypair(self) -> tuple[PublicKey, PrivateKey]: ...
def sign(self, message: Message, private_key: PrivateKey, ctx: Context = b'', ph: str = '') -> Signature: ...
def verify(self, message: Message, signature: Signature, public_key: PublicKey, ctx: Context = b'', ph: str = '') -> bool: ...
```

---

## Exception Classes

```python
class QSCGError(Exception):
    """Base exception for QSCG library errors."""

class KeyGenerationError(QSCGError):
    """Raised when key generation fails."""

class EncapsulationError(QSCGError):
    """Raised when key encapsulation fails."""

class DecapsulationError(QSCGError):
    """Raised when key decapsulation fails."""

class SigningError(QSCGError):
    """Raised when signature generation fails."""

class VerificationError(QSCGError):
    """Raised when signature verification fails."""

class InvalidKeyError(QSCGError):
    """Raised when an invalid key is provided."""

class SecurityLevelError(QSCGError):
    """Raised when an invalid security level is specified."""
```

---

> **Last Updated**: 2025-01-15 | QSCG v2.2.0
>
> API documentation covers all public interfaces. Internal functions are documented in source code docstrings.
