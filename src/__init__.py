"""
QSCG - Quantum-Safe Cryptography GitHub Repository

Professional post-quantum cryptographic toolkit.
Implements NIST FIPS 203 (ML-KEM), FIPS 204 (ML-DSA),
FIPS 205 (SLH-DSA) with AES-256-GCM hybrid layer.

Usage:
    >>> from qscg import MLKEM, MLDSA, AES256GCM
    >>> kem = MLKEM(level=SecurityLevel.LEVEL_3)
    >>> kp = kem.keygen()
"""

__version__ = "4.0.1"
__author__ = "Mehmet Cem Koca (mcemkoca)"
__license__ = "MIT"
__all__ = [
    "SecurityLevel",
    "LatticeParameters",
    "PolynomialRing",
    "ModuleLattice",
    "MLKEM",
    "MLKEMKeyPair",
    "MLKEMCiphertext",
    "MLDSA",
    "MLDSASignature",
    "CryptoComparison",
    "LWEProblems",
    "QuantumResistanceAnalysis",
    "NISTPQCStandards2026",
    "HarvestNowDecryptLater",
    "HybridCryptography",
    "utils",
]

# Package-level imports (lazy to avoid circular imports)
def _get_mlkem():
    from .lattice_crypto import MLKEM
    return MLKEM

def _get_mldsa():
    from .lattice_crypto import MLDSA
    return MLDSA

# Version info
def version_info():
    """Return detailed version information."""
    return {
        "version": __version__,
        "author": __author__,
        "license": __license__,
        "nist_standards": ["FIPS 203", "FIPS 204", "FIPS 205"],
        "algorithms": ["ML-KEM", "ML-DSA", "SLH-DSA", "AES-256-GCM"],
    }
