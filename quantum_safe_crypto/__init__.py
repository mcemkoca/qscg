"""
quantum_safe_crypto - Post-Quantum Cryptography Toolkit v3.0.0

NIST FIPS 203/204/205 + HQC (IR 8545) + FN-DSA (FIPS 206 draft)
"""

__version__ = "3.0.0"
__author__ = "Mehmet Cem Koca (mcemkoca)"
__license__ = "MIT"

__all__ = [
    "SecurityLevel",
    "HQC_KEM",
    "FN_DSA",
    "QuantumThreatAnalyzer",
    "QUIC_PQC",
    "Signal_PQC",
    "WireGuard_PQC",
]

# Lazy imports to avoid circular dependencies
def _get_hqc():
    from .hqc import HQC_KEM
    return HQC_KEM

def _get_fndsa():
    from .fndsa import FN_DSA
    return FN_DSA

def _get_analyzer():
    from .quantum_threat import QuantumThreatAnalyzer
    return QuantumThreatAnalyzer
