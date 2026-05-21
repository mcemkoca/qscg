"""QSCG Quantum Module — Quantum Random Number Generation.

This module provides quantum-computing-based random number generation
using quantum superposition and measurement principles. It serves as
the ultimate entropy source for post-quantum cryptographic algorithms.

Classes:
    Qubit: Single qubit with superposition state.
    QuantumRegister: Multi-qubit quantum register.
    QuantumRNG: Cryptographically secure quantum random number generator.

Functions:
    generate_quantum_seed: Generate quantum-random seeds for QSCG algorithms.
    benchmark_qrng: Benchmark QRNG performance and entropy quality.

Example:
    >>> from qscg.quantum import QuantumRNG, generate_quantum_seed
    >>> qrng = QuantumRNG(n_qubits=16)
    >>> seed = qrng.random_bytes(32)
    >>> seed_hex = seed.hex()
"""

from .qrng import Qubit, QuantumRegister, QuantumRNG, generate_quantum_seed, benchmark_qrng

__all__ = [
    "Qubit",
    "QuantumRegister",
    "QuantumRNG",
    "generate_quantum_seed",
    "benchmark_qrng",
]
