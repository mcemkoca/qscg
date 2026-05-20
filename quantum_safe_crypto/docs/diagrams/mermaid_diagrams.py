"""Mermaid.js diagrams for QSCG v3.0 documentation."""

# Architecture diagram
ARCHITECTURE = """
```mermaid
graph TD
    A[Application] --> B{quantum_safe_crypto}
    B --> C[ML-KEM: Lattice]
    B --> D[HQC: Code-based]
    B --> E[FN-DSA: Compact]
    B --> F[SLH-DSA: Hash]
    C --> G[Hybrid Encryption]
    D --> G
    E --> H[Digital Signature]
    F --> H
```
"""

# Qubit evolution timeline
QUBIT_EVOLUTION = """
```mermaid
graph LR
    A[2012] -->|1B qubits| B[2019]
    B -->|20M qubits| C[2025]
    C -->|1M qubits| D[2026]
    D -->|100K qubits| E[2030?]
    E -->|~25K| F[RSA-2048 Broken]
```
"""

# Algorithm comparison
ALGORITHM_COMPARISON = """
```mermaid
graph TD
    A[Security Requirement] --> B{Data Lifetime}
    B -->|< 5 years| C[ML-KEM-512]
    B -->|5-10 years| D[ML-KEM-768]
    B -->|> 10 years| E[ML-KEM-1024 + SLH-DSA]
    C --> F[Standard Apps]
    D --> G[Banking/IoT]
    E --> H[Government/Classified]
```
"""

# Security proofs
SECURITY_PROOFS = """
```mermaid
graph LR
    A[ML-KEM] -->|MLWE| B[Lattice Reduction]
    C[HQC] -->|QC-MDPC| D[Code Decoding]
    E[FN-DSA] -->|SIS| F[Shortest Vector]
    G[SLH-DSA] -->|Collision| H[Hash Function]
```
"""

if __name__ == "__main__":
    print(ARCHITECTURE)
    print(QUBIT_EVOLUTION)
    print(ALGORITHM_COMPARISON)
    print(SECURITY_PROOFS)
