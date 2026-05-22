# Related Open-Source Projects & References

> **QSCG v4.0 — Curated list of GitHub projects related to quantum-safe cryptography**
> **Last Updated:** 2026-05-22

---

## 🔐 Post-Quantum Cryptography (Direct Competitors / References)

### NIST Reference Implementations

| Project | Stars | Language | Standard | URL |
|---------|-------|----------|----------|-----|
| **pq-crystals/kyber** | ⭐ 1.2k | C | ML-KEM (FIPS 203) | <https://github.com/pq-crystals/kyber> |
| **pq-crystals/dilithium** | ⭐ 589 | C | ML-DSA (FIPS 204) | <https://github.com/pq-crystals/dilithium> |
| **sphincs/sphincsplus** | ⭐ 225 | C | SLH-DSA (FIPS 205) | <https://github.com/sphincs/sphincsplus> |
| **PQClean/PQClean** | ⭐ 920 | C | All NIST finalists | <https://github.com/PQClean/PQClean> |

### Comprehensive Libraries

| Project | Stars | Language | Description | URL |
|---------|-------|----------|-------------|-----|
| **open-quantum-safe/liboqs** | ⭐ 2.9k | C | Prototyping PQC library | <https://github.com/open-quantum-safe/liboqs> |
| **open-quantum-safe/liboqs-python** | ⭐ 237 | Python | Python bindings for liboqs | <https://github.com/open-quantum-safe/liboqs-python> |
| **rustpq/pqcrypto** | ⭐ 398 | Rust | Rust PQC implementations | <https://github.com/rustpq/pqcrypto> |
| **paulmillr/noble-post-quantum** | ⭐ 324 | TypeScript | JS ML-KEM/ML-DSA/SLH-DSA/FALCON | <https://github.com/paulmillr/noble-post-quantum> |

### Python Implementations (Our Benchmark Targets)

| Project | Stars | Focus | URL |
|---------|-------|-------|-----|
| **GiacomoPope/kyber-py** | ⭐ 298 | Pure Python ML-KEM | <https://github.com/GiacomoPope/kyber-py> |
| **tprest/falcon.py** | ⭐ 196 | Python Falcon signatures | <https://github.com/tprest/falcon.py> |
| **pq-code-package/mlkem-native** | ⭐ 192 | Secure C90 ML-KEM (formal verification) | <https://github.com/pq-code-package/mlkem-native> |

### Network / Application Security

| Project | Stars | Language | Description | URL |
|---------|-------|----------|-------------|-----|
| **quincy-rs/quincy** | ⭐ 302 | Rust | Post-quantum QUIC VPN | <https://github.com/quincy-rs/quincy> |
| **veil-net/conflux** | ⭐ 507 | Go | Decentralized PQC network | <https://github.com/veil-net/conflux> |
| **Avarok-Cybersecurity/Citadel-Protocol** | ⭐ 160 | Rust | PQC messaging SDK | <https://github.com/Avarok-Cybersecurity/Citadel-Protocol> |
| **sbom-tool/sbom-tools** | ⭐ 219 | Rust | PQC compliance / CNSA 2.0 | <https://github.com/sbom-tool/sbom-tools> |

### Curated Lists

| Project | Stars | Description | URL |
|---------|-------|-------------|-----|
| **veorq/awesome-post-quantum** | ⭐ 472 | PQC resources list | <https://github.com/veorq/awesome-post-quantum> |

---

## ⚛️ Quantum Computing (Threat Simulation)

### Major SDKs

| Project | Stars | Org | Language | URL |
|---------|-------|-----|----------|-----|
| **Qiskit** | ⭐ 7.4k | IBM | Python/C/Rust | <https://github.com/Qiskit/qiskit> |
| **Cirq** | ⭐ 5.0k | Google | Python | <https://github.com/quantumlib/Cirq> |
| **QuantumKatas** | ⭐ 4.9k | Microsoft | Q# | <https://github.com/microsoft/QuantumKatas> |
| **PennyLane** | ⭐ 3.2k | Xanadu | Python | <https://github.com/PennyLaneAI/pennylane> |
| **TensorFlow Quantum** | ⭐ 2.1k | Google | Python | <https://github.com/tensorflow/quantum> |

### Simulators (Shor's Algorithm / Cryptanalysis)

| Project | Stars | Language | Focus | URL |
|---------|-------|----------|-------|-----|
| **qsim** | ⭐ 661 | C++ | State-vector simulation | <https://github.com/quantumlib/qsim> |
| **qiskit-aer** | ⭐ 665 | C++ | Noise modeling | <https://github.com/Qiskit/qiskit-aer> |
| **NVIDIA/cuda-quantum** | ⭐ 1.0k | C++/Python | GPU quantum | <https://github.com/NVIDIA/cuda-quantum> |
| **QuTiP** | ⭐ 2.0k | Python | Quantum toolbox | <https://github.com/qutip/qutip> |
| **Quirk** | ⭐ 1.1k | JavaScript | Browser simulator | <https://github.com/Strilanc/Quirk> |

### Research / Analysis

| Project | Stars | Focus | URL |
|---------|-------|-------|-----|
| **GiacomoPope/Castryck-Decru-SageMath** | ⭐ 140 | SIDH attack (isogenies broken) | <https://github.com/GiacomoPope/Castryck-Decru-SageMath> |
| **slothy-optimizer/slothy** | ⭐ 325 | Assembly super-optimization for PQC | <https://github.com/slothy-optimizer/slothy> |

### Curated Lists

| Project | Stars | Description | URL |
|---------|-------|-------------|-----|
| **awesome-quantum-computing** | ⭐ 3.2k | Quantum computing resources | <https://github.com/desireevl/awesome-quantum-computing> |
| **awesome-quantum-machine-learning** | ⭐ 3.5k | QML resources | <https://github.com/krishnakumarsekar/awesome-quantum-machine-learning> |
| **qosf/awesome-quantum-software** | ⭐ 2.1k | Quantum software list | <https://github.com/qosf/awesome-quantum-software> |

---

## 🎯 QSCG Integration Opportunities

```
┌─────────────────────────────────────────────────────────────┐
│                    QSCG v4.0 Ecosystem                       │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  [liboqs C backend] ──ctypes──→ [QSCG Python Core]           │
│       ↑                           ↓                         │
│   Performance                  ML-KEM / ML-DSA / SLH-DSA    │
│       ↑                           ↓                         │
│  [kyber-py] ←──validation──→ [NTT + Gaussian]             │
│       ↑                           ↓                         │
│  Cross-test                  [CustomTkinter GUI]              │
│                                  ↓                          │
│                              [AI Agent]                      │
│                                  ↓                          │
│  [Qiskit] ←──threat sim──→ [Quantum Threat Timeline]        │
│                                  ↓                          │
│                              [Industry Maps]                 │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Recommended GitHub Topics for QSCG Repo

Add these topics to `https://github.com/mcemkoca/qscg` for discoverability:

```
post-quantum-cryptography, quantum-computing, ml-kem, ml-dsa, slh-dsa,
lattice-based-crypto, nist-fips-203, nist-fips-204, nist-fips-205,
cryptography, python, customtkinter, ai-agent, quantum-threat,
nist-pqc, cybersecurity, quantum-safe, pqc
```

---

## 📚 Academic References Available on GitHub

| Paper | GitHub Resource | Stars |
|-------|----------------|-------|
| Gidney & Ekera 2024 (RSA-2048) | qsim + qiskit-aer | ⭐ 1,300+ combined |
| Google Quantum AI 2026 (ECDLP) | Cirq + TensorFlow Quantum | ⭐ 7,000+ combined |
| Castryck-Decru SIDH Attack | Castryck-Decru-SageMath | ⭐ 140 |
| NIST FIPS 203/204/205 | pq-crystals (kyber + dilithium) | ⭐ 1,800+ combined |

---

*Maintained by QSCG Research Team | M.Cem Koca {Deuterium12}*
