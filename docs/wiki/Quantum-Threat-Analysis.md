# Quantum Threat Analysis and Migration Guide

> **Comprehensive analysis of quantum computing threats to cryptography and practical migration strategies.**
>
> This document provides a detailed technical and strategic analysis for organizations preparing for the post-quantum transition.

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [Shor's Algorithm Impact](#shors-algorithm-impact)
3. [Grover's Algorithm Impact](#grovers-algorithm-impact)
4. [Harvest Now Decrypt Later (HNDL)](#harvest-now-decrypt-later-hndl)
5. [NIST Migration Timeline (2024-2035)](#nist-migration-timeline-2024-2035)
6. [CNSA 2.0 Requirements](#cnsa-20-requirements)
7. [Hybrid Cryptography Strategies](#hybrid-cryptography-strategies)
8. [Recommended Protection Strategies](#recommended-protection-strategies)
9. [Sector-Based Recommendations](#sector-based-recommendations)
10. [Implementation Roadmap](#implementation-roadmap)
11. [Resources and References](#resources-and-references)

---

## Executive Summary

Quantum computers pose an existential threat to the cryptographic infrastructure protecting global communications, financial systems, and sensitive data. Two quantum algorithms in particular---Shor's algorithm and Grover's algorithm---fundamentally undermine the security assumptions of current cryptographic standards.

| Threat | Affected Algorithms | Impact | Timeline |
|--------|---------------------|--------|----------|
| Shor's Algorithm | RSA, ECC, DH, DSA | Complete break | 2030-2035 |
| Grover's Algorithm | AES-128, SHA-256 | Security halved | Already relevant |
| HNDL Attack | All classical crypto | Retroactive decryption | Ongoing |

**Immediate Action Required**: Organizations must begin cryptographic inventories and migration planning now, even before quantum computers are available, due to the Harvest Now, Decrypt Later threat model.

---

## Shor's Algorithm Impact

### Mathematical Foundation

Shor's algorithm (1994) solves the integer factorization and discrete logarithm problems in polynomial time on a quantum computer:

```
Classical complexity for factoring N-bit integer:
  Best classical: O(exp((ln N)^(1/3) * (ln ln N)^(2/3)))
  
Shor's quantum algorithm: O((log N)^3)
  
For RSA-2048:
  Classical: ~10^29 operations (infeasible)
  Quantum:   ~10^9 operations (feasible)
```

### Affected Cryptosystems

| Algorithm | Problem Shor Solves | Security After Quantum |
|-----------|---------------------|----------------------|
| **RSA** | Integer factorization | Completely broken |
| **ECC (P-256, P-384, P-521)** | Elliptic curve discrete log | Completely broken |
| **Diffie-Hellman** | Discrete logarithm | Completely broken |
| **DSA/ECDSA** | Discrete logarithm | Completely broken |
| **ElGamal** | Discrete logarithm | Completely broken |
| **ML-KEM** | Module-LWE | **Secure** |
| **ML-DSA** | Module-SIS/MLWE | **Secure** |
| **SLH-DSA** | Hash preimage | **Secure** |

### Breaking RSA with Shor's Algorithm

```
Step 1: Choose random a < N, compute gcd(a, N)
Step 2: If gcd != 1, found factor
Step 3: Find period r of a^x mod N using quantum Fourier transform
Step 4: If r is odd, choose new a
Step 5: Factors are gcd(a^(r/2) ± 1, N)

Quantum operations required:
  - Number of qubits: ~2n (for n-bit modulus)
  - For RSA-2048: ~4096 logical qubits
  - With error correction: ~millions of physical qubits
```

### Quantum Resource Estimates for Breaking RSA

| RSA Key Size | Logical Qubits | Physical Qubits (est.) | Time (est.) |
|-------------|---------------|----------------------|-------------|
| RSA-1024 | 2,048 | ~20 million | Hours |
| RSA-2048 | 4,096 | ~50 million | Days |
| RSA-3072 | 6,144 | ~100 million | Weeks |
| RSA-4096 | 8,192 | ~200 million | Months |

**Current State**: IBM's Condor (2023) has 1,121 qubits. Estimated need: millions of error-corrected qubits. Most experts estimate 2030-2040 for cryptographically-relevant quantum computers.

---

## Grover's Algorithm Impact

### Mathematical Foundation

Grover's algorithm (1996) provides a quadratic speedup for unstructured search:

```
Classical search in unsorted database of N items:
  Classical: O(N) queries
  Grover's:  O(sqrt(N)) queries
  
For AES key search:
  AES-128: Classical O(2^128) -> Quantum O(2^64)
  AES-256: Classical O(2^256) -> Quantum O(2^128)
```

Unlike Shor's algorithm, Grover's algorithm does **not** completely break symmetric cryptography. It reduces security by half (in terms of bit strength).

### Impact on Symmetric Algorithms

| Algorithm | Classical Security | Quantum Security | Mitigation |
|-----------|-------------------|------------------|------------|
| AES-128 | 128 bits | 64 bits | **Insufficient** - must upgrade |
| AES-192 | 192 bits | 96 bits | Marginal - consider upgrade |
| AES-256 | 256 bits | 128 bits | **Secure** - sufficient against quantum |
| SHA-256 | 128-bit collision | 85-bit collision | Use SHA-384/SHA3-256 for 128-bit quantum |
| SHA-384 | 192-bit collision | 128-bit collision | **Secure** |

### Practical Implications

```
Pre-quantum recommendation:
  AES-128, SHA-256 -> Sufficient for most use cases

Post-quantum recommendation:
  AES-256, SHA-384 -> Required for quantum resistance
  
Double key length principle:
  Symmetric keys: Double the key length for same security
  Hash outputs: Double the output length for same security
```

---

## Harvest Now Decrypt Later (HNDL)

### Threat Model

The HNDL attack represents the most immediate quantum threat:

```
Timeline of HNDL Attack:

2025: Adversary (nation-state) intercepts and stores encrypted data
      - VPN traffic
      - TLS handshakes
      - Encrypted emails
      - Financial transactions
      - Government communications
      
      Storage cost: ~$1M per PB per year
      
2035: Quantum computer becomes available
      - Decrypt all stored RSA/ECC traffic
      - Extract secrets retroactively
      
      Cost of decryption: Finite and decreasing
      
Result: All historical communications compromised
```

### Risk Assessment Matrix

| Data Type | Retention Period | HNDL Risk | Recommended Action |
|-----------|-----------------|-----------|-------------------|
| Military/Intelligence Communications | 50+ years | **CRITICAL** | Migrate immediately |
| Financial Records | 7-10 years | **CRITICAL** | Begin migration now |
| Healthcare Records | 7+ years (HIPAA) | **HIGH** | Plan migration within 2 years |
| Government Communications | 25+ years | **CRITICAL** | CNSA 2.0 compliance required |
| TLS Session Keys | Ephemeral | **MEDIUM** | Implement hybrid key exchange |
| Short-lived Messages | Hours-days | **LOW** | May be obsolete |
| Personal Communications | Variable | **MEDIUM** | Awareness and gradual migration |

### HNDL Mitigation Timeline

```
2025-2027: Crypto inventory and risk assessment
2027-2029: Deploy hybrid encryption for all long-term data
2029-2032: Full PQC migration for critical systems
2032-2035: Complete deprecation of classical algorithms
2035+: Quantum-safe only
```

---

## NIST Migration Timeline (2024-2035)

### Official Timeline

| Year | Milestone | Details |
|------|-----------|---------|
| **2024** | FIPS 203, 204, 205 Published | NIST releases final PQC standards |
| **2025** | CNSA 2.0 Guidance | NSA publishes Commercial National Security Algorithm Suite 2.0 |
| **2026** | Initial Vendor Support | Major TLS libraries add PQC support |
| **2027** | Federal Agency Planning | U.S. government agencies submit migration plans |
| **2028** | ML-KEM Required | ML-KEM mandatory for sensitive federal data |
| **2030** | ML-DSA Required | PQC signatures required for federal systems |
| **2032** | Classical Deprecation | RSA and ECC deprecated for sensitive use |
| **2035** | Full Transition | Complete migration to PQC for all systems |

### Migration Phases

```
Phase 1: Discovery (2025-2026)
  - Inventory all cryptographic assets
  - Classify data by sensitivity and lifetime
  - Identify dependencies on classical algorithms
  - Assess vendor PQC support

Phase 2: Planning (2026-2027)
  - Develop migration roadmap
  - Select PQC algorithms (ML-KEM, ML-DSA, SLH-DSA)
  - Design hybrid architectures
  - Establish testing environments

Phase 3: Hybrid Deployment (2027-2029)
  - Deploy hybrid key exchange
  - Add PQC signatures alongside classical
  - Update TLS/SSL configurations
  - Begin certificate migration

Phase 4: Full Migration (2029-2032)
  - Remove classical-only endpoints
  - Transition to PQC-only where possible
  - Update all cryptographic libraries
  - Retire legacy systems

Phase 5: Complete Transition (2032-2035)
  - Deprecate all classical algorithms
  - Maintain hybrid for interoperability
  - Continuous PQC security monitoring
  - Prepare for future PQC standards
```

---

## CNSA 2.0 Requirements

The NSA's Commercial National Security Algorithm Suite 2.0 (CNSA 2.0) provides specific guidance for national security systems.

### CNSA 2.0 Algorithm Suite

| Purpose | CNSA 2.0 Algorithm | Parameters | Status |
|---------|-------------------|------------|--------|
| Key Encapsulation | ML-KEM | Level 5 (ML-KEM-1024) | Required |
| Digital Signature | ML-DSA | Level 5 (ML-DSA-87) | Required |
| Alternative Signature | SLH-DSA | Level 5 (SLH-DSA-256s) | Acceptable |
| Symmetric Encryption | AES-256 | GCM mode | Required |
| Hash Function | SHA-384 | - | Required |
| Alternative Hash | SHA-512 | - | Acceptable |

### CNSA 2.0 Transition Timeline

| Date | Requirement |
|------|-------------|
| **Now** | Software/firmware signing must use PQC |
| **2025** | Web browsers and cloud services support PQC |
| **2026** | Traditional VPNs migrate to PQC |
| **2027** | All NSS must support PQC in OS and applications |
| **2030** | Full CNSA 2.0 compliance required |

### Compliance Checklist

```
□ Software/Firmware Signing
  □ Code signing certificates use ML-DSA or SLH-DSA
  □ Update signing infrastructure
  □ Verify signature validation support

□ Web Services
  □ TLS 1.3 with hybrid key exchange
  □ Support ML-KEM in TLS handshake
  □ Browser/client compatibility verified

□ VPN/Network Security
  □ IKEv3 with PQC support
  □ ML-KEM for key establishment
  □ Network equipment firmware updated

□ Cloud Services
  □ Cloud provider PQC support confirmed
  □ KMS integration with PQC algorithms
  □ Data at rest encryption updated

□ Operating Systems
  □ OS crypto libraries updated
  □ Kernel PQC support verified
  □ Application compatibility tested
```

---

## Hybrid Cryptography Strategies

### What is Hybrid Cryptography?

Hybrid cryptography combines classical and post-quantum algorithms to provide defense-in-depth:

```
Traditional (Vulnerable):
  Client ----RSA/ECDH----> Server
  
Hybrid (Protects against both classical and quantum):
  Client ----ML-KEM + X25519----> Server
  
  Shared Secret = KDF(ML-KEM_secret || X25519_secret)
  
  Benefits:
  - If X25519 broken: ML-KEM still secures
  - If ML-KEM broken: X25519 still secures
  - If both broken: attacker needs to break both independently
```

### Hybrid Construction in QSCG

```python
from qscg import HybridKEM

# Initialize hybrid KEM with PQ Level 3 + classical X25519
hybrid = HybridKEM(pq_level=3)

# Generate combined keypair
pq_pk, pq_sk, cl_pk, cl_sk = hybrid.generate_keypair()

# Encapsulate: both PQ and classical
ct_pq, ct_cl, shared_secret = hybrid.encapsulate(pq_pk, cl_pk)

# Decapsulate: recover from both
decrypted = hybrid.decapsulate(ct_pq, ct_cl, pq_sk, cl_sk)

assert shared_secret == decrypted
```

### Security Analysis of Hybrid Schemes

| Attack Model | Classical Only | Quantum | Defense Status |
|-------------|---------------|---------|---------------|
| Classical attacker | X25519 secure | N/A | Secure |
| Future quantum | ML-KEM secure | ML-KEM + Grover | Secure |
| Unknown weakness | One algorithm compensates | - | Defense-in-depth |

---

## Recommended Protection Strategies

### Strategy 1: Crypto Agility

Design systems that can switch cryptographic algorithms without major changes:

```python
# Example: Algorithm negotiation
ALGORITHMS = {
    'kem': {
        'ML-KEM-768': MLKEM(level=3),
        'ML-KEM-1024': MLKEM(level=5),
        'hybrid': HybridKEM(pq_level=3),
    },
    'sig': {
        'ML-DSA-65': MLDSA(level=3),
        'SLH-DSA-128s': SLHDSA(level=1),
    }
}

def negotiate_algorithm(client_prefs, server_prefs):
    """Select best mutually supported algorithm."""
    for alg in client_prefs:
        if alg in server_prefs:
            return ALGORITHMS[alg]
    raise NoCommonAlgorithmError()
```

### Strategy 2: Layered Encryption

Encrypt sensitive data with multiple layers:

```
Layer 1: ML-KEM key encapsulation
Layer 2: AES-256-GCM symmetric encryption
Layer 3: SLH-DSA signature for authentication

Breaking requires defeating all three independently.
```

### Strategy 3: Forward Secrecy with PQC

```python
from qscg import MLKEM

# Ephemeral key exchange for each session
kem = MLKEM(level=3)

# Generate ephemeral keys (discarded after session)
ephemeral_pk, ephemeral_sk = kem.generate_keypair()

# Use for single session only
# Keys never stored long-term
# Compromise of long-term keys doesn't reveal past sessions
```

### Strategy 4: Crypto Inventory and Monitoring

```python
"""
Cryptographic Asset Inventory Template

For each system/application, document:
1. Algorithm names and parameters
2. Key lifetimes and rotation schedules
3. Data classification levels
4. Compliance requirements
5. Migration priority
"""

inventory = [
    {
        'system': 'Payment Gateway',
        'algorithm': 'RSA-2048',
        'data_class': 'PCI-DSS',
        'priority': 'CRITICAL',
        'target_date': '2027-01',
        'replacement': 'ML-KEM-768 + ML-DSA-65'
    },
    {
        'system': 'Internal VPN',
        'algorithm': 'ECDH P-256',
        'data_class': 'INTERNAL',
        'priority': 'HIGH',
        'target_date': '2028-06',
        'replacement': 'Hybrid ML-KEM-768 + X25519'
    }
]
```

---

## Sector-Based Recommendations

### Financial Services

| Aspect | Recommendation | Priority |
|--------|---------------|----------|
| Payment Processing | Migrate to ML-KEM for key exchange | Critical |
| Transaction Signing | Deploy ML-DSA for transaction signatures | Critical |
| Document Signing | Use SLH-DSA for long-term document signatures | High |
| TLS/HTTPS | Implement hybrid key exchange | High |
| Compliance | Meet PCI-DSS quantum requirements | Critical |

**Specific Actions:**
- Audit all encryption in payment processing chains
- Update HSM firmware for PQC support
- Train security teams on PQC algorithms
- Engage with payment networks on PQC migration timeline

### Healthcare

| Aspect | Recommendation | Priority |
|--------|---------------|----------|
| Patient Records | AES-256 + ML-KEM for data protection | Critical |
| Digital Prescriptions | ML-DSA for prescription signing | High |
| Medical Imaging | Hybrid encryption for image transmission | Medium |
| Telemedicine | PQC-secured real-time communications | High |
| Compliance | HIPAA + quantum readiness | Critical |

**Specific Actions:**
- Inventory all encrypted patient data
- Update EHR systems with PQC libraries
- Ensure medical device firmware supports updates
- Document encryption methods for compliance audits

### Government

| Aspect | Recommendation | Priority |
|--------|---------------|----------|
| Classified Communications | CNSA 2.0 Level 5 (ML-KEM-1024) | Critical |
| Citizen Data | ML-KEM-768 minimum | Critical |
| Digital Signatures | ML-DSA-87 or SLH-DSA-256s | Critical |
| Inter-agency Comms | Hybrid encryption mandatory | Critical |
| Compliance | NIST/CNSA 2.0 full compliance | Critical |

**Specific Actions:**
- Implement CNSA 2.0 algorithm suite
- Update all NSS by 2030
- Classify all data by quantum vulnerability
- Establish quantum-readiness task forces

### Military/Defense

| Aspect | Recommendation | Priority |
|--------|---------------|----------|
| All Communications | CNSA 2.0 Level 5, no exceptions | Critical |
| Weapons Systems | Air-gapped PQC implementation | Critical |
| Satellite Comms | ML-KEM-1024 + AES-256 | Critical |
| Supply Chain | PQC-signed firmware and software | Critical |
| Compliance | Immediate CNSA 2.0 adoption | Critical |

### Technology/Enterprise

| Aspect | Recommendation | Priority |
|--------|---------------|----------|
| Cloud Services | Implement PQC in TLS configurations | High |
| API Security | ML-KEM for API key exchange | High |
| Code Signing | SLH-DSA for software signatures | High |
| DevOps | PQC-enabled CI/CD pipelines | Medium |
| Customer Data | Hybrid encryption for data at rest | High |

---

## Implementation Roadmap

### Phase 1: Immediate (2025-2026)

```
Week 1-4:   Crypto inventory of all systems
Week 5-8:   Risk assessment and prioritization
Week 9-12:  Install QSCG and run --analysis
Week 13-16: Pilot PQC on non-critical systems
Week 17-20: Develop migration plan
Week 21-24: Begin hybrid deployment
```

### Phase 2: Short-term (2026-2028)

```
- Deploy ML-KEM for all key exchange
- Add ML-DSA for digital signatures
- Implement hybrid TLS configurations
- Update all cryptographic libraries
- Train development teams
- Establish PQC monitoring
```

### Phase 3: Medium-term (2028-2032)

```
- Remove classical-only endpoints
- Full PQC for critical systems
- Update compliance documentation
- Deprecate RSA/ECC for new deployments
- Continuous security assessment
```

### Phase 4: Long-term (2032-2035)

```
- Complete migration to PQC
- Maintain hybrid for interoperability
- Monitor for new quantum threats
- Prepare for next-generation PQC standards
```

---

## Resources and References

### NIST Standards and Publications

1. **FIPS 203** - *Module-Lattice-Based Key-Encapsulation Mechanism Standard* (August 2024)
2. **FIPS 204** - *Module-Lattice-Based Digital Signature Standard* (August 2024)
3. **FIPS 205** - *Stateless Hash-Based Digital Signature Standard* (August 2024)
4. **NIST IR 8547** - *Transition to Post-Quantum Cryptography Standards* (2024)
5. **NIST SP 800-208** - *Recommendation for Stateful Hash-Based Signature Schemes*
6. **NIST CSRC** - https://csrc.nist.gov/projects/post-quantum-cryptography

### NSA Publications

7. **CNSA 2.0** - *Commercial National Security Algorithm Suite 2.0* (September 2022)
8. **NSA Cybersecurity Information** - https://www.nsa.gov/Cybersecurity/

### Academic Papers

9. Shor, P.W. - *Algorithms for Quantum Computation* (1994)
10. Grover, L.K. - *A Fast Quantum Mechanical Algorithm for Database Search* (1996)
11. Bernstein, D.J. and Lange, T. - *Post-Quantum Cryptography* (Nature, 2017)
12. Avanzi, R. et al. - *CRYSTALS-Kyber Algorithm Specifications*
13. Ducas, L. et al. - *CRYSTALS-Dilithium Algorithm Specifications*
14. Hulsing, A. et al. - *SPHINCS+ Algorithm Specifications*

### Industry Resources

15. **PQCrypto.org** - https://pqcrypto.org/
16. **Open Quantum Safe** - https://openquantumsafe.org/
17. **Cloudflare Post-Quantum** - https://blog.cloudflare.com/tag/post-quantum/
18. **Google PQC** - https://security.googleblog.com/search/label/post-quantum%20cryptography

### Quantum Computing Progress

19. **IBM Quantum Roadmap** - https://www.ibm.com/roadmaps/quantum/
20. **Google Quantum AI** - https://quantumai.google/

### QSCG Project

21. **GitHub Repository** - https://github.com/mcemkoca/qscg
22. **Issue Tracker** - https://github.com/mcemkoca/qscg/issues
23. **PyPI Package** - https://pypi.org/project/qscg

---

> **Last Updated**: 2025-01-15 | QSCG v2.2.0
>
> This threat analysis is based on publicly available information and NIST/NSA publications. For classified or mission-critical applications, consult with your organization's security team and relevant authorities.
