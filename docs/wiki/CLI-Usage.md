# CLI Usage Guide

> **QSCG Command-Line Interface Reference**
>
> Complete guide for the `qscg` command-line tool with all commands, options, examples, and troubleshooting.

---

## Table of Contents

1. [Installation](#installation)
2. [Command Overview](#command-overview)
3. [Global Options](#global-options)
4. [Command Reference](#command-reference)
5. [Security Level Options](#security-level-options)
6. [Usage Scenarios](#usage-scenarios)
7. [Error Messages and Solutions](#error-messages-and-solutions)
8. [Output Formats](#output-formats)
9. [Scripting Examples](#scripting-examples)
10. [Environment Variables](#environment-variables)

---

## Installation

### From PyPI (Recommended)

```bash
# Install latest stable version
pip install qscg

# Verify installation
qscg --version
# Output: qscg 2.2.0
```

### From Source

```bash
# Clone the repository
git clone https://github.com/mcemkoca/qscg.git
cd qscg

# Install in development mode
pip install -e .

# Verify
qscg --version
```

### Requirements

| Requirement | Minimum Version | Notes |
|-------------|----------------|-------|
| Python | 3.9 | 3.11+ recommended for best performance |
| pip | 21.0 | For dependency resolution |
| Memory | 256 MB | Sufficient for all operations |
| Disk | 50 MB | For installation and key storage |

### Optional Dependencies

```bash
# Install with development dependencies
pip install qscg[dev]

# Install with performance optimizations
pip install qscg[optimized]
```

---

## Command Overview

| Command | Description | Section |
|---------|-------------|---------|
| `qscg --help` | Display help message | [Help](#--help) |
| `qscg --version` | Display version information | [Version](#--version) |
| `qscg --test` | Run algorithm test suite | [Test](#--test) |
| `qscg --kem` | Run ML-KEM operations | [KEM](#--kem) |
| `qscg --dsa` | Run ML-DSA operations | [DSA](#--dsa) |
| `qscg --slh` | Run SLH-DSA operations | [SLH](#--slh) |
| `qscg --aes` | Run AES-256-GCM operations | [AES](#--aes) |
| `qscg --analysis` | Run quantum threat analysis | [Analysis](#--analysis) |
| `qscg --nist` | Run NIST compliance check | [NIST](#--nist) |
| `qscg --hndl` | Run HNDL analysis | [HNDL](#--hndl) |
| `qscg --hybrid` | Run hybrid encryption test | [Hybrid](#--hybrid) |

---

## Global Options

```
Global Options:
  -h, --help          Show help message and exit
  -V, --version       Show program version and exit
  -v, --verbose       Enable verbose output (repeat for more detail)
  -q, --quiet         Suppress non-error output
  --level {1,3,5}     Set NIST security level (default: 3)
  --hash {shake,sha2} Set hash type for SLH-DSA (default: shake)
  --output FILE       Save output to file
  --json              Output results in JSON format
  --no-color          Disable colored output
```

---

## Command Reference

### `--help`

Display comprehensive help with all available commands and options.

```bash
$ qscg --help
```

**Example Output:**
```
QSCG - Quantum-Safe Cryptography GitHub Repository v2.2.0
Post-Quantum Cryptography Toolkit

Usage: qscg [OPTIONS]

Options:
  -h, --help            Show this help message and exit
  -V, --version         Show version and exit
  -v, --verbose         Verbose output (-vv for debug)
  -q, --quiet           Suppress non-error output
  --level {1,3,5}       Security level (default: 3)
  --hash {shake,sha2}   SLH-DSA hash function
  --output FILE         Write output to file
  --json                JSON output format
  --no-color            Disable ANSI colors

Commands:
  --test                Run all algorithm tests
  --kem                 Run ML-KEM key encapsulation
  --dsa                 Run ML-DSA signature tests
  --slh                 Run SLH-DSA signature tests
  --aes                 Run AES-256-GCM tests
  --analysis            Run quantum threat analysis
  --nist                Check NIST compliance
  --hndl                Run HNDL analysis
  --hybrid              Run hybrid encryption test
```

---

### `--version`

Display version information, Python version, and installed dependencies.

```bash
$ qscg --version
```

**Example Output:**
```
QSCG - Quantum-Safe Cryptography GitHub Repository
Version: 2.2.0
Python: 3.12.1 (CPython)
Platform: Linux x86_64
NIST Standards: FIPS 203, FIPS 204, FIPS 205
Build: release
Date: 2025-01-15
```

---

### `--test`

Run the complete algorithm test suite covering all three NIST standards.

```bash
# Run all tests
$ qscg --test

# Run with verbose output
$ qscg --test -v

# Run at specific security level
$ qscg --test --level 5

# Save results to file
$ qscg --test --output test_results.txt

# JSON output
$ qscg --test --json
```

**Example Output:**
```
========================================
  QSCG Algorithm Test Suite v2.2.0
========================================

ML-KEM Tests:
  [PASS] ML-KEM-512: Key Generation        (0.012s)
  [PASS] ML-KEM-512: Encaps/Decaps         (0.015s)
  [PASS] ML-KEM-768: Key Generation        (0.018s)
  [PASS] ML-KEM-768: Encaps/Decaps         (0.021s)
  [PASS] ML-KEM-1024: Key Generation       (0.025s)
  [PASS] ML-KEM-1024: Encaps/Decaps       (0.029s)

ML-DSA Tests:
  [PASS] ML-DSA-44: Key Generation         (0.035s)
  [PASS] ML-DSA-44: Sign/Verify            (0.042s)
  [PASS] ML-DSA-65: Key Generation         (0.048s)
  [PASS] ML-DSA-65: Sign/Verify            (0.055s)
  [PASS] ML-DSA-87: Key Generation         (0.062s)
  [PASS] ML-DSA-87: Sign/Verify            (0.070s)

SLH-DSA Tests:
  [PASS] SLH-DSA-SHAKE-128s: Key Gen      (0.180s)
  [PASS] SLH-DSA-SHAKE-128s: Sign/Verify  (0.420s)
  [PASS] SLH-DSA-SHAKE-192s: Key Gen      (0.280s)
  [PASS] SLH-DSA-SHAKE-192s: Sign/Verify  (0.680s)
  [PASS] SLH-DSA-SHAKE-256s: Key Gen      (0.420s)
  [PASS] SLH-DSA-SHAKE-256s: Sign/Verify  (1.020s)

AES-256-GCM Tests:
  [PASS] AES-256-GCM: Encrypt/Decrypt      (0.003s)
  [PASS] AES-256-GCM: Authenticated AAD     (0.003s)
  [PASS] AES-256-GCM: Tamper Detection      (0.002s)

Hybrid Tests:
  [PASS] Hybrid KEM: Full Cycle             (0.025s)

----------------------------------------
Results: 17/17 PASSED
Time: 2.347s
All tests completed successfully!
```

---

### `--kem`

Run ML-KEM key encapsulation mechanism tests and demonstrations.

```bash
# Basic KEM test at default level (3)
$ qscg --kem

# Specific security level
$ qscg --kem --level 1
$ qscg --kem --level 5

# Verbose output
$ qscg --kem -v

# JSON output
$ qscg --kem --json --level 3
```

**Example Output (Level 3):**
```
========================================
  ML-KEM (FIPS 203) - Key Encapsulation
  Security Level: 3 (ML-KEM-768)
========================================

[1] Key Generation:
    Public Key:  1,184 bytes
    Private Key: 2,400 bytes
    Time: 0.018s

[2] Encapsulation:
    Ciphertext:  1,088 bytes
    Shared Secret: 32 bytes
    Shared Secret (hex): a3f7c9e2...
    Time: 0.021s

[3] Decapsulation:
    Recovered Secret: 32 bytes
    Recovered (hex):  a3f7c9e2...
    Time: 0.020s

[4] Verification:
    Secrets Match: YES ✓
    Result: SUCCESS

Key Sizes:
    Public Key:  1,184 bytes
    Private Key: 2,400 bytes
    Ciphertext:  1,088 bytes
    Secret:      32 bytes

Total Time: 0.059s
```

**JSON Output:**
```json
{
  "algorithm": "ML-KEM-768",
  "nist_level": 3,
  "key_generation": {
    "public_key_size": 1184,
    "private_key_size": 2400,
    "time_ms": 18.2
  },
  "encapsulation": {
    "ciphertext_size": 1088,
    "shared_secret_size": 32,
    "time_ms": 21.4
  },
  "decapsulation": {
    "recovered_secret_size": 32,
    "time_ms": 20.1
  },
  "verified": true,
  "total_time_ms": 59.7
}
```

---

### `--dsa`

Run ML-DSA digital signature tests.

```bash
# Basic DSA test at default level (3)
$ qscg --dsa

# Specific security level
$ qscg --dsa --level 2
$ qscg --dsa --level 5

# Verbose output with signature details
$ qscg --dsa -v

# JSON output
$ qscg --dsa --json
```

**Example Output (Level 3):**
```
========================================
  ML-DSA (FIPS 204) - Digital Signatures
  Security Level: 3 (ML-DSA-65)
========================================

[1] Key Generation:
    Public Key:  1,952 bytes
    Private Key: 4,032 bytes
    Time: 0.048s

[2] Signing:
    Message: "Test message for ML-DSA signature"
    Message Size: 33 bytes
    Signature: 3,293 bytes
    Signature (first 32 bytes): b4e7a2c9...
    Time: 0.055s

[3] Verification:
    Signature Valid: YES ✓
    Time: 0.012s

[4] Tampering Test:
    Modified message: REJECTED ✓
    Modified signature: REJECTED ✓

Key/Sig Sizes:
    Public Key:  1,952 bytes
    Private Key: 4,032 bytes
    Signature:   3,293 bytes

Performance:
    Key Generation:  48 ms
    Signing:         55 ms
    Verification:    12 ms
    Total:          115 ms

Result: SUCCESS
```

---

### `--slh`

Run SLH-DSA hash-based signature tests.

```bash
# Basic SLH-DSA test at default level (1)
$ qscg --slh

# Specific security level
$ qscg --slh --level 3
$ qscg --slh --level 5

# SHA2 variant
$ qscg --slh --hash sha2

# Verbose output
$ qscg --slh -v

# JSON output
$ qscg --slh --json --level 3
```

**Example Output (Level 1, SHAKE):**
```
========================================
  SLH-DSA (FIPS 205) - Hash Signatures
  Security Level: 1 (SLH-DSA-SHAKE-128s)
  Hash Function: SHAKE-128
========================================

[1] Key Generation:
    Public Key:  32 bytes
    Private Key: 64 bytes
    Time: 0.180s

[2] Signing:
    Message: "Test message for SLH-DSA"
    Signature: 7,856 bytes
    Time: 2.350s

[3] Verification:
    Signature Valid: YES ✓
    Time: 0.095s

[4] Tampering Tests:
    Modified message: REJECTED ✓
    Wrong public key: REJECTED ✓

Key/Sig Sizes:
    Public Key:    32 bytes
    Private Key:   64 bytes
    Signature:   7,856 bytes

Performance:
    Key Generation:   180 ms
    Signing:        2,350 ms
    Verification:      95 ms

Result: SUCCESS
```

---

### `--aes`

Run AES-256-GCM encryption/decryption tests.

```bash
# Basic AES test
$ qscg --aes

# With larger test data
$ qscg --aes -v

# JSON output
$ qscg --aes --json
```

**Example Output:**
```
========================================
  AES-256-GCM - Symmetric Encryption
========================================

[1] Key Generation:
    Key Size: 32 bytes (256 bits)
    Key (hex): a4f8c2e1...

[2] Encryption:
    Plaintext: "Sensitive quantum-safe data"
    Plaintext Size: 27 bytes
    Associated Data: "metadata-v1"
    Ciphertext: 27 bytes
    Nonce: 12 bytes
    Tag: 16 bytes

[3] Decryption:
    Decrypted: "Sensitive quantum-safe data"
    Decryption Status: SUCCESS ✓

[4] Authentication Test:
    Wrong AAD: REJECTED ✓
    Tampered ciphertext: REJECTED ✓

Performance:
    Encrypt: 0.003 ms
    Decrypt: 0.002 ms

Result: SUCCESS
```

---

### `--analysis`

Run comprehensive quantum threat analysis.

```bash
# Full analysis
$ qscg --analysis

# Save to file
$ qscg --analysis --output threat_analysis.txt

# JSON output
$ qscg --analysis --json

# Verbose mode with detailed recommendations
$ qscg --analysis -v
```

**Example Output:**
```
========================================
  Quantum Threat Analysis Report
  QSCG v2.2.0
========================================

Generated: 2025-01-15 14:32:00

[Shor's Algorithm Impact]
  RSA-2048:        BROKEN (polynomial time)
  ECC P-256:       BROKEN (polynomial time)
  Diffie-Hellman:  BROKEN (polynomial time)
  ML-KEM:          SECURE (lattice-based)
  ML-DSA:          SECURE (lattice-based)
  SLH-DSA:         SECURE (hash-based)

[Grover's Algorithm Impact]
  AES-128:         Reduced to 64-bit security
  AES-256:         Reduced to 128-bit security
  SHA-256:         Collision search: O(2^85)
  ML-KEM-768:      Full security maintained
  ML-DSA-65:       Full security maintained

[Harvest Now Decrypt Later]
  Risk Level: CRITICAL
  Encrypted data today may be stored for future decryption.
  Estimated quantum capability: 2030-2035

[Migration Recommendations]
  1. Start inventorying cryptographic assets now
  2. Deploy hybrid encryption for long-term data
  3. Implement ML-KEM for key exchange
  4. Implement ML-DSA/SLH-DSA for signatures
  5. Monitor NIST migration timeline

[NIST Migration Timeline]
  2024: FIPS 203, 204, 205 published
  2025: CNSA 2.0 guidance
  2028: ML-KEM required for sensitive data
  2030: ML-DSA required for digital signatures
  2032: All classical algorithms deprecated
  2035: Full PQC transition complete

Full report: See threat_analysis.txt
```

---

### `--nist`

Verify NIST standard compliance for all implemented algorithms.

```bash
# Full NIST compliance check
$ qscg --nist

# With verbose output
$ qscg --nist -v

# JSON output
$ qscg --nist --json
```

**Example Output:**
```
========================================
  NIST Compliance Verification
  Standards: FIPS 203, FIPS 204, FIPS 205
========================================

[ML-KEM / FIPS 203]
  Standard Version: FIPS 203 (August 13, 2024)
  Algorithm: ML-KEM-512, ML-KEM-768, ML-KEM-1024
  Parameter Sets:     COMPLIANT ✓
  Key Generation:     COMPLIANT ✓
  Encapsulation:      COMPLIANT ✓
  Decapsulation:      COMPLIANT ✓
  NTT Implementation: COMPLIANT ✓
  KAT Vectors:        18/18 PASSED ✓
  Status: COMPLIANT

[ML-DSA / FIPS 204]
  Standard Version: FIPS 204 (August 13, 2024)
  Algorithm: ML-DSA-44, ML-DSA-65, ML-DSA-87
  Parameter Sets:     COMPLIANT ✓
  Key Generation:     COMPLIANT ✓
  Signing:            COMPLIANT ✓
  Verification:       COMPLIANT ✓
  Rejection Sampling: COMPLIANT ✓
  Hint Mechanism:     COMPLIANT ✓
  KAT Vectors:        24/24 PASSED ✓
  Status: COMPLIANT

[SLH-DSA / FIPS 205]
  Standard Version: FIPS 205 (August 13, 2024)
  Algorithm: SLH-DSA-SHAKE-*s, SLH-DSA-SHA2-*s
  Parameter Sets:     COMPLIANT ✓
  Key Generation:     COMPLIANT ✓
  Signing:            COMPLIANT ✓
  Verification:       COMPLIANT ✓
  FOROTS/WOTS+:       COMPLIANT ✓
  XMSS Trees:         COMPLIANT ✓
  KAT Vectors:        36/36 PASSED ✓
  Status: COMPLIANT

Overall Compliance Status: ALL STANDARDS COMPLIANT ✓

Known Answer Test Results:
  Total KAT Vectors Tested: 78
  Passed: 78/78 (100%)
  Failed: 0
```

---

### `--hndl`

Run Harvest Now, Decrypt Later (HNDL) risk analysis.

```bash
# HNDL analysis
$ qscg --hndl

# Save report
$ qscg --hndl --output hndl_report.txt

# JSON output
$ qscg --hndl --json
```

**Example Output:**
```
========================================
  HNDL - Harvest Now, Decrypt Later
  Risk Assessment Report
========================================

[HNDL Threat Model]
  Adversary Strategy:
    1. Intercept and store encrypted communications today
    2. Wait for quantum computers capable of running Shor's algorithm
    3. Decrypt all stored data retroactively

  Timeline Estimate:
    Conservative: 2030-2035 for cryptographically-relevant quantum computer
    Aggressive:   2028-2032
    Optimistic:   2035-2040

[Risk Assessment by Data Type]
  Classified/Military:    CRITICAL - Must migrate immediately
  Financial Records:      CRITICAL - 10+ year retention
  Healthcare Records:     HIGH - 7+ year retention, legal exposure
  Personal Data (GDPR):   HIGH - Long-term legal implications
  TLS/HTTPS Traffic:      MEDIUM-MEDIUM - Session keys ephemeral
  Short-lived Messages:   LOW - May be obsolete by decryption time

[Current Algorithm Vulnerability]
  Algorithm    | HNDL Risk | Recommended Action
  RSA-2048     | CRITICAL  | Replace with ML-KEM + ML-DSA
  ECC P-256    | CRITICAL  | Replace with ML-KEM + ML-DSA
  AES-256-GCM  | MEDIUM    | Add ML-KEM key encapsulation
  ML-KEM-768   | NONE      | Already quantum-resistant
  ML-DSA-65    | NONE      | Already quantum-resistant

[Mitigation Strategies]
  1. Implement crypto agility (algorithm negotiation)
  2. Deploy hybrid key exchange (ML-KEM + X25519)
  3. Inventory all cryptographic assets
  4. Prioritize long-lived data migration
  5. Establish quantum-readiness roadmap
```

---

### `--hybrid`

Run hybrid encryption combining ML-KEM with classical algorithms.

```bash
# Basic hybrid test
$ qscg --hybrid

# Specific PQ level
$ qscg --hybrid --level 5

# Verbose output
$ qscg --hybrid -v

# JSON output
$ qscg --hybrid --json
```

**Example Output:**
```
========================================
  Hybrid Key Encapsulation
  PQ Algorithm: ML-KEM-768 (Level 3)
  Classical:    X25519
========================================

[1] Key Generation:
    ML-KEM Public Key:  1,184 bytes
    ML-KEM Private Key: 2,400 bytes
    X25519 Public Key:     32 bytes
    X25519 Private Key:    32 bytes
    Time: 0.025s

[2] Encapsulation:
    ML-KEM Ciphertext:  1,088 bytes
    X25519 Ciphertext:     32 bytes
    Combined Secret:       64 bytes (32+32, then hashed)
    Time: 0.028s

[3] Decapsulation:
    PQ Secret Recovered:   YES ✓
    Classical Secret:      YES ✓
    Combined Secret:       MATCH ✓
    Time: 0.027s

[4] Verification:
    Shared secrets match: YES ✓
    Result: SUCCESS

Benefits:
    - Secure if ML-KEM broken: X25519 provides classical security
    - Secure if X25519 broken: ML-KEM provides post-quantum security
    - Defense-in-depth against unknown attacks

Key Sizes:
    PQ Public Key:    1,184 bytes
    Classical Pub:       32 bytes
    PQ Ciphertext:    1,088 bytes
    Classical CT:        32 bytes
    Combined Secret:     64 bytes
```

---

## Security Level Options

The `--level` flag controls the NIST security level for all algorithm tests:

| Level | Algorithms | Use Case | Performance |
|-------|-----------|----------|-------------|
| **1** | ML-KEM-512, ML-DSA-44, SLH-DSA-128s | Standard applications | Fastest |
| **3** | ML-KEM-768, ML-DSA-65, SLH-DSA-192s | Sensitive data (default) | Balanced |
| **5** | ML-KEM-1024, ML-DSA-87, SLH-DSA-256s | Classified/Military | Most secure |

```bash
# Level 1 - Fastest, standard security
$ qscg --kem --level 1
$ qscg --dsa --level 1

# Level 3 - Balanced (default)
$ qscg --kem --level 3
$ qscg --dsa --level 3

# Level 5 - Maximum security
$ qscg --kem --level 5
$ qscg --dsa --level 5

# SLH-DSA with different levels
$ qscg --slh --level 1
$ qscg --slh --level 3
$ qscg --slh --level 5
```

---

## Usage Scenarios

### Scenario 1: Quick Verification After Installation

```bash
# Verify everything works
qscg --test

# Check version
qscg --version
```

### Scenario 2: Security Audit

```bash
# Full security analysis
qscg --analysis --output security_audit.txt
qscg --nist --output compliance_report.txt
qscg --hndl --output hndl_assessment.txt
```

### Scenario 3: Algorithm Benchmarking

```bash
#!/bin/bash
for level in 1 3 5; do
    echo "=== Security Level $level ==="
    qscg --kem --level $level --json
    qscg --dsa --level $level --json
    qscg --slh --level $level --json
done
```

### Scenario 4: CI/CD Pipeline Integration

```yaml
# .github/workflows/qscg-test.yml
name: QSCG Tests
on: [push, pull_request]
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: '3.12'
      - run: pip install qscg
      - run: qscg --test --json > results.json
      - run: qscg --nist
```

### Scenario 5: Automated Compliance Checking

```bash
#!/bin/bash
# compliance_check.sh

OUTPUT="compliance_$(date +%Y%m%d).txt"

echo "Running NIST compliance check..."
qscg --nist --output "$OUTPUT"

if qscg --nist --json | grep -q '"compliant": true'; then
    echo "✓ NIST COMPLIANT"
    exit 0
else
    echo "✗ NON-COMPLIANT - Check $OUTPUT"
    exit 1
fi
```

---

## Error Messages and Solutions

| Error Message | Cause | Solution |
|--------------|-------|----------|
| `error: unrecognized arguments` | Invalid command or option | Run `qscg --help` to see valid options |
| `error: --level: invalid choice` | Level not 1, 3, or 5 | Use `--level 1`, `--level 3`, or `--level 5` |
| `error: --hash: invalid choice` | Wrong hash type | Use `--hash shake` or `--hash sha2` |
| `QSCGError: Invalid key length` | Key file corrupted or wrong format | Regenerate keys with correct level |
| `QSCGError: Security level mismatch` | Key and operation levels differ | Use matching `--level` for all operations |
| `MemoryError` | Insufficient memory for SLH-DSA | Close other applications or use lower level |
| `PermissionError` | Cannot write to output file | Check file permissions and path |
| `ModuleNotFoundError` | QSCG not installed | Run `pip install qscg` |
| `ImportError: No module named 'cryptography'` | Missing dependency | Run `pip install cryptography` |
| `AssertionError: Shared secret mismatch` | Internal implementation error | Report on GitHub issues |

### Common Issues and Fixes

```bash
# Issue: "qscg: command not found"
# Fix: Ensure pip install location is on PATH
pip install --user qscg
export PATH="$HOME/.local/bin:$PATH"

# Issue: Slow SLH-DSA operations
# Fix: SLH-DSA is inherently slower; use lower level or consider ML-DSA for signing
qscg --slh --level 1  # Faster than level 3 or 5

# Issue: Import errors in virtual environment
# Fix: Activate virtual environment first
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate      # Windows
```

---

## Output Formats

### Plain Text (Default)

Human-readable formatted output with colors and progress indicators.

### JSON Output

```bash
$ qscg --test --json
```

All JSON output follows this schema:

```json
{
  "version": "2.2.0",
  "timestamp": "2025-01-15T14:32:00Z",
  "command": "test",
  "results": {
    "passed": 17,
    "failed": 0,
    "total": 17,
    "tests": [...]
  },
  "timing": {
    "total_ms": 2347.2
  }
}
```

---

## Scripting Examples

### Python Script Integration

```python
#!/usr/bin/env python3
"""Automated QSCG testing script."""

import subprocess
import json
import sys

def run_qscg_tests():
    """Run all QSCG tests and return results."""
    result = subprocess.run(
        ['qscg', '--test', '--json'],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f"Test failed: {result.stderr}")
        sys.exit(1)
    
    data = json.loads(result.stdout)
    return data

if __name__ == '__main__':
    results = run_qscg_tests()
    print(f"Tests: {results['results']['passed']}/{results['results']['total']} passed")
    print(f"Time: {results['timing']['total_ms']:.1f} ms")
```

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `QSCG_LEVEL` | Default security level | `3` |
| `QSCG_HASH` | Default SLH-DSA hash type | `shake` |
| `QSCG_NO_COLOR` | Disable colored output | unset |
| `QSCG_VERBOSE` | Default verbosity level | `0` |

```bash
# Set default security level
export QSCG_LEVEL=5
qscg --kem  # Uses level 5 automatically

# Disable colors for logging
export QSCG_NO_COLOR=1
qscg --test > test.log
```

---

> **Last Updated**: 2025-01-15 | QSCG v2.2.0
>
> For CLI bugs or feature requests, please open an issue on [GitHub](https://github.com/mcemkoca/qscg/issues).
