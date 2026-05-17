# Security Policy

The **qscg** project takes security seriously. As a library implementing post-quantum cryptographic standards, maintaining the integrity and correctness of our implementations is paramount. This document outlines our security policies, supported versions, and vulnerability reporting procedures.

---

## Supported Versions

We provide security updates for the following versions of qscg:

| Version | Status | Release Date | Security Support Until |
|---------|--------|-------------|----------------------|
| 0.3.x | ✅ Active development | 2025-01 | Current + 6 months |
| 0.2.x | ✅ Supported | 2024-08 | 2025-08 |
| 0.1.x | 🛇 End of life | 2024-03 | No longer supported |
| < 0.1.0 | 🛇 Unsupported | — | No longer supported |

- **Active development**: Receives all security patches, bug fixes, and new features.
- **Supported**: Receives critical security patches only.
- **End of life**: No longer receives any updates. Please upgrade to a supported version.

> **Note**: We follow [Semantic Versioning](https://semver.org/). Security fixes are released as patch version bumps (e.g., `0.3.0` → `0.3.1`).

### Python Version Support

qscg supports Python 3.9+. However, we strongly recommend using the latest stable Python release for security-sensitive applications:

| Python Version | Supported | Recommendation |
|----------------|-----------|----------------|
| 3.13 | ✅ | Recommended |
| 3.12 | ✅ | Recommended |
| 3.11 | ✅ | Supported |
| 3.10 | ✅ | Supported |
| 3.9 | ✅ | Minimum supported |
| < 3.9 | ❌ | Not supported |

---

## Reporting a Vulnerability

If you believe you have discovered a security vulnerability in qscg, **please do not open a public issue**. Instead, follow the responsible disclosure process below.

### Responsible Disclosure Process

1. **Report privately**: Submit a vulnerability report via [GitHub Security Advisories](https://github.com/mcemkoca/qscg/security/advisories/new).
   - Alternatively, you may email the maintainers directly (see contact below).

2. **Provide details**: Include the following information in your report:
   - **Description**: Clear description of the vulnerability
   - **Impact**: What security property is violated (confidentiality, integrity, authenticity)?
   - **Affected versions**: Which versions of qscg are affected?
   - **Affected components**: Which modules, functions, or algorithms are involved?
   - **Reproduction steps**: Detailed steps to reproduce the issue
   - **Proof of concept**: If available, provide minimal code demonstrating the vulnerability
   - **Mitigation**: Suggested fix or workaround if known
   - **References**: Any related standards (NIST docs), CVEs, or academic papers

3. **Acknowledgment**: We will acknowledge receipt of your report within **72 hours**.

4. **Investigation**: We will investigate the vulnerability and may request additional information.

5. **Resolution timeline**:

   | Severity | Response Time | Fix Timeline |
   |----------|--------------|--------------|
   | Critical | 24 hours | 7 days |
   | High | 72 hours | 14 days |
   | Medium | 7 days | 30 days |
   | Low | 14 days | 60 days |

6. **Disclosure**: Once fixed, we will:
   - Release a patched version
   - Publish a security advisory on GitHub
   - Credit the reporter (unless anonymity is requested)
   - Request a CVE identifier if appropriate

### What We Commit To

- We will **never take legal action** against security researchers who follow this responsible disclosure process.
- We will **credit you** in the security advisory (unless you prefer anonymity).
- We will **keep you informed** of our progress toward resolving the issue.
- We will **not disclose** the vulnerability publicly until a fix is available.

### Out of Scope

The following are generally not considered security vulnerabilities:

- Vulnerabilities in dependencies (report to the upstream project)
- Issues requiring local system access or physical access
- Social engineering attacks against project maintainers
- DoS via resource exhaustion in non-production configurations
- Issues in deprecated/end-of-life versions

---

## PGP Key (Optional)

For encrypted communication, you may use the following PGP key to encrypt your reports:

```
-----BEGIN PGP PUBLIC KEY BLOCK-----

[PLACEHOLDER - This is a placeholder for the project's PGP public key.
 Project maintainers should replace this with the actual PGP key.
 To generate: gpg --full-generate-key
 To export: gpg --armor --export <KEY_ID>]

-----END PGP PUBLIC KEY BLOCK-----
```

**Fingerprint**: `XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX XXXX`

> ⚠️ This key is optional. The recommended reporting channel is [GitHub Security Advisories](https://github.com/mcemkoca/qscg/security/advisories/new), which provides encrypted communication automatically.

---

## Security Update Notifications

Stay informed about security updates:

1. **Watch the repository**: Click "Watch" → "Custom" → "Security alerts" on the GitHub repository page.

2. **GitHub Security Advisories**: Follow our [security advisories page](https://github.com/mcemkoca/qscg/security/advisories).

3. **Release notifications**: Enable GitHub release notifications to get notified of new versions.

4. **PyPI**: Subscribe to the project on [PyPI](https://pypi.org/project/qscg/) for release notifications.

---

## Security Best Practices for Users

When using qscg in your applications, follow these security guidelines:

### Key Management

- **Never hardcode keys**: Use secure key management systems (HSMs, AWS KMS, HashiCorp Vault).
- **Rotate keys regularly**: Establish a key rotation policy appropriate for your threat model.
- **Secure key generation**: Always use the library's built-in key generation; never derive keys from weak entropy sources.

### Randomness

- Ensure your system's CSPRNG (`/dev/urandom`, `CryptGenRandom`, `getrandom()`) is properly seeded.
- In virtualized environments, ensure the hypervisor provides adequate entropy to guests.

### Algorithm Selection

- **ML-KEM** (FIPS 203): Use for key encapsulation. Recommended parameter set: **ML-KEM-768** (balance of security and performance).
- **ML-DSA** (FIPS 204): Use for digital signatures. Recommended parameter set: **ML-DSA-65**.
- **SLH-DSA** (FIPS 205): Use when stateless signatures with conservative security assumptions are required.

### General

- Keep qscg and all dependencies up to date.
- Monitor our security advisories.
- Use qscg in an isolated security boundary for critical applications.
- Validate all inputs (ciphertexts, signatures, public keys) before processing.

---

## Disclaimer

This software is provided "as is", without warranty of any kind, express or implied, including but not limited to the warranties of merchantability, fitness for a particular purpose, and noninfringement.

While we strive for correctness and security, this library:

- Has **not** undergone formal third-party certification or validation.
- Should be used with appropriate security review for your specific use case.
- Does not guarantee protection against all attack vectors, including side-channel attacks not addressed by the implementation.
- Users are responsible for compliance with applicable laws and regulations in their jurisdiction.

For production deployments with high security requirements, we recommend:

1. Conducting your own security audit.
2. Using certified cryptographic modules where required (e.g., FIPS 140-3 validated HSMs).
3. Consulting with a qualified cryptography professional.

---

## Contact

| Method | Details |
|--------|---------|
| **GitHub Security Advisories** | [github.com/mcemkoca/qscg/security/advisories/new](https://github.com/mcemkoca/qscg/security/advisories/new) |
| **Maintainer** | [@mcemkoca](https://github.com/mcemkoca) |
| **General Issues** | Please use [GitHub Issues](https://github.com/mcemkoca/qscg/issues) for non-security bugs |
| **Discussions** | Use [GitHub Discussions](https://github.com/mcemkoca/qscg/discussions) for general questions |

---

*Last updated: 2025-01-15*

*This security policy is based on best practices from the [OpenSSF](https://openssf.org/) and [CNCF](https://www.cncf.io/) security guidelines.*
