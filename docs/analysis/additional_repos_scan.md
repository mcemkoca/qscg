# rustpq/pqcrypto - Kısa Analiz

**Repo:** https://github.com/rustpq/pqcrypto  
**Yıldız:** ⭐ 398  
**Dil:** Rust  
**Amaç:** Rust'ta post-quantum kriptografi

## Özet

Rust tabanlı PQC kütüphanesi. QSCG ile doğrudan rekabet etmiyor (farklı dil) ama entegrasyon hedefi olabilir.

## Özellikler

| Algoritma | Destek |
|-----------|--------|
| ML-KEM | ✅ |
| ML-DSA | ✅ |
| FN-DSA (Falcon) | ✅ |
| SLH-DSA | ✅ |
| SABER | ✅ |
| NTRU | ✅ |
| Classic McEliece | ✅ |

## QSCG ile İlişki

- **PyO3 entegrasyonu:** Rust modülü Python'a çağrılabilir
- **Farklı dil = farklı ekosistem:** Doğrudan rekabet değil
- **Rust'ın güvenliği:** Memory safety, ownership model

## Entegrasyon Önerisi

**Uzun vade:** PyO3 ile Rust modülü ekleme
- Avantaj: Rust'ın performansı + Python'un ergonomisi
- Dezavantaj: Derleme karmaşıklığı

---

# quincy-rs/quincy - Kısa Analiz

**Repo:** https://github.com/quincy-rs/quincy  
**Yıldız:** ⭐ 302  
**Dil:** Rust  
**Amaç:** Post-quantum QUIC tabanlı VPN

## Özet

Rust ile yazılmış, QUIC protokolü üzerinden PQC VPN. Network-layer PQC uygulaması.

## QSCG ile İlişki

- **Network security:** QSCG'nin KEM'i VPN tunnel encryption'da kullanılabilir
- **QUIC:** Modern TCP alternatifi, hızlı bağlantı kurulumu
- **Use case:** QSCG ile quincy entegrasyonu = PQC VPN

## Entegrasyon Önerisi

**Orta vade:** QSCG Python API'si quincy ile konuşabilir
- QSCG key generation -> quincy VPN tunnel
- QSCG GUI'de "VPN Mode" eklenebilir

---

# slothy-optimizer/slothy - Kısa Analiz

**Repo:** https://github.com/slothy-optimizer/slothy  
**Yıldız:** ⭐ 325  
**Dil:** Python  
**Amaç:** Assembly super-optimizasyon (constraint solving)

## Özet

PQC assembly kodunu otomatik olarak optimize eden araç. ARM Cortex-M4, Apple M1 optimizasyonları yapıyor.

## QSCG ile İlişki

- **Doğrudan kullanım:** QSCG Python kodu assembly'ye derlenmez
- **Dolaylı kullanım:** liboqs backend C kodu slothy ile optimize edilebilir
- **İlham:** Optimizasyon teknikleri Python implementasyonuna uygulanabilir

## Entegrasyon Önerisi

**Düşük öncelik:** liboqs backend + slothy = en hızlı PQC
- Ama bu kombinasyon üretim ortamında kullanılır, QSCG araştırma/prototipleme

---

# sbom-tool/sbom-tools - Kısa Analiz

**Repo:** https://github.com/sbom-tool/sbom-tools  
**Yıldız:** ⭐ 219  
**Dil:** Rust  
**Amaç:** SBOM/CBOM (Software/Cryptographic Bill of Materials) analizi

## Özet

Yazılım bağımlılıklarının kriptografik envanterini çıkaran araç. PQC compliance (CNSA 2.0, NIST IR 8547) kontrolü yapıyor.

## QSCG ile İlişki

- **Compliance:** QSCG kullanan projeler SBOM ile PQC uyumunu kontrol edebilir
- **CBOM:** Cryptographic Bill of Materials — hangi algoritmalar kullanılıyor
- **Migration:** RSA/ECC -> PQC geçiş planlaması

## Entegrasyon Önerisi

**Düşük öncelik:** QSCG dokümantasyonuna SBOM/CBOM bölümü ekle
- "How to audit your project's crypto inventory"
- CNSA 2.0 compliance checklist

---

# paulmillr/noble-post-quantum - Kısa Analiz

**Repo:** https://github.com/paulmillr/noble-post-quantum  
**Yıldız:** ⭐ 324  
**Dil:** TypeScript  
**Amaç:** Auditable & minimal JS PQC (web/browser)

## Özet

JavaScript/TypeScript'te PQC. ML-KEM, ML-DSA, SLH-DSA, FN-DSA hepsi var. Web crypto için.

## QSCG ile İlişki

- **Web bridge:** QSCG Python backend -> noble-post-quantum frontend
- **Browser crypto:** QSCG GUI'de web tabanlı demo eklenebilir
- **Cross-validation:** JS ve Python implementasyonları birbirini doğrulayabilir

## Entegrasyon Önerisi

**Orta vade:** QSCG Web API (FastAPI/Flask) + noble-post-quantum frontend

---

*Kısa Analizler | QSCG Quantum Tunneling Research | 2026-05-22*
