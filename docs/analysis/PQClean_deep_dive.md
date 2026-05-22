# PQClean Derin Analiz Raporu

**Tarih:** 2026-05-22  
**Repo:** https://github.com/PQClean/PQClean  
**Yıldız:** ⭐ 920  
**Dil:** C (portable, clean)  
**Amaç:** NIST PQC finalistlerinin temiz, taşınabilir, test edilmiş C implementasyonları

---

## 1. Mimari Analizi

### 1.1 Klasör Yapısı (Mükemmel Organizasyon)

```
PQClean/
├── crypto_kem/                    # Key Encapsulation Mechanisms
│   ├── ml-kem-512/               # ML-KEM (FIPS 203) — 3 varyant
│   ├── ml-kem-768/
│   ├── ml-kem-1024/
│   ├── hqc-128/                  # HQC (code-based) — NIST Round 4
│   ├── hqc-192/
│   ├── hqc-256/
│   └── mceliece*/                # Classic McEliece — 10 varyant
├── crypto_sign/                   # Digital Signatures
│   ├── ml-dsa-44/                # ML-DSA (FIPS 204) — 3 varyant
│   ├── ml-dsa-65/
│   ├── ml-dsa-87/
│   ├── falcon-512/               # FN-DSA (Falcon) — 2 varyant
│   ├── falcon-1024/
│   └── sphincs-*/                # SLH-DSA (SPHINCS+) — 24 varyant
├── common/                        # Shared utilities
│   ├── randombytes.c             # OS randomness wrapper
│   ├── sha2.c / sha3.c           # Hash functions
│   ├── fips202.c                 # Keccak/SHA-3
│   └── aes.c                     # AES for DRBG
└── test/                          # Comprehensive test suite
    ├── crypto_kem/functest.c     # Functional tests
    ├── crypto_sign/functest.c
    └── common/                   # Common test utilities
```

### 1.2 Algoritma Kapsamı (QSCG Karşılaştırması)

| Algoritma | PQClean | QSCG v4.0 | Fark |
|-----------|---------|-----------|------|
| ML-KEM-512/768/1024 | ✅ | ✅ | Eşit |
| ML-DSA-44/65/87 | ✅ | ✅ | Eşit |
| SLH-DSA (SPHINCS+) | ✅ 24 varyant | ✅ | PQClean daha fazla varyant |
| FALCON-512/1024 | ✅ | ❌ | QSCG'de yok! |
| HQC (code-based) | ✅ 3 varyant | ❌ | QSCG'de yok |
| McEliece | ✅ 10 varyant | ❌ | QSCG'de yok |
| **Toplam** | **41 algoritma** | **7 algoritma** | PQClean 6x daha fazla |

---

## 2. Kod Kalitesi Analizi

### 2.1 Her Algoritma için Standart Dosya Yapısı

```
algo-name/
├── api.h                          # Public API (NIST standard)
├── params.h                       # Algorithm parameters
├── clean/                         # Pure C implementation
│   ├── *.c / *.h                  # Source files
│   └── Makefile                   # Build
├── avx2/                          # AVX2 optimized (opsiyonel)
│   ├── *.c / *.h
│   └── Makefile
└── META.yml                       # Metadata (NIST submission info)
```

### 2.2 API Standardizasyonu (Mükemmel)

**Her KEM aynı API:**
```c
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM512_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
```

**Her İmza aynı API:**
```c
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen, const uint8_t *sk);
int PQCLEAN_MLDSA44_CLEAN_crypto_sign_open(uint8_t *m, size_t *mlen, const uint8_t *sig, size_t siglen, const uint8_t *pk);
```

**QSCG Karşılaştırması:**
- PQClean: C fonksiyonları, sabit boyutlu buffer'lar
- QSCG: Python class'ları, dinamik boyutlar
- PQClean daha düşük seviyede (donanıma yakın)
- QSCG daha yüksek seviyede (kullanıcı dostu)

### 2.3 "Clean" Implementasyon Prensibi

| Özellik | PQClean "clean/" | QSCG Python |
|---------|------------------|-------------|
| Dilde bağımsız | ✅ Pure C99 | ❌ Python-only |
| Platform bağımsız | ✅ (x86, ARM, RISC-V) | ✅ (CPython) |
| Derleyici bağımsız | ✅ (gcc, clang, msvc) | ✅ (CPython 3.12+) |
| Sabit zamanlı | ⚠️ Amaçlanıyor | ⚠️ Kısmen |
| Branch-free | ⚠️ Amaçlanıyor | ❌ Python if/else |
| Bellek güvenliği | ✅ Explicit clear | ❌ GC dependent |

---

## 3. Test ve Doğrulama

### 3.1 Test Kapsamı

| Test Türü | PQClean | QSCG v4.0 |
|-----------|---------|-----------|
| Fonksiyonel test | ✅ crypto_kem/sign/functest.c | ⚠️ Kısmen |
| NIST KAT vektörleri | ✅ | ❌ |
| Hafıza güvenliği testi | ✅ Valgrind/ASAN | ❌ |
| Sabit zaman testi | ✅ dudect | ❌ |
| Fuzz test | ✅ libFuzzer | ❌ |
| Çapraz implementasyon | ✅ PQClean ↔ NIST | ❌ |
| Kod kapsamı | >90% (hedef) | Bilinmiyor |

### 3.2 CI/CD

| Özellik | PQClean | QSCG v4.0 |
|---------|---------|-----------|
| GitHub Actions | ✅ (çoklu platform) | ✅ |
| Travis CI | ✅ | ❌ |
| AppVeyor | ✅ | ❌ |
| CircleCI | ✅ | ❌ |
| Platform | Linux, macOS, Windows, ARM | Ubuntu, Windows, macOS |
| Derleyici | gcc, clang, msvc | — |
| Sanitizer | ASAN, UBSAN, MSAN | ❌ |
| Valgrind | ✅ | ❌ |

---

## 4. Güvenlik Analizi

### 4.1 Side-Channel Direnç

| Vektör | PQClean | QSCG v4.0 |
|--------|---------|-----------|
| Timing attack | ⚠️ "clean" hedefi, ama C derleyicisi optimize edebilir | ❌ Python interpreter timing leak |
| Cache attack | ⚠️ Düz erişim deseni | ❌ Python obje cache karmaşık |
| Branch prediction | ⚠️ Dallanmasız kod hedefi | ❌ Python if/else açık |
| Power analysis | ❌ Yüksek seviye | ❌ Yüksek seviye |
| Fault attack | ❌ Yazılım seviyesinde koruma yok | ❌ Yazılım seviyesinde koruma yok |

**Sonuç:** PQClean "clean" hedefi constant-time ama C derleyici optimizasyonları nedeniyle garanti vermez. QSCG Python'da bu seviyede kontrol imkansız.

### 4.2 Bellek Güvenliği

| Özellik | PQClean | QSCG v4.0 |
|---------|---------|-----------|
| Secret key zeroization | ✅ `explicit_bzero()` / `memset_s()` | ❌ Python `del` (GC bağımlı) |
| Stack canaries | Derleyici bağımlı | N/A |
| ASAN | ✅ | ❌ |
| Secure heap | ❌ | ❌ |

---

## 5. Bulunan Hatalar/Eksiklikler

### 5.1 PQClean'de Bulunanlar

1. **META.yml çeşitliliği:** Her algoritma için farklı META.yml formatı
   - Standardizasyon tam değil
   - Otomatik parsing zor

2. **AVX2/Clean ikili yapı:** Aynı algoritmanın iki implementasyonu bakımı zor
   - Bug fix'ler her iki versiyona da uygulanmalı
   - Synchronizasyon riski

3. **HQC ve McEliece eksikliği QSCG'de:**
   - QSCG sadece lattice-based (ML-KEM, ML-DSA)
   - Code-based (HQC, McEliece) yok
   - Hash-based (SPHINCS+) var ama sınırlı

4. **SPHINCS+ 24 varyant:**
   - PQClean: sha2-simple, sha2-robust, shake-simple, shake-robust × 6 seviye
   - QSCG: Sadece SLH-DSA (FIPS 205)
   - "Simple" vs "Robust" farkı QSCG'de belgelenmemiş

### 5.2 QSCG'de Bulunan (PQClean Karşılaştırması)

1. **NIST KAT test vektörleri eksik** — PQClean'de var
2. **Fuzz testing yok** — PQClean'de var
3. **Memory sanitizer yok** — PQClean'de ASAN/Valgrind
4. **Formal verification yok** — PQClean hedefi
5. **HQC/McEliece yok** — PQClean'de var

---

## 6. Entegrasyon Önerileri

### 6.1 QSCG'ye Eklenecek (PQClean Referans)

| Öncelik | Algoritma | Kaynak | Efor | Risk |
|---------|-----------|--------|------|------|
| 🔴 P0 | **FALCON** (FN-DSA) | PQClean falcon-512/1024 | 40+ saat | Orta |
| 🟡 P1 | **HQC** (code-based KEM) | PQClean hqc-128/192/256 | 30+ saat | Düşük |
| 🟡 P1 | **McEliece** (code-based KEM) | PQClean mceliece* | 50+ saat | Yüksek |
| 🟡 P1 | **SLH-DSA varyantları** | PQClean sphincs-* | 20+ saat | Düşük |
| 🟢 P2 | **NIST KAT test vektörleri** | PQClean/test/ | 10 saat | Düşük |
| 🟢 P2 | **Valgrind/ASAN entegrasyonu** | PQClean CI | 5 saat | Düşük |

### 6.2 PQClean'den Öğrenilecek Teknikler

1. **Uniform API tasarımı** — `crypto_kem_keypair()`, `crypto_sign()` gibi standart fonksiyonlar
2. **Multi-variant organizasyon** — Her algoritma kendi klasöründe, izole edilmiş
3. **"Clean" + "Optimized" ikili yapı** — Taşınabilirlik + performans
4. **Kapsamlı test suite** — Fonksiyonel + KAT + fuzz + memory
5. **META.yml metadata** — Algoritma bilgisi için standart format

---

## 7. Benchmark (Tahmini)

| Algoritma | PQClean (C) | QSCG (Python) | Hız Farkı |
|-----------|-------------|---------------|-----------|
| ML-KEM-768 KeyGen | ~50μs | ~2ms | 40x |
| ML-KEM-768 Encaps | ~60μs | ~2.5ms | 42x |
| ML-DSA-65 Sign | ~200μs | ~5ms | 25x |
| FALCON-512 Sign | ~300μs | ❌ | N/A |
| SPHINCS+-128s Sign | ~5ms | ❌ | N/A |

> **Not:** C vs Python doğal performans farkı. QSCG'nin değeri "C hızında çalışması" değil, "Python'da kapsamlı toolkit" olması.

---

## 8. Sonuç

**PQClean Güçlü Yönleri:**
- 41 algoritma (QSCG'den 6x fazla)
- Mükemmel organizasyon (clean/avx2 ikili yapı)
- Kapsamlı test ve doğrulama
- Taşınabilir C99 kod
- NIST KAT vektörleri

**QSCG Güçlü Yönleri:**
- Python-native (pip install, çalışır)
- GUI + AI Agent entegrasyonu
- Akademik/endüstri dokümantasyon
- PyPI paketi
- GitHub Actions CI/CD

**QSCG Eksikleri (PQClean Karşılaştırması):**
- FALCON (FN-DSA) — Önemli! NIST FIPS 206 yakında
- HQC/McEliece — Code-based alternatifler
- Kapsamlı test vektörleri
- Memory sanitizer
- Fuzz testing

**Tavsiye:** QSCG'ye FALCON eklemek (highest priority), sonra HQC/McEliece (diversification).

---

*Analiz: Bilge Kağan | QSCG Quantum Tunneling Research | M.Cem Koca {Deuterium12}*
