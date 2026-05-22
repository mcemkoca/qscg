# liboqs (Open Quantum Safe) Derin Analiz Raporu

**Tarih:** 2026-05-22  
**Repo:** https://github.com/open-quantum-safe/liboqs  
**Yıldız:** ⭐ 2,900  
**Dil:** C (prototyping library)  
**Amaç:** Üretim ortamında prototipleme ve test için C kütüphanesi

---

## 1. Mimari Analizi

### 1.1 Katmanlı Yapı

```
liboqs/
├── src/
│   ├── kem/                       # Key Encapsulation
│   │   ├── kyber/                 # ML-KEM (FIPS 203)
│   │   ├── ntru/                  # NTRU (NTRU-HPS, NTRU-HRSS)
│   │   ├── saber/                 # Saber (NIST Round 3 finalist)
│   │   ├── frodokem/            # FrodoKEM (conservative lattice)
   │   ├── bike/                  # BIKE (code-based)
   │   └── hqc/                   # HQC (code-based)
│   ├── sig/                       # Digital Signatures
│   │   ├── dilithium/             # ML-DSA (FIPS 204)
│   │   ├── falcon/                # FN-DSA (Falcon)
│   │   ├── sphincs/               # SLH-DSA (FIPS 205)
│   │   ├── picnic/                # Picnic (zero-knowledge)
│   │   ├── rainbow/               # Rainbow (NIST Round 3 finalist)
│   │   └── ntrusign/              # NTRU Signature
│   ├── common.c / common.h        # Shared utilities
│   └── oqs.h                      # Master header
├── tests/                         # Comprehensive test suite
│   ├── kat_test.c                 # NIST Known Answer Tests
│   ├── speed_kem.c                # Performance benchmarks
│   ├── speed_sig.c
│   └── test_kem.c / test_sig.c
├── .github/workflows/              # CI/CD
└── docs/                          # Doxygen documentation
```

### 1.2 Algoritma Kapsamı

| Kategori | Algoritmalar | QSCG'de? |
|----------|-------------|----------|
| **KEM (10)** | ML-KEM, NTRU, Saber, FrodoKEM, BIKE, HQC, Classic McEliece | ML-KEM ✅, diğerleri ❌ |
| **Signature (8)** | ML-DSA, FN-DSA, SLH-DSA, Picnic, Rainbow | ML-DSA ✅, SLH-DSA ✅, Falcon ❌ |
| **Toplam** | **18 algoritma** | **4 algoritma** |

---

## 2. API Tasarımı (Çok İyi)

### 2.1 Uniform API Pattern

```c
// Algorithm selection (runtime)
OQS_KEM *kem = OQS_KEM_new("Kyber512");
OQS_SIG *sig = OQS_SIG_new("Dilithium2");

// Key generation
uint8_t *public_key = malloc(kem->length_public_key);
uint8_t *secret_key = malloc(kem->length_secret_key);
kem->keypair(public_key, secret_key);

// Encapsulation
uint8_t *ciphertext = malloc(kem->length_ciphertext);
uint8_t *shared_secret = malloc(kem->length_shared_secret);
kem->encaps(ciphertext, shared_secret, public_key);

// Decapsulation
kem->decaps(shared_secret, ciphertext, secret_key);

// Cleanup
OQS_MEM_secure_free(secret_key, kem->length_secret_key);
OQS_KEM_free(kem);
```

### 2.2 Algorithm Information (Dinamik)

```c
// Runtime algorithm discovery
int alg_count = OQS_KEM_alg_count();
const char *alg_name = OQS_KEM_alg_identifier(i);
// "Kyber512", "Kyber768", "Kyber1024", "NTRU-HPS-2048-509", ...
```

**QSCG Karşılaştırması:**

| Özellik | liboqs | QSCG v4.0 |
|---------|--------|-----------|
| Algorithm discovery | ✅ Runtime string | ❌ Hardcoded Enum |
| Memory management | ✅ `OQS_MEM_secure_free()` | ❌ Python GC |
| Length query | ✅ `kem->length_public_key` | ✅ `len(keypair.public_key)` |
| Error handling | ✅ Return codes | ❌ Exceptions |
| Cleanup | ✅ Explicit | ❌ Implicit |

---

## 3. Performans Özellikleri

### 3.1 Speed Benchmark Sonuçları (liboqs kendi raporlarından)

| Algoritma | KeyGen | Encaps/Sign | Decaps/Verify | Platform |
|-----------|--------|-------------|---------------|----------|
| ML-KEM-512 | ~30μs | ~50μs | ~40μs | x86_64 AVX2 |
| ML-KEM-768 | ~50μs | ~70μs | ~60μs | x86_64 AVX2 |
| ML-DSA-44 | ~100μs | ~200μs | ~50μs | x86_64 AVX2 |
| ML-DSA-65 | ~150μs | ~300μs | ~80μs | x86_64 AVX2 |
| FN-DSA-512 | ~5ms | ~300μs | ~80μs | x86_64 AVX2 |
| SLH-DSA-128s | ~5ms | ~5ms | ~1ms | x86_64 AVX2 |

### 3.2 Optimizasyon Seviyeleri

| Seviye | Açıklama | Hız Artışı |
|--------|----------|------------|
| **Reference** | Pure C, portable | 1x (baseline) |
| **AVX2** | SIMD x86_64 | 2-5x |
| **AVX-512** | Geniş SIMD | 3-8x |
| **NEON** | ARM SIMD | 2-4x |

---

## 4. Test ve Doğrulama (Çok Kapsamlı)

| Test Türü | Araç | Kapsam |
|-----------|------|--------|
| NIST KAT | `kat_test.c` | Tüm algoritmalar |
| Speed | `speed_kem.c`, `speed_sig.c` | Tüm algoritmalar |
| Memory | Valgrind | Bellek sızıntısı |
| Constant-time | `test_constant_time.c` | Timing attack |
| Fuzz | libFuzzer | Girdi doğrulama |
| Coverage | gcov/lcov | >90% hedefi |

---

## 5. Güvenlik Özellikleri

| Özellik | liboqs | QSCG v4.0 |
|---------|--------|-----------|
| Constant-time | ⚠️ Derleyici bağımlı | ❌ |
| Side-channel resistant | ⚠️ Derleyici bağımlı | ❌ |
| Memory clearing | ✅ `OQS_MEM_secure_free()` | ❌ |
| Input validation | ✅ | ⚠️ |
| Secure random | ✅ `OQS_randombytes()` | ✅ `secrets` |

---

## 6. QSCG İçin Entegrasyon Stratejisi

### 6.1 ctypes Backend (Önerilen)

```python
# liboqs Python binding via ctypes
import ctypes
from ctypes import cdll

_lib = cdll.LoadLibrary("liboqs.so")

class LiboqsKEM:
    """QSCG backend using liboqs C library"""
    
    def __init__(self, algorithm_name: str):
        self.kem = _lib.OQS_KEM_new(algorithm_name.encode())
        self.pk_len = self.kem.length_public_key
        self.sk_len = self.kem.length_secret_key
        self.ct_len = self.kem.length_ciphertext
        self.ss_len = self.kem.length_shared_secret
    
    def keygen(self):
        pk = ctypes.create_string_buffer(self.pk_len)
        sk = ctypes.create_string_buffer(self.sk_len)
        self.kem.keypair(pk, sk)
        return bytes(pk), bytes(sk)
    
    def encaps(self, pk: bytes):
        ct = ctypes.create_string_buffer(self.ct_len)
        ss = ctypes.create_string_buffer(self.ss_len)
        self.kem.encaps(ct, ss, pk)
        return bytes(ct), bytes(ss)
    
    def decaps(self, ct: bytes, sk: bytes):
        ss = ctypes.create_string_buffer(self.ss_len)
        self.kem.decaps(ss, ct, sk)
        return bytes(ss)
    
    def __del__(self):
        _lib.OQS_MEM_secure_free(self.sk, self.sk_len)
        _lib.OQS_KEM_free(self.kem)
```

**Avantajlar:**
- 10-50x hız artışı (C vs Python)
- 18 algoritma anında kullanılabilir
- NIST KAT vektörleri doğrulanmış
- Bellek güvenliği

**Dezavantajlar:**
- C kütüphanesi derleme gerektiriyor (Windows zor)
- Python binding (liboqs-python) C extension gerektiriyor
- Deployment karmaşıklığı

### 6.2 Hybrid Yaklaşım (Önerilen)

```
QSCG v4.1 Mimari (Önerilen):
├── src/core/
│   ├── qscg_pure.py          # Pure Python (fallback, portable)
│   ├── qscg_liboqs.py        # liboqs ctypes backend (performans)
│   └── qscg_hybrid.py        # Auto-select: liboqs varsa hızlı, yoksa pure
```

---

## 7. Bulunan Hatalar/Eksiklikler

### 7.1 liboqs'de

1. **liboqs-python binding eksikliği**
   - Sadece temel KEM/SIG API
   - Ekstra özellikler (benchmark, algorithm listing) yok
   - Windows derlemesi zor

2. **Deployment karmaşıklığı**
   - Linux: `apt install liboqs-dev`
   - macOS: `brew install liboqs`
   - Windows: Visual Studio + CMake gerekli
   - Her platform farklı

3. **Algorithm isimlendirme tutarsızlığı**
   - `"Kyber512"` vs `"ML-KEM-512"` (NIST sonrası isim değişikliği)
   - `"Dilithium2"` vs `"ML-DSA-44"`
   - QSCG'de NIST isimleri kullanılıyor, liboqs eski isimler

### 7.2 QSCG'de (liboqs Karşılaştırması)

1. **18 algoritma eksik** — liboqs 18, QSCG 4
2. **Performans** — Python 10-50x yavaş
3. **Memory security** — Python GC, explicit clear yok
4. **Platform coverage** — liboqs x86/ARM/RISC-V, QSCG sadece CPython
5. **Algorithm discovery** — QSCG hardcoded, liboqs runtime

---

## 8. Sonuç ve Tavsiyeler

**liboqs = Referans Performans Kütüphanesi**
**QSCG = Python Ekosistem Arayüzü**

| Senaryo | Tavsiye |
|---------|---------|
| Hız kritik (10μs seviyesi) | liboqs doğrudan |
| Python ekosisteminde çalışmak | QSCG pure |
| En iyi ikisi | QSCG + liboqs ctypes backend |
| Prototipleme/Hızlı test | QSCG pure |
| Üretim/Deployment | liboqs veya QSCG + liboqs |

**QSCG Geliştirme Önerisi:**
1. `qscg_liboqs.py` modülü ekle (ctypes wrapper)
2. `QSCG` class'ına `backend="liboqs"` parametresi ekle
3. `setup.py`'ye `extras_require={"liboqs": ["oqs"]}]` ekle
4. CI'de liboqs ile cross-validation testleri ekle

---

*Analiz: Bilge Kağan | QSCG Quantum Tunneling Research | M.Cem Koca {Deuterium12}*
