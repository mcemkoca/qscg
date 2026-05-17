# 🔐 Quantum-Safe Kriptografi - Kafes (Lattice) Tabanlı

[![NIST](https://img.shields.io/badge/NIST-FIPS%20203%2F204%2F205-blue)](https://www.nist.gov/pqc)
[![Quantum-Safe](https://img.shields.io/badge/Quantum-Safe-success)](https://en.wikipedia.org/wiki/Post-quantum_cryptography)
[![Python](https://img.shields.io/badge/Python-3.9%2B-blue)](https://python.org)

> **NIST Post-Quantum Cryptography (PQC) Standartlarına uygun, kuantum bilgisayarlara karşı dirençli kriptografik araç seti.**

## 🚀 Özellikler

- **🔐 ML-KEM (FIPS 203)**: Module-Lattice-Based Key Encapsulation Mechanism
- **✍️ ML-DSA (FIPS 204)**: Module-Lattice-Based Digital Signature Algorithm  
- **🔒 AES-256-GCM**: Simetrik şifreleme (Authenticated Encryption)
- **⚡ Tek Tık İşlemler**: Kullanıcı dostu masaüstü arayüzü
- **📊 Karşılaştırma**: Klasik vs Kafes kriptografi analizi
- **⚛️ Kuantum Analiz**: Shor, Grover, HNDL tehdit değerlendirmesi

## 📦 Kurulum

```bash
# Gereksinimler
pip install cryptography numpy

# Uygulamayı çalıştır
python src/quantum_safe_gui.py
```

## 🖥️ Kullanım

### 1. ML-KEM Anahtar Değişimi
```python
from src.lattice_crypto import MLKEM

# Anahtar üret
kem = MLKEM(level=3)  # Level 3 = AES-192 eşdeğeri
keys = kem.keygen()

# Kapsülle
ct, secret = kem.encapsulate(keys['pk'])

# Aç
recovered = kem.decapsulate(keys['sk'], ct)
assert secret == recovered  # ✅ Başarılı
```

### 2. ML-DSA Dijital İmza
```python
from src.lattice_crypto import MLDSA

# Anahtar üret
dsa = MLDSA(level=3)
keys = dsa.keygen()

# İmzala
message = b"Kuantum güvenli mesaj"
signature = dsa.sign(keys['sk'], message)

# Doğrula
valid = dsa.verify(keys['pk'], message, signature)
assert valid  # ✅ Geçerli
```

### 3. AES-256-GCM Şifreleme
```python
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

key = os.urandom(32)
nonce = os.urandom(12)
aesgcm = AESGCM(key)

ciphertext = aesgcm.encrypt(nonce, b"Gizli veri", None)
plaintext = aesgcm.decrypt(nonce, ciphertext, None)
```

## 📊 Algoritma Karşılaştırması

| Özellik | Klasik (RSA/ECC) | Kafes (ML-KEM/ML-DSA) |
|---------|------------------|----------------------|
| Kuantum Güvenlik | ❌ Kırılır | ✅ Dirençli |
| NIST Durum | 2035 Yasak | FIPS 203/204/205 |
| Public Key | 32-256 bytes | 1,184 bytes (ML-KEM-768) |
| İmza Boyutu | 64 bytes (ECDSA) | 3,293 bytes (ML-DSA-65) |
| KeyGen Hızı | Yavaş (RSA) | ~100 mikrosaniye |
| Matematiksel Temel | Tam Çarpana Ayırma | Module-LWE / Module-SIS |

## ⚛️ Kuantum Tehdidi Analizi

### Shor Algoritması
- **RSA ve ECC**: Polinom zamanda kırılır (O(n³))
- **Kafes Kripto**: **UYGULANAMAZ** - farklı matematiksel temel

### Grover Algoritması  
- **Simetrik Şifreleme**: Arama hızlanması O(N) → O(√N)
- **AES-256**: Kuantumda ~128-bit güvenlik (YETERLİ)
- **Kafes Kripto**: Doğrudan etkisi YOK

### Harvest Now, Decrypt Later (HNDL)
> Düşmanlar bugün şifreli veriyi toplar, yarın çözer.
> 
> **Çözüm**: Hemen hibrit kriptografi geçişi (X25519Kyber768)

## 📅 Migrasyon Takvimi

| Tarih | Olay |
|-------|------|
| 2026 Eylül | FIPS 140-2 sunset |
| 2027 Ocak | CNSA 2.0 - PQC zorunlu |
| 2030 | 112-bit algoritmalar deprecated |
| 2035 | Klasik algoritmalar **YASAK** |

## 🛠️ Proje Yapısı

```
quantum-safe-crypto/
├── src/
│   ├── __init__.py
│   ├── lattice_crypto.py      # Kafes kriptografi kütüphanesi
│   ├── quantum_safe_gui.py    # Masaüstü uygulaması
│   └── utils.py               # Yardımcı fonksiyonlar
├── docs/
│   ├── NIST_FIPS_203.md       # ML-KEM spesifikasyonu
│   ├── NIST_FIPS_204.md       # ML-DSA spesifikasyonu
│   └── quantum_analysis.md    # Kuantum analiz raporu
├── diagrams/
│   ├── diagram1_overview.png  # Genel yapı
│   ├── diagram2_mlkem.png     # ML-KEM detaylı
│   └── ...                    # 8 adet diyagram
├── tests/
│   └── test_lattice.py        # Birim testleri
├── README.md
├── LICENSE
└── requirements.txt
```

## 📚 Kaynaklar

- [NIST PQC Project](https://www.nist.gov/pqc)
- [FIPS 203: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [FIPS 204: ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [FIPS 205: SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [CRYSTALS-Kyber](https://pq-crystals.org/kyber/)
- [CRYSTALS-Dilithium](https://pq-crystals.org/dilithium/)

## ⚠️ Uyarı

Bu proje eğitim ve araştırma amaçlıdır. Üretim ortamında kullanmadan önce:
- Formal doğrulama yapın
- Side-channel analizi yapın
- Uzman kriptograf gözden geçirmesi alın

## 📄 Lisans

MIT License - Detaylar için [LICENSE](LICENSE) dosyasına bakın.

## 👤 Yazar

**Dante** - Quantum-Safe Kriptografi Araştırmacısı

---

⭐ **Bu projeyi beğendiyseniz yıldız verin!**
