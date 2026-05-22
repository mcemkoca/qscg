# HQC ve Classic McEliece Değerlendirmesi
## QSCG v4.0 - Quantum Tunneling Research

### Özet

liboqs backend ile QSCG artık **BIKE, HQC, Classic-McEliece** gibi code-based KEM algoritmalarına da erişebiliyor. Bu doküman bu algoritmaların QSCG entegrasyonu için değerlendirmesini içerir.

---

## 1. HQC (Hamming Quasi-Cyclic)

### Teknik Detaylar
- **Kategori:** Code-based (QC-MDPC türevi)
- **Güvenlik:** NIST Round 4 (finalist)
- **liboqs isimleri:** `HQC-128`, `HQC-192`, `HQC-256`
- **Anahtar boyutları:**
  - HQC-128: PK=2249B, SK=2289B, CT=4481B
  - HQC-192: PK=4562B, SK=4626B, CT=9026B
  - HQC-256: PK=7285B, SK=7373B, CT=14469B

### Artıları
- Daha küçük ciphertext (ML-KEM-768: 1088B vs HQC-128: 4481B) ❌
- Daha büyük ciphertext (dezavantaj)
- Conservative security assumption (coding theory)
- Simple implementation

### Eksileri
- Çok büyük ciphertext (~4-14KB)
- Daha yavaş (ML-KEM'ye göre)
- Daha az kullanım (community adoption)

### QSCG Entegrasyonu
```python
from liboqs_backend import LiboqsKEM

hqc = LiboqsKEM('HQC-128')
pk, sk = hqc.keypair()
ct, ss = hqc.encaps(pk)
```
**Durum:** Kolayca entegre edilebilir (liboqs backend zaten destekliyor).

---

## 2. Classic McEliece

### Teknik Detaylar
- **Kategori:** Code-based (Goppa codes)
- **Güvenlik:** NIST Round 4 (finalist)
- **liboqs isimleri:** `Classic-McEliece-348864`, `Classic-McEliece-460896`, ..., `Classic-McEliece-8192128`
- **Anahtar boyutları (8192128):**
  - PK: **1,357,824 bytes (1.3 MB!)**
  - SK: 13,936 bytes
  - CT: 240 bytes

### Artıları
- En eski PQC algoritması (40+ yıllık literatür)
- Strong security proofs
- Very small ciphertext (240B)
- Fast decapsulation

### Eksileri
- **Devasa public key (1.3 MB)** - Pratik kullanım zor
- Büyük secret key
- NIST standardı DEĞİL (Round 4 finalist)

### QSCG Entegrasyonu
```python
mceliece = LiboqsKEM('Classic-McEliece-348864')
# PK = 261,120 bytes - hâlâ çok büyük!
```
**Durum:** Teknik olarak mümkün, pratik olarak zor.

---

## 3. BIKE (Bit Flipping Key Encapsulation)

### Teknik Detaylar
- **Kategori:** Code-based (QC-MDPC)
- **Güvenlik:** NIST Round 4 (finalist)
- **liboqs isimleri:** `BIKE-L1`, `BIKE-L3`, `BIKE-L5`
- **Anahtar boyutları:**
  - BIKE-L1: PK=1,541B, SK=1,630B, CT=1,573B
  - BIKE-L3: PK=3,083B, SK=3,158B, CT=3,113B
  - BIKE-L5: PK=5,122B, SK=5,218B, CT=5,172B

### Artıları
- Relatively small keys
- Simple structure
- Conservative assumptions

### Eksileri
- Variable-time decoding (side-channel risk)
- Daha az optimize edilmiş
- Limited real-world deployment

---

## 4. Karşılaştırma Tablosu

| Algoritma | PK (B) | SK (B) | CT (B) | liboqs desteği |
|-----------|--------|--------|--------|----------------|
| ML-KEM-768 | 1,184 | 2,400 | 1,088 | ✅ Çalışıyor |
| HQC-128 | 2,249 | 2,289 | 4,481 | ✅ Hazır |
| BIKE-L1 | 1,541 | 1,630 | 1,573 | ✅ Hazır |
| McEliece-348864 | 261,120 | 13,936 | 240 | ✅ Hazır (ama devasa) |

---

## 5. Öneri

### Hemen Entegre Edilecek (Kolay)
1. **BIKE-L1/L3** - Makul boyutlar, liboqs destekli
2. **HQC-128** - NIST finalist, konservatif güvenlik

### Düşük Öncelik
3. **Classic McEliece** - 1.3MB public key pratik değil

### Entegrasyon Kodu
```python
# QSCG class'a ekle:
def generate_kem_keypair_bike(self, level=1):
    """BIKE KEM via liboqs"""
    from liboqs_backend import LiboqsKEM
    kem = LiboqsKEM(f'BIKE-L{level}')
    return kem.keypair()

def encapsulate_bike(self, pk, level=1):
    from liboqs_backend import LiboqsKEM
    kem = LiboqsKEM(f'BIKE-L{level}')
    return kem.encaps(pk)
```

---

## Sonuç

**ML-KEM halâ QSCG'nin ana KEM algoritması olmalı.** Ancak:
- **BIKE** ve **HQC** liboqs backend ile kolayca eklenebilir
- **Kriptografik çeşitlilik** için faydalı (farklı hard problem assumptions)
- **Future-proofing** için NIST Round 4 finalistleri desteklemek iyi

**Eylem:** `QSCG.generate_kem_keypair()` API'sini genişletip BIKE/HQC opsiyonları eklemek.

---

*Built with love by M.Cem Koca {Deuterium12}*
*QSCG v4.0 - Quantum Tunneling Research*
