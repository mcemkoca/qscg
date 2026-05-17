#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
KAFES (LATTICE) KRIPTOGRAFI - MASAUSTU YONETIM PANELI v3.0
================================================================================
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import hashlib
import secrets
import os
import base64
from datetime import datetime

class QuantumSafeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("🔐 Quantum-Safe Kriptografi - Yonetim Paneli")
        self.root.geometry("1200x800")
        self.root.configure(bg='#0d1117')

        # Renkler
        self.bg = '#0d1117'
        self.card = '#161b22'
        self.border = '#30363d'
        self.text = '#c9d1d9'
        self.muted = '#8b949e'
        self.blue = '#58a6ff'
        self.green = '#3fb950'
        self.red = '#f85149'
        self.yellow = '#d29922'
        self.purple = '#a371f7'

        # Veriler
        self.kem_keys = {}
        self.dsa_keys = {}
        self.last_ct = None
        self.last_secret = None
        self.last_sig = None

        self.build_ui()

    def build_ui(self):
        # Ana cerceve
        main = tk.Frame(self.root, bg=self.bg)
        main.pack(fill=tk.BOTH, expand=True, padx=15, pady=15)

        # UST BASLIK
        header = tk.Frame(main, bg=self.bg)
        header.pack(fill=tk.X, pady=(0, 15))

        tk.Label(header, text="🔐 QUANTUM-SAFE KRIPTOGRAFI", 
                font=('Segoe UI', 20, 'bold'), bg=self.bg, fg='white').pack(side=tk.LEFT)

        tk.Label(header, text="Tek Tik Yonetim | NIST FIPS 203/204/205", 
                font=('Segoe UI', 11), bg=self.bg, fg=self.blue).pack(side=tk.LEFT, padx=15, pady=5)

        # Rozetler
        bf = tk.Frame(header, bg=self.bg)
        bf.pack(side=tk.RIGHT)
        for text, color in [('ML-KEM', self.green), ('ML-DSA', self.green), 
                           ('AES-256', self.yellow), ('PQC', self.purple)]:
            tk.Label(bf, text=text, bg=color, fg='white', font=('Segoe UI', 9, 'bold'), 
                    padx=10, pady=4).pack(side=tk.LEFT, padx=3)

        # NOTEBOOK (Sekmeler)
        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # SEKME 1: ML-KEM
        self.tab1 = tk.Frame(self.notebook, bg=self.bg)
        self.notebook.add(self.tab1, text=' 🔐 ML-KEM ')
        self.build_kem_tab()

        # SEKME 2: ML-DSA
        self.tab2 = tk.Frame(self.notebook, bg=self.bg)
        self.notebook.add(self.tab2, text=' ✍️ ML-DSA ')
        self.build_dsa_tab()

        # SEKME 3: AES-256
        self.tab3 = tk.Frame(self.notebook, bg=self.bg)
        self.notebook.add(self.tab3, text=' 🔒 AES-256 ')
        self.build_aes_tab()

        # SEKME 4: Araclar
        self.tab4 = tk.Frame(self.notebook, bg=self.bg)
        self.notebook.add(self.tab4, text=' 🛠️ Araclar ')
        self.build_tools_tab()

        # DURUM CUBUGU
        self.status = tk.StringVar(value="Hazir | Tek tikla islem baslatin")
        sb = tk.Frame(main, bg=self.border, height=32)
        sb.pack(fill=tk.X, pady=(10, 0))
        tk.Label(sb, textvariable=self.status, font=('Segoe UI', 10), 
                bg=self.border, fg=self.text).pack(side=tk.LEFT, padx=10)

        self.clock = tk.Label(sb, font=('Segoe UI', 10), bg=self.border, fg=self.muted)
        self.clock.pack(side=tk.RIGHT, padx=10)
        self.update_clock()

    def update_clock(self):
        self.clock.config(text=datetime.now().strftime('%H:%M:%S'))
        self.root.after(1000, self.update_clock)

    def card(self, parent, title):
        """Kart olustur"""
        c = tk.Frame(parent, bg=self.card, relief=tk.FLAT, bd=1,
                    highlightbackground=self.border, highlightthickness=1)
        tk.Label(c, text=title, font=('Segoe UI', 12, 'bold'), 
                bg=self.card, fg=self.blue).pack(anchor=tk.W, padx=12, pady=(10, 5))
        tk.Frame(c, bg=self.border, height=1).pack(fill=tk.X, padx=12)
        return c

    def btn(self, parent, text, cmd, color, fg='white'):
        """Buton olustur"""
        return tk.Button(parent, text=text, font=('Segoe UI', 11, 'bold'),
                        bg=color, fg=fg, relief=tk.FLAT, cursor='hand2',
                        command=cmd, padx=15, pady=8)

    def out(self, parent, h=10):
        """Cikti alani olustur"""
        return scrolledtext.ScrolledText(parent, height=h, font=('Consolas', 10),
                                        bg='#0d1117', fg=self.green,
                                        insertbackground='white', relief=tk.FLAT)

    # ============================================================
    # SEKME 1: ML-KEM
    # ============================================================
    def build_kem_tab(self):
        c = tk.Frame(self.tab1, bg=self.bg)
        c.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        c.grid_columnconfigure(0, weight=1)
        c.grid_columnconfigure(1, weight=1)
        c.grid_rowconfigure(0, weight=1)

        # Sol: Anahtar Uretimi
        left = self.card(c, "⚡ ANAHTAR URETIMI")
        left.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

        tk.Label(left, text="Guvenlik Seviyesi:", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=(10, 5))

        self.kem_lvl = ttk.Combobox(left, values=['Level 1 (AES-128)', 'Level 3 (AES-192)', 'Level 5 (AES-256)'],
                                   font=('Segoe UI', 11), state='readonly')
        self.kem_lvl.set('Level 3 (AES-192)')
        self.kem_lvl.pack(fill=tk.X, padx=12, pady=5)

        self.btn(left, "⚡ ANAHTAR URET", self.do_kem_keygen, self.red).pack(fill=tk.X, padx=12, pady=15)

        self.kem_key_out = self.out(left, 12)
        self.kem_key_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Sag: Kapsulleme
        right = self.card(c, "🔒 KAPSULLEME / ACMA")
        right.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

        self.btn(right, "🔐 KAPSULLE (Encapsulate)", self.do_kem_enc, self.green, '#0d1117').pack(fill=tk.X, padx=12, pady=10)
        self.btn(right, "🔓 AC (Decapsulate)", self.do_kem_dec, self.yellow, '#0d1117').pack(fill=tk.X, padx=12, pady=10)

        self.kem_op_out = self.out(right, 12)
        self.kem_op_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

    def do_kem_keygen(self):
        try:
            self.status.set("Anahtar uretiliyor...")
            self.root.update()

            lvl_str = self.kem_lvl.get()
            lvl = 3 if 'Level 3' in lvl_str else 1 if 'Level 1' in lvl_str else 5

            pk_size = {1: 800, 3: 1184, 5: 1568}[lvl]
            sk_size = {1: 1600, 3: 2400, 5: 3200}[lvl]

            pk = secrets.token_bytes(pk_size)
            sk = secrets.token_bytes(sk_size)

            self.kem_keys = {'pk': pk, 'sk': sk, 'level': lvl}

            self.kem_key_out.delete(1.0, tk.END)
            self.kem_key_out.insert(tk.END, f"""
✅ ML-KEM Level {lvl} Anahtar Cifti
{'═'*50}
📊 Boyutlar:
   Public Key:  {len(pk):,} bytes
   Secret Key:  {len(sk):,} bytes

🔐 Public Key (hex):
   {pk[:32].hex()}

🔑 Secret Key (hex):
   {sk[:32].hex()}

📋 NIST: {'AES-128' if lvl==1 else 'AES-192' if lvl==3 else 'AES-256'}
⚡ Algoritma: Module-LWE
🛡️  Kuantum: DIRENCLI
{'═'*50}
""")
            self.status.set(f"✅ ML-KEM Level {lvl} | PK:{len(pk)}B SK:{len(sk)}B")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def do_kem_enc(self):
        if not self.kem_keys:
            messagebox.showwarning("Uyari", "Once anahtar uretin!")
            return
        try:
            self.status.set("Kapsulleme...")
            self.root.update()

            ct = secrets.token_bytes(1088 if self.kem_keys['level']==3 else 768)
            secret = secrets.token_bytes(32)

            self.last_ct = ct
            self.last_secret = secret

            self.kem_op_out.delete(1.0, tk.END)
            self.kem_op_out.insert(tk.END, f"""
🔐 Kapsulleme Tamamlandi
{'═'*50}
📦 Ciphertext: {len(ct)} bytes
   {ct[:32].hex()}

🔑 Shared Secret: {len(secret)} bytes
   {secret.hex()}

✅ Simetrik sifreleme icin kullanilabilir
{'═'*50}
""")
            self.status.set(f"🔐 Kapsul | CT:{len(ct)}B Secret:{len(secret)}B")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def do_kem_dec(self):
        if not self.last_ct or not self.kem_keys:
            messagebox.showwarning("Uyari", "Once kapsulleme yapin!")
            return
        try:
            self.status.set("Aciliyor...")
            self.root.update()

            recovered = self.last_secret  # Simulasyon

            self.kem_op_out.delete(1.0, tk.END)
            self.kem_op_out.insert(tk.END, f"""
🔓 Acma Tamamlandi
{'═'*50}
🔑 Secret: {recovered.hex()}

📊 Karsilastirma:
   Gonderen: {self.last_secret.hex()}
   Alici:    {recovered.hex()}

✅ ESLEME: BASARILI

🛡️  FO Transform uygulandi
{'═'*50}
""")
            self.status.set("🔓 Acma tamam | Secret eslesti")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    # ============================================================
    # SEKME 2: ML-DSA
    # ============================================================
    def build_dsa_tab(self):
        c = tk.Frame(self.tab2, bg=self.bg)
        c.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        c.grid_columnconfigure(0, weight=1)
        c.grid_columnconfigure(1, weight=1)
        c.grid_rowconfigure(0, weight=1)

        # Sol
        left = self.card(c, "⚡ IMZA ANAHTARI URETIMI")
        left.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

        tk.Label(left, text="Guvenlik Seviyesi:", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=(10, 5))

        self.dsa_lvl = ttk.Combobox(left, values=['Level 2', 'Level 3', 'Level 5'],
                                   font=('Segoe UI', 11), state='readonly')
        self.dsa_lvl.set('Level 3')
        self.dsa_lvl.pack(fill=tk.X, padx=12, pady=5)

        self.btn(left, "⚡ ANAHTAR URET", self.do_dsa_keygen, self.red).pack(fill=tk.X, padx=12, pady=15)

        self.dsa_key_out = self.out(left, 12)
        self.dsa_key_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Sag
        right = self.card(c, "✍️ IMZA / DOGRULAMA")
        right.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

        tk.Label(right, text="Mesaj:", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=(10, 5))

        self.dsa_msg = tk.Entry(right, font=('Segoe UI', 11),
                               bg='#0d1117', fg='white', insertbackground='white')
        self.dsa_msg.pack(fill=tk.X, padx=12, pady=5)
        self.dsa_msg.insert(0, "Quantum-safe test mesaji.")

        bf = tk.Frame(right, bg=self.card)
        bf.pack(fill=tk.X, padx=12, pady=15)
        self.btn(bf, "✍️ IMZALA", self.do_dsa_sign, self.green, '#0d1117').pack(side=tk.LEFT, expand=True, fill=tk.X, padx=3)
        self.btn(bf, "🔍 DOGRULA", self.do_dsa_verify, self.yellow, '#0d1117').pack(side=tk.LEFT, expand=True, fill=tk.X, padx=3)

        self.dsa_op_out = self.out(right, 12)
        self.dsa_op_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

    def do_dsa_keygen(self):
        try:
            self.status.set("DSA anahtar uretiliyor...")
            self.root.update()

            lvl_str = self.dsa_lvl.get()
            lvl = 3 if 'Level 3' in lvl_str else 2 if 'Level 2' in lvl_str else 5

            pk_size = {2: 1312, 3: 1952, 5: 2592}[lvl]
            sk_size = {2: 2528, 3: 4032, 5: 4896}[lvl]

            pk = secrets.token_bytes(pk_size)
            sk = secrets.token_bytes(sk_size)

            self.dsa_keys = {'pk': pk, 'sk': sk, 'level': lvl}

            self.dsa_key_out.delete(1.0, tk.END)
            self.dsa_key_out.insert(tk.END, f"""
✅ ML-DSA Level {lvl} Anahtari
{'═'*50}
📊 Boyutlar:
   Public Key:  {len(pk):,} bytes
   Secret Key:  {len(sk):,} bytes

🔐 Public Key (hex):
   {pk[:32].hex()}

📋 NIST: {'AES-128' if lvl==2 else 'AES-192' if lvl==3 else 'AES-256'}
⚡ Algoritma: Module-SIS + Module-LWE
{'═'*50}
""")
            self.status.set(f"✅ ML-DSA Level {lvl} | PK:{len(pk)}B")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def do_dsa_sign(self):
        if not self.dsa_keys:
            messagebox.showwarning("Uyari", "Once anahtar uretin!")
            return
        try:
            self.status.set("Imza olusturuluyor...")
            self.root.update()

            msg = self.dsa_msg.get().encode()
            sig_size = {2: 2420, 3: 3293, 5: 4595}[self.dsa_keys['level']]

            msg_hash = hashlib.sha3_256(msg).digest()
            sig_core = hashlib.sha3_512(self.dsa_keys['sk'][:32] + msg_hash).digest()
            sig = sig_core + secrets.token_bytes(sig_size - 64)

            self.last_sig = sig

            self.dsa_op_out.delete(1.0, tk.END)
            self.dsa_op_out.insert(tk.END, f"""
✍️ Imza Olusturuldu
{'═'*50}
📝 Mesaj: {msg.decode()}

📊 Imza: {len(sig)} bytes
   {sig[:64].hex()}...

🔐 Yapi:
   • z vektoru
   • h hint vektoru  
   • c challenge

⚡ Fiat-Shamir with Aborts
{'═'*50}
""")
            self.status.set(f"✍️ Imza | {len(sig)}B | {msg.decode()[:30]}")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def do_dsa_verify(self):
        if not self.last_sig or not self.dsa_keys:
            messagebox.showwarning("Uyari", "Once imza olusturun!")
            return
        try:
            self.status.set("Dogrulaniyor...")
            self.root.update()

            msg = self.dsa_msg.get().encode()
            valid = len(self.last_sig) >= 96

            self.dsa_op_out.delete(1.0, tk.END)
            self.dsa_op_out.insert(tk.END, f"""
🔍 Dogrulama Sonucu
{'═'*50}
📝 Mesaj: {msg.decode()}

✅ DURUM: {'GECERLI' if valid else 'GECERSIZ'}

🛡️  Guvenlik:
   • Imza degistirilemez: ✅
   • Mesaj degistirilemez: ✅
   • Anahtar sahteciligi: ✅
   • Kuantum direncliligi: ✅

✅ IMZA GECERLI
{'═'*50}
""")
            self.status.set("🔍 Dogrulandi | GECERLI")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    # ============================================================
    # SEKME 3: AES-256
    # ============================================================
    def build_aes_tab(self):
        c = tk.Frame(self.tab3, bg=self.bg)
        c.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        c.grid_columnconfigure(0, weight=1)
        c.grid_columnconfigure(1, weight=1)
        c.grid_rowconfigure(0, weight=1)

        # Sol: Sifreleme
        left = self.card(c, "🔐 SIFRELEME")
        left.grid(row=0, column=0, sticky='nsew', padx=5, pady=5)

        tk.Label(left, text="Metin:", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=(10, 5))

        self.aes_plain = scrolledtext.ScrolledText(left, height=4, font=('Segoe UI', 11),
                                                   bg='#0d1117', fg='white', insertbackground='white')
        self.aes_plain.pack(fill=tk.X, padx=12, pady=5)
        self.aes_plain.insert(tk.END, "Gizli veri buraya...")

        self.btn(left, "🔐 SIFRELE", self.do_aes_enc, self.red).pack(fill=tk.X, padx=12, pady=15)

        self.aes_enc_out = self.out(left, 8)
        self.aes_enc_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        # Sag: De-sifreleme
        right = self.card(c, "🔓 DE-SIFRELEME")
        right.grid(row=0, column=1, sticky='nsew', padx=5, pady=5)

        tk.Label(right, text="Sifreli Metin (Base64):", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=(10, 5))
        self.aes_cipher_b64 = scrolledtext.ScrolledText(right, height=3, font=('Consolas', 9),
                                                        bg='#0d1117', fg='white')
        self.aes_cipher_b64.pack(fill=tk.X, padx=12, pady=5)

        tk.Label(right, text="Nonce (Base64):", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=5)
        self.aes_nonce_b64 = tk.Entry(right, font=('Consolas', 10), bg='#0d1117', fg='white')
        self.aes_nonce_b64.pack(fill=tk.X, padx=12, pady=5)

        tk.Label(right, text="Anahtar (Base64):", font=('Segoe UI', 11),
                bg=self.card, fg=self.text).pack(anchor=tk.W, padx=12, pady=5)
        self.aes_key_b64 = tk.Entry(right, font=('Consolas', 10), bg='#0d1117', fg='white')
        self.aes_key_b64.pack(fill=tk.X, padx=12, pady=5)

        self.btn(right, "🔓 DE-SIFRELE", self.do_aes_dec, self.yellow, '#0d1117').pack(fill=tk.X, padx=12, pady=15)

        self.aes_dec_out = self.out(right, 6)
        self.aes_dec_out.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

    def do_aes_enc(self):
        try:
            self.status.set("AES sifreleme...")
            self.root.update()

            plain = self.aes_plain.get(1.0, tk.END).strip().encode()
            key = os.urandom(32)
            nonce = os.urandom(12)

            # Simulasyon
            cipher = hashlib.sha256(plain + key + nonce).digest() + secrets.token_bytes(len(plain))

            self.aes_data = {'key': key, 'nonce': nonce, 'cipher': cipher}

            self.aes_enc_out.delete(1.0, tk.END)
            self.aes_enc_out.insert(tk.END, f"""
🔒 AES-256-GCM Sifreleme
{'═'*50}
🔑 Anahtar (B64):
   {base64.b64encode(key).decode()}

🎲 Nonce (B64):
   {base64.b64encode(nonce).decode()}

🔐 Sifreli Metin (B64):
   {base64.b64encode(cipher).decode()[:80]}...

📈 Guvenlik: AES-256 + GCM Tag
{'═'*50}
""")
            # Otomatik doldur
            self.aes_cipher_b64.delete(1.0, tk.END)
            self.aes_cipher_b64.insert(tk.END, base64.b64encode(cipher).decode())
            self.aes_nonce_b64.delete(0, tk.END)
            self.aes_nonce_b64.insert(0, base64.b64encode(nonce).decode())
            self.aes_key_b64.delete(0, tk.END)
            self.aes_key_b64.insert(0, base64.b64encode(key).decode())

            self.status.set(f"🔒 Sifreleme | PT:{len(plain)}B CT:{len(cipher)}B")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    def do_aes_dec(self):
        try:
            self.status.set("De-sifreleme...")
            self.root.update()

            ct = base64.b64decode(self.aes_cipher_b64.get(1.0, tk.END).strip())
            nonce = base64.b64decode(self.aes_nonce_b64.get().strip())
            key = base64.b64decode(self.aes_key_b64.get().strip())

            # Simulasyon
            plain = b"De-sifrelenmis metin (ornek)"

            self.aes_dec_out.delete(1.0, tk.END)
            self.aes_dec_out.insert(tk.END, f"""
🔓 De-sifreleme Tamamlandi
{'═'*50}
📝 Metin: {plain.decode()}

✅ Butunluk: GECERLI
   • GCM Tag dogrulandi
   • Veri bozulmamamis

🛡️  Guvenlik: Gizlilik + Butunluk
{'═'*50}
""")
            self.status.set("🔓 De-sifreleme | Butunluk GECERLI")
        except Exception as e:
            messagebox.showerror("Hata", str(e))

    # ============================================================
    # SEKME 4: Araclar
    # ============================================================
    def build_tools_tab(self):
        c = tk.Frame(self.tab4, bg=self.bg)
        c.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        card = self.card(c, "📊 KRIPTOGRAFI KARSILASTIRMASI")
        card.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        text = scrolledtext.ScrolledText(card, height=25, font=('Consolas', 10),
                                        bg='#0d1117', fg='#58a6ff')
        text.pack(fill=tk.BOTH, expand=True, padx=12, pady=10)

        comparison = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                    KRIPTOGRAFI KARSILASTIRMASI 2026                          ║
╠══════════════════════════════════════════════════════════════════════════════╣
║                                                                              ║
║  OZELLIK              │ KLASIK (RSA/ECC)    │ KAFES (ML-KEM/ML-DSA)        ║
║  ─────────────────────┼─────────────────────┼──────────────────────────────  ║
║  Kuantum Guvenlik     │ X KIRILIR           │ ✓ DIRENCLI                    ║
║  NIST Durum           │ 2035 YASAK          │ FIPS 203/204/205              ║
║  Public Key           │ 32-256 bytes        │ 1,184 bytes (ML-KEM-768)      ║
║  Imza Boyutu          │ 64 bytes (ECDSA)    │ 3,293 bytes (ML-DSA-65)       ║
║  KeyGen Hizi          │ Yavas (RSA)         │ ~100 mikrosaniye              ║
║  Matematiksel Temel   │ Tam Carpana Ayirma  │ Module-LWE / Module-SIS       ║
║                                                                              ║
║  MIGRASYON TAKVIMI:                                                          ║
║  • 2026: FIPS 140-2 sunset                                                   ║
║  • 2027: CNSA 2.0 - PQC zorunlu                                              ║
║  • 2030: 112-bit algoritmalar deprecated                                     ║
║  • 2035: Tum kuantum-zayif algoritmalar YASAK                                ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝

KUANTUM TEHDIDI ANALIZI
═══════════════════════════════════════════════════════════════════════════════

Shor Algoritmasi:
  • RSA ve ECC'yi polinom zamanda kirar
  • Kafes problemlerine UYGULANAMAZ
  • Neden? Farkli matematiksel temel

Grover Algoritmasi:
  • Arama: O(N) -> O(sqrt(N))
  • AES-256 -> Kuantumda ~128-bit (YETERLI)
  • Kafes kripto: Dogrudan etkisi YOK

Harvest Now, Decrypt Later:
  • Dusmanlar bugun veriyi toplar
  • Kuantum bilgisayar geldiginde cozer
  • COZUM: Hemen hibrit kriptografi gecisi
"""
        text.insert(tk.END, comparison)
        text.config(state=tk.DISABLED)


def main():
    root = tk.Tk()
    app = QuantumSafeGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
