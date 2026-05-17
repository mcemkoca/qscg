"""
Yardimci fonksiyonlar
"""

import base64
import os

def bytes_to_base64(data: bytes) -> str:
    """Baytlari Base64'e cevir"""
    return base64.b64encode(data).decode('utf-8')

def base64_to_bytes(data: str) -> bytes:
    """Base64'ten bayta cevir"""
    return base64.b64decode(data)

def secure_random_bytes(length: int = 32) -> bytes:
    """Kriptografik olarak guvenli rastgele bayt"""
    return os.urandom(length)

def hex_to_bytes(hex_str: str) -> bytes:
    """Hex string'i bayta cevir"""
    return bytes.fromhex(hex_str)

def bytes_to_hex(data: bytes) -> str:
    """Baytlari hex string'e cevir"""
    return data.hex()
