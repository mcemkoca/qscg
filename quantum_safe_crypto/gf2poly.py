"""GF(2) polynomials for HQC - bit-vector representation.

Polynomials over GF(2) = {0, 1} with XOR addition and AND multiplication.
Represented as arrays of 64-bit words (little-endian bit order).
Ring: GF(2)[x] / (x^n - 1)  => cyclic convolution
"""

from typing import List, Tuple
import os


class GF2Poly:
    """Polynomial over GF(2) represented as bit vector."""

    def __init__(self, n: int, words: List[int] = None):
        self.n = n
        self.nwords = (n + 63) // 64
        if words is None:
            self.words = [0] * self.nwords
        else:
            self.words = list(words) + [0] * (self.nwords - len(words))
            self.words = self.words[:self.nwords]
        # Mask higher bits in last word
        if n % 64 != 0:
            mask = (1 << (n % 64)) - 1
            self.words[-1] &= mask

    @classmethod
    def from_bits(cls, n: int, bits: bytes) -> "GF2Poly":
        """Create from byte array (little-endian bit order within bytes)."""
        p = cls(n)
        for i, b in enumerate(bits):
            word_idx = i // 8
            bit_idx = (i % 8) * 8
            if word_idx < p.nwords:
                p.words[word_idx] |= b << bit_idx
        return p

    def to_bytes(self) -> bytes:
        """Export as byte array."""
        size = (self.n + 7) // 8
        result = bytearray(size)
        for i in range(size):
            word_idx = i // 8
            bit_idx = (i % 8) * 8
            if word_idx < self.nwords:
                result[i] = (self.words[word_idx] >> bit_idx) & 0xFF
        return bytes(result)

    def bit(self, i: int) -> int:
        """Get bit i (0 or 1)."""
        i %= self.n
        return (self.words[i // 64] >> (i % 64)) & 1

    def set_bit(self, i: int, val: int):
        """Set bit i to val (0 or 1)."""
        i %= self.n
        if val:
            self.words[i // 64] |= 1 << (i % 64)
        else:
            self.words[i // 64] &= ~(1 << (i % 64))

    def __xor__(self, other: "GF2Poly") -> "GF2Poly":
        """XOR addition in GF(2)."""
        result = GF2Poly(self.n)
        for i in range(self.nwords):
            result.words[i] = self.words[i] ^ other.words[i]
        return result

    def __eq__(self, other) -> bool:
        if not isinstance(other, GF2Poly):
            return False
        return self.n == other.n and self.words == other.words

    def hamming_weight(self) -> int:
        """Count number of 1 bits."""
        return sum(w.bit_count() for w in self.words)

    @classmethod
    def random_sparse(cls, n: int, weight: int) -> "GF2Poly":
        """Generate random sparse polynomial with given Hamming weight."""
        import random
        p = cls(n)
        positions = random.sample(range(n), weight)
        for pos in positions:
            p.set_bit(pos, 1)
        return p

    @classmethod
    def random_dense(cls, n: int) -> "GF2Poly":
        """Generate random dense polynomial."""
        p = cls(n)
        nbytes = (n + 7) // 8
        buf = os.urandom(nbytes)
        for i, b in enumerate(buf):
            word_idx = i // 8
            bit_idx = (i % 8) * 8
            if word_idx < p.nwords:
                p.words[word_idx] |= b << bit_idx
        # Mask
        if n % 64 != 0:
            mask = (1 << (n % 64)) - 1
            p.words[-1] &= mask
        return p

    def __repr__(self):
        return f"GF2Poly(n={self.n}, w={self.hamming_weight()})"


def gf2_mul(a: GF2Poly, b: GF2Poly, n: int) -> GF2Poly:
    """Multiply two polynomials in GF(2)[x] / (x^n - 1).

    This is cyclic convolution (mod x^n - 1).
    Naive O(n^2) algorithm - sufficient for education/research.
    For production, use NTT or Karatsuba.
    """
    assert a.n == b.n == n
    result = GF2Poly(n)
    # For each set bit in a, XOR-shift b
    for i in range(n):
        if a.bit(i):
            for j in range(n):
                if b.bit(j):
                    k = (i + j) % n
                    result.set_bit(k, result.bit(k) ^ 1)
    return result


def gf2_mul_sparse(a: GF2Poly, b: GF2Poly, n: int) -> GF2Poly:
    """Optimized multiplication when inputs are sparse."""
    assert a.n == b.n == n
    result = GF2Poly(n)
    a_positions = [i for i in range(n) if a.bit(i)]
    b_positions = [j for j in range(n) if b.bit(j)]
    for i in a_positions:
        for j in b_positions:
            k = (i + j) % n
            result.set_bit(k, result.bit(k) ^ 1)
    return result
