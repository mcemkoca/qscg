"""Reed-Muller RM(1,7) code - duplicated for HQC.

HQC uses duplicated Reed-Muller codes:
  HQC-1: [384, 8, 192]  = 3 copies of RM(1,7) = [128, 8, 64]
  HQC-3: [640, 8, 320]  = 5 copies of RM(1,7)
  HQC-5: [640, 8, 320]  = 5 copies of RM(1,7)

RM(1,m) parameters:
  length: 2^m
  dimension: m + 1
  min distance: 2^(m-1)

For m=7: length=128, dim=8, min_dist=64
"""

from typing import List


class ReedMuller:
    """First-order Reed-Muller code RM(1,7) with duplication.

    Encode: 8-bit message → 128-bit codeword (× n_copies → 384 or 640 bits)
    Decode: Maximum Likelihood via brute-force (256 codewords, fast enough)
    """

    def __init__(self, m: int = 7, n_copies: int = 3):
        self.m = m              # number of variables
        self.n = 2 ** m         # codeword length per copy (128)
        self.k = m + 1          # message bits (8)
        self.d = 2 ** (m - 1)  # min distance per copy (64)
        self.n_copies = n_copies
        self.total_n = self.n * n_copies  # total length (384 or 640)

        # Precompute all 2^k = 256 codewords for one copy
        self._codewords = []
        for msg in range(2 ** self.k):
            cw = self._encode_single(msg)
            self._codewords.append(cw)

    def _encode_single(self, msg: int) -> int:
        """Encode 8-bit message to 128-bit codeword (integer representation)."""
        cw = 0
        for j in range(self.n):
            # codeword bit j = m0 XOR sum(m_i * j_i) for i=1..7
            bit = (msg >> 0) & 1  # constant term m0
            for i in range(self.m):
                j_bit = (j >> i) & 1      # i-th bit of position j
                msg_bit = (msg >> (i + 1)) & 1  # variable m_{i+1}
                bit ^= j_bit & msg_bit
            if bit:
                cw |= (1 << j)
        return cw

    def encode_byte(self, byte_val: int) -> int:
        """Encode one byte (0..255) to full duplicated codeword."""
        cw = self._codewords[byte_val]
        # Duplicate n_copies times
        result = 0
        for copy in range(self.n_copies):
            result |= (cw << (copy * self.n))
        return result

    def encode(self, message: bytes) -> int:
        """Encode a message (multiple bytes) to concatenated codewords.

        Returns integer representing the full bit vector.
        """
        result = 0
        pos = 0
        for b in message:
            cw = self.encode_byte(b)
            result |= (cw << pos)
            pos += self.total_n
        return result

    def decode(self, noisy: int, msg_bits: int = 8) -> int:
        """Maximum Likelihood decode a noisy word.

        Args:
            noisy: received word as integer (full duplicated length)
            msg_bits: number of message bits to decode (default 8 = 1 byte)

        Returns:
            decoded message as integer (0..255 for 1 byte)
        """
        # We decode one byte at a time
        best_msg = 0
        best_score = -1

        for msg in range(2 ** self.k):
            score = 0
            for copy in range(self.n_copies):
                copy_offset = copy * self.n
                cw = self._codewords[msg]
                # Count agreements between noisy[copy_offset:copy_offset+n] and cw
                for j in range(self.n):
                    noisy_bit = (noisy >> (copy_offset + j)) & 1
                    cw_bit = (cw >> j) & 1
                    if noisy_bit == cw_bit:
                        score += 1

            if score > best_score:
                best_score = score
                best_msg = msg

        return best_msg

    def decode_bytes(self, noisy: int, num_bytes: int) -> bytes:
        """Decode multiple bytes from concatenated noisy word."""
        result = bytearray(num_bytes)
        for i in range(num_bytes):
            byte_start = i * self.total_n
            # Extract this byte's noisy segment
            segment = (noisy >> byte_start) & ((1 << self.total_n) - 1)
            result[i] = self.decode(segment)
        return bytes(result)


class ReedSolomon:
    """Reed-Solomon code over GF(256) for HQC.

    HQC-1: RS[46, 16, 31] - 16 data symbols → 46 symbols (30 parity)
    HQC-3: RS[56, 24, 33] - 24 data symbols → 56 symbols
    HQC-5: RS[90, 32, 59] - 32 data symbols → 90 symbols

    Uses brute-force Berlekamp-Massey decoder (simplified for HQC).
    """

    # Primitive polynomial for GF(256): x^8 + x^4 + x^3 + x^2 + 1
    PRIMITIVE_POLY = 0x11D

    def __init__(self, n: int, k: int):
        """Initialize RS(n, k) code.

        Args:
            n: total symbols (codeword length)
            k: data symbols (message length)
        """
        self.n = n
        self.k = k
        self.t = (n - k) // 2  # error correction capability

        # Build GF(256) log/antilog tables
        self._gf_log = [0] * 256
        self._gf_alog = [0] * 256
        self._build_gf_tables()

        # Generator polynomial roots: alpha^0, alpha^1, ..., alpha^(n-k-1)
        self._roots = list(range(n - k))

    def _build_gf_tables(self):
        """Build GF(256) multiplication tables."""
        x = 1
        for i in range(255):
            self._gf_alog[i] = x
            self._gf_log[x] = i
            x <<= 1
            if x & 0x100:
                x ^= self.PRIMITIVE_POLY
        self._gf_alog[255] = 1
        self._gf_log[0] = 0  # log(0) undefined, set to 0

    def _gf_mul(self, a: int, b: int) -> int:
        """Multiply in GF(256)."""
        if a == 0 or b == 0:
            return 0
        return self._gf_alog[(self._gf_log[a] + self._gf_log[b]) % 255]

    def _gf_inv(self, a: int) -> int:
        """Inverse in GF(256)."""
        if a == 0:
            raise ValueError("GF(0) has no inverse")
        return self._gf_alog[(255 - self._gf_log[a]) % 255]

    def _gf_add(self, a: int, b: int) -> int:
        """Add in GF(256) = XOR."""
        return a ^ b

    def encode(self, message: bytes) -> bytes:
        """Encode message (k bytes) to codeword (n bytes).

        Systematic encoding: first k symbols = message, last n-k = parity.
        """
        if len(message) != self.k:
            raise ValueError(f"Message must be {self.k} bytes")

        # For simplicity: return message + zero padding
        # Real RS encoding requires polynomial division by generator
        # This is a STUB - real implementation needs generator polynomial
        return message + bytes(self.n - self.k)

    def decode(self, received: bytes) -> bytes:
        """Decode received word to message.

        Simplified decoder - assumes no errors for now.
        Full Berlekamp-Massey implementation would be ~200 lines.
        """
        if len(received) != self.n:
            raise ValueError(f"Received must be {self.n} bytes")

        # STUB: just return first k bytes (systematic)
        # Real decoder would:
        # 1. Compute syndromes
        # 2. Berlekamp-Massey for error locator
        # 3. Chien search for error positions
        # 4. Forney for error values
        # 5. Correct and extract message
        return received[:self.k]


class HQCCode:
    """Concatenated RS + RM code used in HQC.

    HQC-1: RS[46,16,31] outer + RM[384,8,192] inner
    """

    def __init__(self, security_level: int = 1):
        if security_level == 1:
            self.rs = ReedSolomon(46, 16)
            self.rm = ReedMuller(m=7, n_copies=3)
        elif security_level == 3:
            self.rs = ReedSolomon(56, 24)
            self.rm = ReedMuller(m=7, n_copies=5)
        elif security_level == 5:
            self.rs = ReedSolomon(90, 32)
            self.rm = ReedMuller(m=7, n_copies=5)
        else:
            raise ValueError("security_level must be 1, 3, or 5")

    def encode(self, message: bytes) -> int:
        """Encode message to full codeword bit vector."""
        # Step 1: RS encode
        rs_codeword = self.rs.encode(message)

        # Step 2: Each RS symbol (1 byte) → RM encode
        result = 0
        pos = 0
        for symbol in rs_codeword:
            rm_cw = self.rm.encode_byte(symbol)
            result |= (rm_cw << pos)
            pos += self.rm.total_n
        return result

    def decode(self, noisy: int, n_bits: int) -> bytes:
        """Decode noisy bit vector to message.

        Args:
            noisy: received word as integer
            n_bits: number of valid bits (may have padding)

        Returns:
            decoded message bytes
        """
        # Step 1: RM decode each symbol
        num_rs_symbols = self.rs.n
        rs_codeword = bytearray(num_rs_symbols)

        for i in range(num_rs_symbols):
            symbol_start = i * self.rm.total_n
            # Extract this symbol's noisy segment
            segment = (noisy >> symbol_start) & ((1 << self.rm.total_n) - 1)
            rs_codeword[i] = self.rm.decode(segment)

        # Step 2: RS decode
        return self.rs.decode(bytes(rs_codeword))
