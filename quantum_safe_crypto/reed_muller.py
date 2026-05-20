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
        Uses polynomial division by generator polynomial.
        """
        if len(message) != self.k:
            raise ValueError(f"Message must be {self.k} bytes")

        # Build generator polynomial g(x) = prod(x - alpha^i) for i=0..n-k-1
        g = [1] + [0] * (self.n - self.k)
        for i in range(self.n - self.k):
            alpha_i = self._gf_alog[i % 255]
            # Multiply g by (x - alpha^i)
            new_g = g[:]
            for j in range(len(g) - 1, -1, -1):
                if g[j] != 0:
                    new_g[j + 1] = self._gf_add(new_g[j + 1], g[j])
                    new_g[j] = self._gf_add(new_g[j], self._gf_mul(g[j], alpha_i))
            g = new_g[:len(g) + 1]

        # Systematic encoding: shift message by n-k, divide by g(x)
        # For simplicity: return message + syndrome of shifted message
        # Real encoding: m(x) * x^(n-k) mod g(x)
        shifted = list(message) + [0] * (self.n - self.k)
        remainder = self._poly_mod(shifted, g)
        return bytes(message) + bytes(remainder)

    def _poly_mod(self, dividend: List[int], divisor: List[int]) -> List[int]:
        """Polynomial division in GF(256): dividend mod divisor."""
        result = list(dividend)
        divisor_lead = divisor[-1]
        divisor_inv = self._gf_inv(divisor_lead)
        for i in range(len(result) - len(divisor), -1, -1):
            if result[i + len(divisor) - 1] != 0:
                coef = self._gf_mul(result[i + len(divisor) - 1], divisor_inv)
                for j in range(len(divisor)):
                    result[i + j] = self._gf_add(result[i + j], self._gf_mul(divisor[j], coef))
        return result[:len(divisor) - 1]

    def _gf_eval(self, poly: List[int], x: int) -> int:
        """Evaluate polynomial at point x in GF(256)."""
        result = 0
        power = 1
        for coef in poly:
            result = self._gf_add(result, self._gf_mul(coef, power))
            power = self._gf_mul(power, x)
        return result

    def decode(self, received: bytes) -> bytes:
        """Decode received word using Berlekamp-Massey algorithm.

        Corrects up to t = (n-k)/2 symbol errors.
        """
        if len(received) != self.n:
            raise ValueError(f"Received must be {self.n} bytes")

        received = list(received)

        # Step 1: Compute syndromes S_0, S_1, ..., S_{2t-1}
        # S_i = sum(R_j * alpha^(i*j)) for j=0..n-1
        syndromes = []
        for i in range(2 * self.t):
            s = 0
            alpha_i = self._gf_alog[i % 255]
            power = 1  # alpha_i^0 = 1
            for j in range(self.n):
                s = self._gf_add(s, self._gf_mul(received[j], power))
                power = self._gf_mul(power, alpha_i)
            syndromes.append(s)

        # If all syndromes are zero, no errors
        if all(s == 0 for s in syndromes):
            return bytes(received[:self.k])

        # Step 2: Berlekamp-Massey for error locator polynomial
        # Lambda(x) = 1 + Lambda_1*x + ... + Lambda_L*x^L
        # where roots are at alpha^{-error_positions}
        L = 0
        n_poly = [1] + [0] * (2 * self.t)  # Lambda(x)
        b_poly = [1] + [0] * (2 * self.t)  # B(x) - auxiliary
        m = 1  # number of elements processed

        for r in range(2 * self.t):
            # Discrepancy: delta = S_r + sum(Lambda_i * S_{r-i}) for i=1..L
            delta = syndromes[r]
            for i in range(1, L + 1):
                delta = self._gf_add(delta, self._gf_mul(n_poly[i], syndromes[r - i]))

            if delta == 0:
                m += 1
            else:
                # Update Lambda
                temp = list(n_poly)
                # n_poly = n_poly + delta * x^m * b_poly
                for i in range(2 * self.t - m + 1):
                    if b_poly[i] != 0:
                        n_poly[i + m] = self._gf_add(n_poly[i + m], self._gf_mul(delta, b_poly[i]))

                if 2 * L <= r:
                    L = r + 1 - L
                    b_poly = [self._gf_mul(self._gf_inv(delta), c) for c in temp]
                    m = 1
                else:
                    m += 1

        # Step 3: Chien search - find error positions
        error_positions = []  # positions in received word
        for j in range(self.n):
            # Evaluate Lambda(alpha^{-j}) = Lambda(alpha^(255-j))
            alpha_inv_j = self._gf_alog[(255 - j) % 255]
            val = self._gf_eval(n_poly[:L + 1], alpha_inv_j)
            if val == 0:
                error_positions.append(j)

        # Step 4: Forney algorithm - compute error values
        # Omega(x) = Lambda(x) * S(x) mod x^(2t)
        # where S(x) = S_0 + S_1*x + ... + S_{2t-1}*x^{2t-1}
        omega = [0] * (2 * self.t)
        for i in range(2 * self.t):
            for j in range(min(i + 1, L + 1)):
                omega[i] = self._gf_add(omega[i], self._gf_mul(n_poly[j], syndromes[i - j]))

        # Error values: e_j = Omega(alpha^{-j}) / (alpha^{-j} * Lambda'(alpha^{-j}))
        for pos in error_positions:
            alpha_inv_j = self._gf_alog[(255 - pos) % 255]
            omega_val = self._gf_eval(omega, alpha_inv_j)

            # Lambda'(x) = sum(i * Lambda_i * x^{i-1})
            lambda_deriv = 0
            for i in range(1, L + 1):
                # In GF(2^8): derivative of x^i is i*x^{i-1}, but i is integer
                # For characteristic 2: derivative of x^(2k) = 0, x^(2k+1) = x^(2k)
                # Simplified: just use i mod 2 (only odd powers contribute)
                if i % 2 == 1:
                    lambda_deriv = self._gf_add(lambda_deriv, self._gf_mul(n_poly[i], self._gf_pow(alpha_inv_j, i - 1)))

            denom = self._gf_mul(alpha_inv_j, lambda_deriv)
            if denom != 0:
                error_val = self._gf_mul(omega_val, self._gf_inv(denom))
                received[pos] = self._gf_add(received[pos], error_val)

        return bytes(received[:self.k])

    def _gf_pow(self, a: int, e: int) -> int:
        """Compute a^e in GF(256)."""
        if a == 0:
            return 0
        return self._gf_alog[(self._gf_log[a] * e) % 255]


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
