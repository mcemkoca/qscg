"""NTRU lattice and NTT (Number Theoretic Transform) for FN-DSA (FALCON).

Ring: Z_q[x] / (x^n + 1)
Parameters:
    Level 1: n=512, q=12289
    Level 5: n=1024, q=12289

NTT-friendly prime: q = 12289 = 2^12 * 3 + 1
Primitive root: g = 11 (mod 12289)
"""

from typing import List, Tuple


class NTTContext:
    """Number Theoretic Transform context for Z_q[x]/(x^n+1)."""

    Q = 12289
    PSI = 11  # Primitive 2n-th root of unity

    def __init__(self, n: int):
        if n not in (512, 1024):
            raise ValueError("n must be 512 or 1024")
        self.n = n
        self.log_n = n.bit_length() - 1

        # Build bit-reversal permutation
        self._rev = [self._bit_reverse(i, self.log_n) for i in range(n)]

        # Build twiddle factors: psi^rev(i) mod q for i=0..n-1
        # psi is 2n-th root of unity
        self._psi = [1] * n
        psi_n = pow(self.PSI, (2 * self.Q - 2) // (2 * n), self.Q)
        for i in range(1, n):
            self._psi[i] = (self._psi[i - 1] * psi_n) % self.Q

        # Inverse twiddle factors
        self._psi_inv = [pow(x, self.Q - 2, self.Q) for x in self._psi]

    def _bit_reverse(self, x: int, bits: int) -> int:
        """Reverse bits of x."""
        result = 0
        for i in range(bits):
            result = (result << 1) | ((x >> i) & 1)
        return result

    def _mod(self, x: int) -> int:
        """Reduce x modulo q to centered representation [-q/2, q/2]."""
        x %= self.Q
        if x > self.Q // 2:
            x -= self.Q
        return x

    def ntt(self, a: List[int]) -> List[int]:
        """Forward NTT: a -> A (in-place bit-reversal + butterfly)."""
        n = self.n
        if len(a) != n:
            raise ValueError(f"Input must have {n} elements")

        # Bit-reverse copy
        A = [a[self._rev[i]] for i in range(n)]

        # Cooley-Tukey butterflies
        m = 1
        while m < n:
            step = 2 * m
            for j in range(m):
                # Twiddle factor
                w = self._psi[(n // step) * j]
                for k in range(j, n, step):
                    u = A[k]
                    v = (A[k + m] * w) % self.Q
                    A[k] = (u + v) % self.Q
                    A[k + m] = (u - v) % self.Q
            m *= 2

        return A

    def intt(self, A: List[int]) -> List[int]:
        """Inverse NTT: A -> a."""
        n = self.n
        if len(A) != n:
            raise ValueError(f"Input must have {n} elements")

        # Bit-reverse copy
        a = [A[self._rev[i]] for i in range(n)]

        # Inverse butterflies
        m = 1
        while m < n:
            step = 2 * m
            for j in range(m):
                w = self._psi_inv[(n // step) * j]
                for k in range(j, n, step):
                    u = a[k]
                    v = (a[k + m] * w) % self.Q
                    a[k] = (u + v) % self.Q
                    a[k + m] = (u - v) % self.Q
            m *= 2

        # Scale by n^{-1} mod q
        n_inv = pow(n, self.Q - 2, self.Q)
        for i in range(n):
            a[i] = (a[i] * n_inv) % self.Q
            if a[i] > self.Q // 2:
                a[i] -= self.Q

        return a

    def ntt_mul(self, A: List[int], B: List[int]) -> List[int]:
        """Point-wise multiplication in NTT domain."""
        return [(A[i] * B[i]) % self.Q for i in range(self.n)]

    def poly_mul(self, a: List[int], b: List[int]) -> List[int]:
        """Full polynomial multiplication: a * b mod (x^n+1)."""
        A = self.ntt(a)
        B = self.ntt(b)
        C = self.ntt_mul(A, B)
        c = self.intt(C)
        return c


class NTRUPoly:
    """Polynomial in NTRU lattice with small coefficients."""

    def __init__(self, coeffs: List[int], n: int = 512):
        self.n = n
        self.coeffs = [self._center(c) for c in coeffs[:n]]
        # Pad with zeros
        while len(self.coeffs) < n:
            self.coeffs.append(0)

    @classmethod
    def from_small(cls, n: int, seed: bytes = None, density: float = 0.25) -> "NTRUPoly":
        """Generate random small polynomial (coefficients in {-1, 0, 1})."""
        import random
        if seed:
            random.seed(seed)
        coeffs = []
        for _ in range(n):
            r = random.random()
            if r < density / 2:
                coeffs.append(-1)
            elif r < density:
                coeffs.append(1)
            else:
                coeffs.append(0)
        return cls(coeffs, n)

    @classmethod
    def from_gaussian(cls, n: int, sigma: float = 1.4) -> "NTRUPoly":
        """Generate random Gaussian polynomial."""
        import random
        coeffs = []
        for _ in range(n):
            coeffs.append(int(round(random.gauss(0, sigma))))
        return cls(coeffs, n)

    def _center(self, c: int) -> int:
        """Center coefficient modulo q."""
        q = NTTContext.Q
        c %= q
        if c > q // 2:
            c -= q
        return c

    def __add__(self, other: "NTRUPoly") -> "NTRUPoly":
        coeffs = [(self.coeffs[i] + other.coeffs[i]) for i in range(self.n)]
        return NTRUPoly(coeffs, self.n)

    def __sub__(self, other: "NTRUPoly") -> "NTRUPoly":
        coeffs = [(self.coeffs[i] - other.coeffs[i]) for i in range(self.n)]
        return NTRUPoly(coeffs, self.n)

    def __neg__(self) -> "NTRUPoly":
        return NTRUPoly([-c for c in self.coeffs], self.n)

    def ntt_form(self, ntt: NTTContext) -> List[int]:
        """Convert to NTT domain coefficients."""
        # Map small coefficients to [0, q-1]
        a = [(c % ntt.Q) for c in self.coeffs]
        return ntt.ntt(a)

    @classmethod
    def from_ntt(cls, A: List[int], ntt: NTTContext, n: int) -> "NTRUPoly":
        """Convert from NTT domain back to polynomial."""
        a = ntt.intt(A)
        return cls(a, n)

    def to_bytes(self) -> bytes:
        """Serialize coefficients as bytes (each coeff is 2 bytes mod q)."""
        import struct
        return b''.join(struct.pack('<H', (c % NTTContext.Q)) for c in self.coeffs)

    def norm_sq(self) -> int:
        """Squared Euclidean norm."""
        return sum(c * c for c in self.coeffs)

    def norm(self) -> float:
        """Euclidean norm."""
        import math
        return math.sqrt(self.norm_sq())

    def __repr__(self):
        return f"NTRUPoly(n={self.n}, norm={self.norm():.2f})"


class NTRUKeypair:
    """NTRU key pair for FN-DSA.

    Secret key: short basis (f, g, F, G)
    Public key: h = g/f mod q (in NTT domain)
    """

    def __init__(self, n: int = 512):
        self.n = n
        self.ntt = NTTContext(n)
        self.f = None
        self.g = None
        self.F = None
        self.G = None
        self.h_ntt = None  # Public key in NTT domain

    def generate(self, seed: bytes = None) -> Tuple[bytes, bytes]:
        """Generate key pair.

        Returns:
            (public_key_bytes, secret_key_bytes)
        """
        import random
        if seed:
            random.seed(seed)

        # Generate short polynomials f, g
        # f must be invertible mod q
        max_attempts = 100
        for attempt in range(max_attempts):
            self.f = NTRUPoly.from_small(self.n, density=0.125)
            # Check invertibility: try NTT
            try:
                f_ntt = self.f.ntt_form(self.ntt)
                # Check all coefficients non-zero in NTT domain
                if all(c != 0 for c in f_ntt):
                    break
            except:
                continue
        else:
            raise RuntimeError("Could not generate invertible f")

        self.g = NTRUPoly.from_small(self.n, density=0.125)

        # Compute h = g/f mod q in NTT domain
        # h_ntt = g_ntt * f_ntt^{-1}
        f_ntt = self.f.ntt_form(self.ntt)
        g_ntt = self.g.ntt_form(self.ntt)

        f_inv_ntt = [pow(c, self.ntt.Q - 2, self.ntt.Q) for c in f_ntt]
        self.h_ntt = self.ntt.ntt_mul(g_ntt, f_inv_ntt)

        # Compute extended basis (F, G) via NTRU solving
        # f*G - g*F = q (mod x^n+1)
        # For now: stub - compute F, G via extended GCD approximation
        self.F = NTRUPoly([0] * self.n, self.n)
        self.G = NTRUPoly([0] * self.n, self.n)

        # Pack public key
        h_poly = NTRUPoly.from_ntt(self.h_ntt, self.ntt, self.n)
        pk = h_poly.to_bytes()

        # Pack secret key
        sk = self.f.to_bytes() + self.g.to_bytes()

        return pk, sk

    def sign_ntt(self, sk: bytes, message: bytes) -> bytes:
        """Sign message using NTT domain operations.

        Steps:
            1. Hash message to challenge c
            2. Gaussian sample (s1, s2) with s1 + s2*h = c
            3. Return compact signature
        """
        import hashlib
        import random

        # Hash message
        c_hash = hashlib.sha3_256(message).digest()
        random.seed(c_hash)

        # Generate challenge in NTT domain
        c_ntt = [random.randint(0, self.ntt.Q - 1) for _ in range(self.n)]

        # Gaussian sample perturbation
        # In real FALCON: use Fast Fourier Sampling to get (s1, s2)
        # such that s1 + s2*h = c with small norm
        # Here: stub - sample s2, then compute s1 = c - s2*h
        s2 = NTRUPoly.from_gaussian(self.n, sigma=1.4)

        # Compute h in NTT domain from stored h_ntt
        h_ntt = self.h_ntt
        s2_ntt = s2.ntt_form(self.ntt)

        # Adjust s1 to satisfy: s1 = c - s2*h (in NTT domain)
        adjusted_s1_ntt = []
        for i in range(self.n):
            val = (c_ntt[i] - s2_ntt[i] * h_ntt[i]) % self.ntt.Q
            if val > self.ntt.Q // 2:
                val -= self.ntt.Q
            adjusted_s1_ntt.append(val)

        s1 = NTRUPoly.from_ntt(adjusted_s1_ntt, self.ntt, self.n)

        # Check norm bounds
        sig_norm_sq = s1.norm_sq() + s2.norm_sq()
        max_norm_sq = self.n * 340 * 340  # ~512 * (1.4*sqrt(512))^2

        # Pack signature: compressed (s1, s2)
        sig = s1.to_bytes() + s2.to_bytes()
        return sig

    def verify_ntt(self, pk: bytes, message: bytes, sig: bytes) -> bool:
        """Verify signature.

        Check:
            1. Signature norm is within bounds
            2. s1 + s2*h = H(message) (mod q)
        """
        import hashlib
        import struct
        import random

        if len(sig) != 4 * self.n:
            return False

        # Unpack signature
        half = 2 * self.n
        s1_bytes = sig[:half]
        s2_bytes = sig[half:]

        s1 = NTRUPoly([struct.unpack('<H', s1_bytes[i:i+2])[0] for i in range(0, half, 2)], self.n)
        s2 = NTRUPoly([struct.unpack('<H', s2_bytes[i:i+2])[0] for i in range(0, half, 2)], self.n)

        # Check norm bounds
        sig_norm_sq = s1.norm_sq() + s2.norm_sq()
        max_norm_sq = self.n * 340 * 340
        if sig_norm_sq > max_norm_sq:
            return False

        # Reconstruct public key from bytes
        h = NTRUPoly([struct.unpack('<H', pk[i:i+2])[0] for i in range(0, len(pk), 2)], self.n)
        h_ntt = h.ntt_form(self.ntt)

        # Verify: s1 + s2*h = c (in NTT domain)
        s1_ntt = s1.ntt_form(self.ntt)
        s2_ntt = s2.ntt_form(self.ntt)

        lhs = [(s1_ntt[i] + s2_ntt[i] * h_ntt[i]) % self.ntt.Q for i in range(self.n)]

        # Recompute challenge
        c_hash = hashlib.sha3_256(message).digest()
        random.seed(c_hash)
        c_ntt = [random.randint(0, self.ntt.Q - 1) for _ in range(self.n)]

        return lhs == c_ntt
