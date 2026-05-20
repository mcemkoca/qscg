"""QC-MDPC codes and iterative bit-flipping decoder for HQC.

Quasi-Cyclic Moderate Density Parity Check codes.
Used in HQC for error correction during decapsulation.
"""

from typing import List, Tuple
from .gf2poly import GF2Poly
import random


class QCMDPC:
    """Quasi-Cyclic MDPC code.

    A QC-MDPC code is defined by a parity-check matrix H
    composed of circulant blocks. Each block is a cyclic shift
    of a sparse polynomial.
    """

    def __init__(self, n: int, w: int, n_blocks: int = 2):
        """Initialize QC-MDPC code.

        Args:
            n: Code length (circulant block size)
            w: Row weight of each circulant block (Hamming weight)
            n_blocks: Number of circulant blocks (typically 2 for HQC)
        """
        self.n = n
        self.w = w
        self.n_blocks = n_blocks
        self.block_size = n
        self.code_length = n * n_blocks

    def generate_parity_block(self, seed: bytes = None) -> GF2Poly:
        """Generate a random sparse circulant block."""
        if seed:
            random.seed(seed)
        return GF2Poly.random_sparse(self.n, self.w)

    def encode(self, message: GF2Poly, generator: GF2Poly) -> GF2Poly:
        """Encode message using generator polynomial.

        For QC-MDPC: codeword = [message | message * g]
        where g is the generator polynomial.
        """
        # Simplified: just return message concatenated with parity
        # Real QC-MDPC uses systematic encoding
        from .gf2poly import gf2_mul
        parity = gf2_mul(message, generator, self.n)
        return message ^ parity  # Simplified

    def syndrome(self, received: GF2Poly, h_blocks: List[GF2Poly]) -> GF2Poly:
        """Compute syndrome: s = received * H^T.

        For QC-MDPC with 2 blocks: s = r0*h0 + r1*h1
        """
        from .gf2poly import gf2_mul_sparse
        # Split received into blocks
        s = GF2Poly(self.n)
        for i, h in enumerate(h_blocks):
            # Extract block i from received
            block = GF2Poly(self.n)
            for j in range(self.n):
                block.set_bit(j, received.bit(i * self.n + j))
            s = s ^ gf2_mul_sparse(block, h, self.n)
        return s


class BitFlippingDecoder:
    """Iterative bit-flipping decoder for QC-MDPC codes.

    Based on Gallager's bit-flipping algorithm adapted for MDPC codes.
    """

    def __init__(self, max_iterations: int = 10, threshold_factor: float = 0.5):
        self.max_iterations = max_iterations
        self.threshold_factor = threshold_factor

    def decode(self, syndrome: GF2Poly, h_blocks: List[GF2Poly],
               received: GF2Poly) -> Tuple[GF2Poly, bool]:
        """Decode received word using bit-flipping.

        Returns:
            (decoded_word, success)
        """
        n = len(h_blocks[0].n) if hasattr(h_blocks[0], 'n') else h_blocks[0].n
        # Current estimate
        estimate = GF2Poly(received.n)
        for i in range(received.n):
            estimate.set_bit(i, received.bit(i))

        for iteration in range(self.max_iterations):
            # Compute syndrome of current estimate
            s = self._compute_syndrome(estimate, h_blocks)

            # Check if syndrome is zero
            if s.hamming_weight() == 0:
                return estimate, True

            # Compute bit flip scores
            scores = [0] * estimate.n
            for bit_pos in range(estimate.n):
                # Count how many unsatisfied parity checks involve this bit
                score = self._bit_score(bit_pos, s, h_blocks, n)
                scores[bit_pos] = score

            # Determine threshold (dynamic)
            max_score = max(scores) if scores else 0
            threshold = max_score * self.threshold_factor

            # Flip bits with score >= threshold
            flipped = False
            for i in range(estimate.n):
                if scores[i] >= threshold and scores[i] > 0:
                    estimate.set_bit(i, estimate.bit(i) ^ 1)
                    flipped = True

            if not flipped:
                break  # No more improvements

        # Final check
        s = self._compute_syndrome(estimate, h_blocks)
        success = s.hamming_weight() == 0
        return estimate, success

    def _compute_syndrome(self, received: GF2Poly, h_blocks: List[GF2Poly]) -> GF2Poly:
        """Compute syndrome s = received * H^T."""
        from .gf2poly import gf2_mul_sparse
        n = h_blocks[0].n
        s = GF2Poly(n)
        for i, h in enumerate(h_blocks):
            block = GF2Poly(n)
            for j in range(n):
                if i * n + j < received.n:
                    block.set_bit(j, received.bit(i * n + j))
            s = s ^ gf2_mul_sparse(block, h, n)
        return s

    def _bit_score(self, bit_pos: int, syndrome: GF2Poly,
                   h_blocks: List[GF2Poly], n: int) -> int:
        """Compute bit flip score: number of unsatisfied checks involving this bit."""
        # Simplified: count syndrome bits that would be affected
        score = 0
        block_idx = bit_pos // n
        block_pos = bit_pos % n
        if block_idx < len(h_blocks):
            h = h_blocks[block_idx]
            # For each set bit in h shifted by block_pos
            for i in range(n):
                if h.bit((i - block_pos) % n):
                    score += syndrome.bit(i)
        return score


def generate_hqc_parity_checks(n: int, w: int) -> Tuple[GF2Poly, GF2Poly]:
    """Generate HQC parity-check polynomials h0, h1.

    HQC uses two circulant blocks: H = [h0 | h1]
    where h0 and h1 are sparse polynomials with weight w.
    """
    h0 = GF2Poly.random_sparse(n, w)
    h1 = GF2Poly.random_sparse(n, w)
    return h0, h1
