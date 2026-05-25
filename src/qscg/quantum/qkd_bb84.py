"""BB84 Quantum Key Distribution Protocol Simulation.

Implements the BB84 protocol for secure key exchange using quantum
mechanical principles:

  * **Qubit preparation**: Alice prepares qubits in random bases (Z/X)
  * **Quantum channel**: Qubits are transmitted to Bob
  * **Measurement**: Bob measures qubits in random bases
  * **Basis reconciliation**: Alice and Bob compare bases over a
    public classical channel and keep only matching results
  * **Error estimation**: A sample of the sifted key is sacrificed to
    estimate the Quantum Bit Error Rate (QBER)
  * **Privacy amplification**: The remaining key material is hashed to
    produce a shorter, information-theoretically secure key

The BB84 protocol, proposed by Bennett and Brassard in 1984, is the
first and most widely studied quantum key distribution protocol. Its
security is guaranteed by the no-cloning theorem of quantum mechanics:
any eavesdropping attempt necessarily introduces detectable errors.

Example::

    from qkd_bb84 import bb84_key_exchange

    result = bb84_key_exchange(n_bits=1024, eavesdrop=False)
    print(f"Keys match: {result['keys_match']}")
    print(f"QBER: {result['qber']:.4f}")

Attributes:
    __version__: Module version string.
    DEFAULT_N_BITS: Default number of qubits to exchange (256).
    DEFAULT_SAMPLE_SIZE: Default QBER sample size (20 bits).
    Z_BASIS: Computational basis (0).
    X_BASIS: Hadamard/diagonal basis (1).

References:
    - Bennett, C. H. & Brassard, G. (1984). "Quantum cryptography:
      Public key distribution and coin tossing." Proceedings of IEEE
      International Conference on Computers, Systems, and Signal
      Processing, 175-179.
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

# ---------------------------------------------------------------------------
# QRNG import (with graceful fallback)
# ---------------------------------------------------------------------------

try:
    from .qrng import QuantumRNG
except ImportError:

    class QuantumRNG:  # type: ignore[no-redef]
        """Stub Quantum RNG for standalone imports."""

        def __init__(self, n_qubits: int = 8) -> None:
            """Initialize the quantum RNG stub.

            Args:
                n_qubits: Number of simulated qubits (unused in stub).
            """
            self.n_qubits = n_qubits

        def random_bits(self, n: int) -> List[int]:
            """Generate *n* cryptographically secure random bits.

            Args:
                n: Number of random bits to generate.

            Returns:
                List of integers (0 or 1) of length *n*.
            """
            num_bytes = (n + 7) // 8
            raw = secrets.token_bytes(num_bytes)
            bits: List[int] = []
            for byte in raw:
                for i in range(8):
                    if len(bits) < n:
                        bits.append((byte >> i) & 1)
            return bits

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
DEFAULT_N_BITS = 256
DEFAULT_SAMPLE_SIZE = 20
Z_BASIS = 0
X_BASIS = 1

logger = logging.getLogger(__name__)


class Basis(IntEnum):
    """Measurement basis enumeration for BB84.

    Attributes:
        Z: Computational basis (rectilinear), encodes |0> and |1>.
        X: Hadamard basis (diagonal), encodes |+> and |->.
    """

    Z = 0
    X = 1


class QubitState:
    """Represents a single qubit in the BB84 protocol.

    A qubit is described by its computational basis state (bit value)
    and the basis in which it was prepared.  In the X basis, the qubit
    exists in a superposition until measured.

    Attributes:
        bit: The classical bit value (0 or 1).
        basis: The preparation basis (Z_BASIS or X_BASIS).
    """

    __slots__ = ("bit", "basis")

    def __init__(self, bit: int, basis: int) -> None:
        """Initialize a qubit state.

        Args:
            bit: Classical bit value (0 or 1).
            basis: Preparation basis (Z_BASIS or X_BASIS).
        """
        if bit not in (0, 1):
            raise ValueError(f"Bit must be 0 or 1, got {bit}")
        if basis not in (Z_BASIS, X_BASIS):
            raise ValueError(f"Basis must be 0 (Z) or 1 (X), got {basis}")
        self.bit: int = bit
        self.basis: int = basis

    def measure(self, measurement_basis: int) -> int:
        """Measure the qubit in the given basis.

        If the measurement basis matches the preparation basis, the
        result is deterministic.  If the bases differ, the result is
        completely random (50/50), which is the fundamental quantum
        mechanical property exploited by BB84.

        Args:
            measurement_basis: Basis to measure in (Z_BASIS or X_BASIS).

        Returns:
            Measurement result (0 or 1).
        """
        if measurement_basis == self.basis:
            # Same basis → deterministic outcome
            return self.bit
        # Different basis → random outcome (superposition collapse)
        return secrets.randbelow(2)

    def __repr__(self) -> str:
        """Return a string representation of the qubit state."""
        basis_name = "Z" if self.basis == Z_BASIS else "X"
        return f"QubitState(bit={self.bit}, basis={basis_name})"


@dataclass
class BB84Result:
    """Complete result of a BB84 key exchange session.

    Attributes:
        alice_key: Final shared key derived by Alice.
        bob_key: Final shared key derived by Bob.
        keys_match: Whether the final keys are identical.
        qber: Estimated quantum bit error rate.
        efficiency: Key generation efficiency (sifted / raw).
        raw_bits: Total number of qubits exchanged.
        sifted_bits: Number of bits remaining after basis reconciliation.
        eavesdropper_detected: True if QBER exceeds the threshold.
        preparation_time_ms: Time spent in qubit preparation (ms).
        exchange_time_ms: Time spent in key exchange (ms).
    """

    alice_key: bytes
    bob_key: bytes
    keys_match: bool
    qber: float
    efficiency: float
    raw_bits: int
    sifted_bits: int
    eavesdropper_detected: bool
    preparation_time_ms: float = 0.0
    exchange_time_ms: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result to a JSON-serializable dictionary.

        Returns:
            Dictionary representation of the exchange result.
        """
        return {
            "alice_key_hex": self.alice_key.hex(),
            "bob_key_hex": self.bob_key.hex(),
            "keys_match": self.keys_match,
            "qber": round(self.qber, 6),
            "efficiency": round(self.efficiency, 6),
            "raw_bits": self.raw_bits,
            "sifted_bits": self.sifted_bits,
            "eavesdropper_detected": self.eavesdropper_detected,
            "preparation_time_ms": round(self.preparation_time_ms, 3),
            "exchange_time_ms": round(self.exchange_time_ms, 3),
        }


def bb84_generate_qubits(
    n_bits: int = DEFAULT_N_BITS,
) -> Tuple[List[int], List[int], List[QubitState]]:
    """Alice: Generate random bits and bases, prepare qubits.

    Alice randomly selects bits and bases for each qubit.  In the Z
    (computational) basis, a bit is encoded as |0> or |1>.  In the X
    (Hadamard) basis, a bit is encoded as |+> or |->, which are
    superpositions of |0> and |1>.

    Args:
        n_bits: Number of qubits to prepare.

    Returns:
        Tuple of (alice_bits, alice_bases, qubit_states):
            - alice_bits: List of random bits [0, 1] of length *n_bits*.
            - alice_bases: List of random bases [0=Z, 1=X] of length *n_bits*.
            - qubit_states: List of :class:`QubitState` objects representing
              the prepared quantum states.
    """
    qrng = QuantumRNG(n_qubits=8)

    alice_bits = qrng.random_bits(n_bits)
    alice_bases = qrng.random_bits(n_bits)  # 0 = Z basis, 1 = X basis

    # Prepare qubit states
    qubit_states: List[QubitState] = []
    for bit, basis in zip(alice_bits, alice_bases):
        qubit_states.append(QubitState(bit, basis))

    logger.debug(
        "Alice prepared %d qubits (Z basis: %d, X basis: %d)",
        n_bits,
        sum(1 for b in alice_bases if b == Z_BASIS),
        sum(1 for b in alice_bases if b == X_BASIS),
    )

    return alice_bits, alice_bases, qubit_states


def bb84_measure_qubits(
    qubit_states: List[QubitState], bob_bases: List[int]
) -> List[int]:
    """Bob: Measure received qubits in random bases.

    Bob chooses a random basis (Z or X) for each incoming qubit and
    measures it.  When Bob's measurement basis matches Alice's
    preparation basis, the result is deterministic and reveals Alice's
    original bit.  When the bases differ, the result is random.

    Args:
        qubit_states: List of :class:`QubitState` received from Alice.
        bob_bases: List of Bob's random measurement bases [0=Z, 1=X].

    Returns:
        List of Bob's measurement results (0 or 1).

    Raises:
        ValueError: If the lengths of *qubit_states* and *bob_bases* differ.
    """
    if len(qubit_states) != len(bob_bases):
        raise ValueError(
            f"Mismatched lengths: {len(qubit_states)} qubits vs "
            f"{len(bob_bases)} bases"
        )

    bob_bits: List[int] = []
    for qubit, basis in zip(qubit_states, bob_bases):
        result = qubit.measure(basis)
        bob_bits.append(result)

    logger.debug(
        "Bob measured %d qubits (Z basis: %d, X basis: %d)",
        len(qubit_states),
        sum(1 for b in bob_bases if b == Z_BASIS),
        sum(1 for b in bob_bases if b == X_BASIS),
    )

    return bob_bits


def bb84_eavesdrop(
    qubit_states: List[QubitState],
    intercept_prob: float = 0.5,
) -> List[QubitState]:
    """Simulate an eavesdropper (Eve) intercepting the quantum channel.

    Eve randomly selects a basis for each qubit, measures it, and
    re-prepares a new qubit with the measured result.  This process
    inevitably introduces errors when Eve's basis differs from Alice's,
    which is the foundation of BB84's security proof.

    Args:
        qubit_states: Original qubits from Alice.
        intercept_prob: Probability that Eve intercepts each qubit (0.0-1.0).

    Returns:
        List of (possibly disturbed) qubit states after Eve's interception.
    """
    disturbed: List[QubitState] = []
    intercepted_count = 0

    for qubit in qubit_states:
        if secrets.randbelow(1000) < int(intercept_prob * 1000):
            # Eve intercepts this qubit
            intercepted_count += 1
            eve_basis = secrets.randbelow(2)
            measured_bit = qubit.measure(eve_basis)
            # Eve re-prepares and sends on
            disturbed.append(QubitState(measured_bit, eve_basis))
        else:
            # Eve does not intercept — qubit passes undisturbed
            disturbed.append(qubit)

    logger.info(
        "Eve intercepted %d/%d qubits (%.1f%%)",
        intercepted_count,
        len(qubit_states),
        100.0 * intercepted_count / len(qubit_states) if qubit_states else 0.0,
    )

    return disturbed


def bb84_reconcile(
    alice_bits: List[int],
    alice_bases: List[int],
    bob_bits: List[int],
    bob_bases: List[int],
) -> Tuple[List[int], List[int]]:
    """Basis reconciliation: keep only bits where bases match.

    After Bob measures the qubits, Alice and Bob publicly compare their
    basis choices (but not the bit values).  They keep only the bits
    where they used the same basis.  On average, 50% of the bits are
    discarded, yielding the "sifted key."

    Args:
        alice_bits: Alice's original random bits.
        alice_bases: Alice's preparation bases.
        bob_bits: Bob's measurement results.
        bob_bases: Bob's measurement bases.

    Returns:
        Tuple of (alice_sifted, bob_sifted): The sifted keys for Alice
        and Bob, containing only bits where their bases matched.

    Raises:
        ValueError: If input lists have mismatched lengths.
    """
    if not (
        len(alice_bits) == len(alice_bases) == len(bob_bits) == len(bob_bases)
    ):
        raise ValueError("All input lists must have the same length")

    alice_sifted: List[int] = []
    bob_sifted: List[int] = []

    for a_bit, a_basis, b_bit, b_basis in zip(
        alice_bits, alice_bases, bob_bits, bob_bases
    ):
        if a_basis == b_basis:
            alice_sifted.append(a_bit)
            bob_sifted.append(b_bit)

    logger.debug(
        "Basis reconciliation: %d -> %d bits (%.1f%% retained)",
        len(alice_bits),
        len(alice_sifted),
        100.0 * len(alice_sifted) / len(alice_bits) if alice_bits else 0.0,
    )

    return alice_sifted, bob_sifted


def bb84_error_check(
    alice_sifted: List[int],
    bob_sifted: List[int],
    sample_size: int = DEFAULT_SAMPLE_SIZE,
) -> Tuple[float, List[int], List[int]]:
    """Estimate the quantum bit error rate (QBER) via random sampling.

    A random subset of the sifted key is sacrificed: Alice and Bob
    publicly compare these bits to estimate the error rate.  If the
    QBER exceeds a threshold (typically ~11% for BB84), an
    eavesdropper is likely present.

    Args:
        alice_sifted: Alice's sifted key bits.
        bob_sifted: Bob's sifted key bits.
        sample_size: Number of bits to use for QBER estimation.  If the
            sifted key is shorter than twice this value, the sample size
            is automatically reduced.

    Returns:
        Tuple of (qber, alice_remaining, bob_remaining):
            - qber: Quantum bit error rate (0.0 to 1.0).
            - alice_remaining: Alice's key bits after removing the sample.
            - bob_remaining: Bob's key bits after removing the sample.

    Raises:
        ValueError: If the sifted keys are empty.
    """
    if not alice_sifted or not bob_sifted:
        raise ValueError("Sifted keys cannot be empty")

    n = len(alice_sifted)
    actual_sample = min(sample_size, n // 2)
    if actual_sample == 0:
        actual_sample = max(1, n // 4)

    # Use the first *actual_sample* bits for error estimation
    errors = sum(
        1
        for a, b in zip(alice_sifted[:actual_sample], bob_sifted[:actual_sample])
        if a != b
    )
    qber = errors / actual_sample if actual_sample > 0 else 0.0

    # Remaining bits after removing the sample
    alice_remaining = alice_sifted[actual_sample:]
    bob_remaining = bob_sifted[actual_sample:]

    logger.info(
        "QBER estimation: %d errors in %d samples = %.4f (%s)",
        errors,
        actual_sample,
        qber,
        "EAVESDROPPER DETECTED" if qber > 0.11 else "acceptable",
    )

    return qber, alice_remaining, bob_remaining


def bb84_privacy_amplification(
    alice_remaining: List[int],
    bob_remaining: List[int],
    target_key_len: int = 32,
) -> Tuple[bytes, bytes]:
    """Privacy amplification: distill a shorter, secure key.

    After error estimation, the remaining key material may contain
    partial information known to an eavesdropper.  Privacy amplification
    uses a universal hash function (here, SHA3-256) to compress the key
    to a shorter length, exponentially reducing the eavesdropper's
    information.

    Args:
        alice_remaining: Alice's key bits after error estimation.
        bob_remaining: Bob's key bits after error estimation.
        target_key_len: Desired output key length in bytes (default 32).

    Returns:
        Tuple of (alice_key, bob_key): The final shared keys.
    """
    alice_bytes = bytes(
        int("".join(map(str, alice_remaining[i : i + 8])), 2)
        for i in range(0, len(alice_remaining), 8)
    ) if alice_remaining else b""

    bob_bytes = bytes(
        int("".join(map(str, bob_remaining[i : i + 8])), 2)
        for i in range(0, len(bob_remaining), 8)
    ) if bob_remaining else b""

    alice_key = hashlib.sha3_256(alice_bytes).digest()[:target_key_len]
    bob_key = hashlib.sha3_256(bob_bytes).digest()[:target_key_len]

    logger.debug(
        "Privacy amplification: %d bits -> %d bytes",
        len(alice_remaining),
        target_key_len,
    )

    return alice_key, bob_key


def bb84_key_exchange(
    n_bits: int = DEFAULT_N_BITS,
    sample_size: int = DEFAULT_SAMPLE_SIZE,
    eavesdrop: bool = False,
    eavesdrop_prob: float = 0.5,
    target_key_len: int = 32,
) -> BB84Result:
    """Execute the complete BB84 quantum key exchange protocol.

    Performs all phases of the BB84 protocol: qubit preparation,
    transmission (with optional eavesdropping simulation), measurement,
    basis reconciliation, error estimation, and privacy amplification.

    Args:
        n_bits: Number of qubits to exchange.  More qubits yield a
            longer sifted key but increase protocol overhead.
        sample_size: Number of bits to sacrifice for QBER estimation.
        eavesdrop: If True, simulate an eavesdropper intercepting
            qubits in the quantum channel.
        eavesdrop_prob: Probability (0.0-1.0) that Eve intercepts each qubit.
        target_key_len: Desired final key length in bytes.

    Returns:
        :class:`BB84Result` containing the final keys, QBER, efficiency,
        and eavesdropper detection status.
    """
    t0 = time.perf_counter()

    # ------------------------------------------------------------------
    # Phase 1: Alice prepares qubits
    # ------------------------------------------------------------------
    alice_bits, alice_bases, qubit_states = bb84_generate_qubits(n_bits)
    t_prep = time.perf_counter()

    # ------------------------------------------------------------------
    # Phase 2: Quantum channel (with optional eavesdropping)
    # ------------------------------------------------------------------
    if eavesdrop:
        qubit_states = bb84_eavesdrop(qubit_states, intercept_prob=eavesdrop_prob)

    # ------------------------------------------------------------------
    # Phase 3: Bob measures qubits
    # ------------------------------------------------------------------
    qrng = QuantumRNG(n_qubits=8)
    bob_bases = qrng.random_bits(n_bits)
    bob_bits = bb84_measure_qubits(qubit_states, bob_bases)

    # ------------------------------------------------------------------
    # Phase 4: Basis reconciliation (sifting)
    # ------------------------------------------------------------------
    alice_sifted, bob_sifted = bb84_reconcile(
        alice_bits, alice_bases, bob_bits, bob_bases
    )

    # ------------------------------------------------------------------
    # Phase 5: Error estimation (QBER)
    # ------------------------------------------------------------------
    qber, alice_remaining, bob_remaining = bb84_error_check(
        alice_sifted, bob_sifted, sample_size
    )

    # ------------------------------------------------------------------
    # Phase 6: Privacy amplification
    # ------------------------------------------------------------------
    alice_key, bob_key = bb84_privacy_amplification(
        alice_remaining, bob_remaining, target_key_len
    )

    t_total = time.perf_counter()
    efficiency = len(alice_sifted) / n_bits if n_bits > 0 else 0.0

    result = BB84Result(
        alice_key=alice_key,
        bob_key=bob_key,
        keys_match=alice_key == bob_key,
        qber=qber,
        efficiency=efficiency,
        raw_bits=n_bits,
        sifted_bits=len(alice_sifted),
        eavesdropper_detected=qber > 0.11,
        preparation_time_ms=(t_prep - t0) * 1000.0,
        exchange_time_ms=(t_total - t0) * 1000.0,
    )

    return result


def bb84_interactive_demo(
    n_bits: int = 128,
    eavesdrop: bool = False,
) -> None:
    """Run an interactive step-by-step BB84 demonstration.

    Prints detailed output for each phase of the protocol, making it
    suitable for educational purposes and protocol understanding.

    Args:
        n_bits: Number of qubits to exchange (use small value for readability).
        eavesdrop: Enable eavesdropper simulation.
    """
    print("=" * 70)
    print("  BB84 Quantum Key Distribution — Interactive Demonstration")
    print("=" * 70)

    # Phase 1: Alice prepares
    print("\n[Phase 1] Alice prepares qubits")
    print("-" * 40)
    alice_bits, alice_bases, qubit_states = bb84_generate_qubits(n_bits)
    print(f"  Alice bits  : {''.join(map(str, alice_bits[:32]))}...")
    print(f"  Alice bases : {''.join('Z' if b == Z_BASIS else 'X' for b in alice_bases[:32])}...")

    # Phase 2: Optional eavesdropping
    if eavesdrop:
        print("\n[Phase 2] Eve intercepts qubits")
        print("-" * 40)
        qubit_states = bb84_eavesdrop(qubit_states, intercept_prob=0.5)

    # Phase 3: Bob measures
    print("\n[Phase 3] Bob measures qubits")
    print("-" * 40)
    qrng = QuantumRNG(n_qubits=8)
    bob_bases = qrng.random_bits(n_bits)
    bob_bits = bb84_measure_qubits(qubit_states, bob_bases)
    print(f"  Bob bases   : {''.join('Z' if b == Z_BASIS else 'X' for b in bob_bases[:32])}...")
    print(f"  Bob bits    : {''.join(map(str, bob_bits[:32]))}...")

    # Phase 4: Reconciliation
    print("\n[Phase 4] Basis reconciliation")
    print("-" * 40)
    alice_sifted, bob_sifted = bb84_reconcile(
        alice_bits, alice_bases, bob_bits, bob_bases
    )
    print(f"  Raw bits    : {n_bits}")
    print(f"  Sifted bits : {len(alice_sifted)} ({len(alice_sifted)/n_bits:.1%})")

    # Phase 5: Error check
    print("\n[Phase 5] Error estimation (QBER)")
    print("-" * 40)
    qber, alice_remaining, bob_remaining = bb84_error_check(
        alice_sifted, bob_sifted, sample_size=min(20, len(alice_sifted) // 2)
    )
    print(f"  QBER        : {qber:.4f} ({qber*100:.2f}%)")
    if qber > 0.11:
        print("  *** EAVESDROPPER LIKELY DETECTED ***")

    # Phase 6: Privacy amplification
    print("\n[Phase 6] Privacy amplification")
    print("-" * 40)
    alice_key, bob_key = bb84_privacy_amplification(alice_remaining, bob_remaining)
    print(f"  Alice key   : {alice_key.hex()}")
    print(f"  Bob key     : {bob_key.hex()}")
    print(f"  Match       : {'YES' if alice_key == bob_key else 'NO'}")

    print("\n" + "=" * 70)
    print("  BB84 Protocol Complete")
    print("=" * 70)


def benchmark_bb84(
    n_bits_list: Tuple[int, ...] = (128, 256, 512, 1024),
    iterations: int = 10,
) -> List[Dict[str, Any]]:
    """Benchmark BB84 key exchange across different qubit counts.

    Runs the protocol multiple times for each qubit count and reports
    average timing and key statistics.

    Args:
        n_bits_list: Tuple of qubit counts to benchmark.
        iterations: Number of iterations per qubit count.

    Returns:
        List of dictionaries containing benchmark results for each
        qubit count.
    """
    import statistics

    results: List[Dict[str, Any]] = []

    for n_bits in n_bits_list:
        timings: List[float] = []
        qbers: List[float] = []
        efficiencies: List[float] = []

        for _ in range(iterations):
            t0 = time.perf_counter()
            result = bb84_key_exchange(n_bits=n_bits)
            elapsed = (time.perf_counter() - t0) * 1000.0
            timings.append(elapsed)
            qbers.append(result.qber)
            efficiencies.append(result.efficiency)

        results.append(
            {
                "n_bits": n_bits,
                "mean_time_ms": round(statistics.mean(timings), 3),
                "stdev_time_ms": round(statistics.stdev(timings), 3) if len(timings) > 1 else 0.0,
                "mean_qber": round(statistics.mean(qbers), 6),
                "mean_efficiency": round(statistics.mean(efficiencies), 4),
                "iterations": iterations,
            }
        )

    return results


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) > 1 and sys.argv[1] == "demo":
        bb84_interactive_demo(n_bits=128, eavesdrop=False)
    elif len(sys.argv) > 1 and sys.argv[1] == "eavesdrop":
        bb84_interactive_demo(n_bits=128, eavesdrop=True)
    elif len(sys.argv) > 1 and sys.argv[1] == "bench":
        print("Running BB84 benchmarks...")
        bench_results = benchmark_bb84()
        print("\n{:<10} {:<15} {:<15} {:<12} {:<12}".format(
            "n_bits", "mean_time_ms", "stdev_time_ms", "mean_qber", "efficiency"
        ))
        print("-" * 65)
        for r in bench_results:
            print(
                "{n_bits:<10} {mean_time_ms:<15.3f} {stdev_time_ms:<15.3f} "
                "{mean_qber:<12.6f} {mean_efficiency:<12.4f}".format(**r)
            )
    else:
        # Default: standard key exchange with full reporting
        print("=" * 60)
        print("  BB84 Quantum Key Distribution Protocol")
        print("=" * 60)
        print()
        print("Running standard key exchange (n_bits=256)...")

        result = bb84_key_exchange(n_bits=256)

        print(f"\nResults:")
        print(f"  Raw bits              : {result.raw_bits}")
        print(f"  Sifted bits           : {result.sifted_bits}")
        print(f"  Efficiency            : {result.efficiency:.2%}")
        print(f"  QBER                  : {result.qber:.2%}")
        print(f"  Keys match            : {result.keys_match}")
        print(f"  Eavesdropper detected : {result.eavesdropper_detected}")
        print(f"  Final key (Alice)     : {result.alice_key[:16].hex()}...")
        print(f"  Final key (Bob)       : {result.bob_key[:16].hex()}...")
        print(f"  Preparation time      : {result.preparation_time_ms:.3f} ms")
        print(f"  Total exchange time   : {result.exchange_time_ms:.3f} ms")
