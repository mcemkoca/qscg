"""Quantum-Safe TLS Tunnel using QSCG post-quantum algorithms.

Implements a quantum-resistant TLS-like protocol:
  - Handshake: ML-KEM key encapsulation + ML-DSA signature
  - Data: AES-256-GCM authenticated encryption
  - Perfect Forward Secrecy via ephemeral ML-KEM keys

This module provides a complete post-quantum secure communication channel
that is resistant to both classical and quantum computer attacks. It
combines the ML-KEM (Module Lattice-based Key Encapsulation Mechanism)
for key exchange with ML-DSA (Module Lattice-based Digital Signature
Algorithm) for authentication, providing NIST FIPS 203/204 compliant
security.

Example:
    Server side::

        from tls_tunnel import QuantumSafeTLS, QuantumTunnel, run_server
        run_server(host="0.0.0.0", port=8443)

    Client side::

        from tls_tunnel import QuantumSafeTLS, QuantumTunnel, run_client
        run_client(host="127.0.0.1", port=8443)

Attributes:
    __version__: Module version string.
    DEFAULT_PORT: Default listening port for quantum-safe TLS (8443).
    MAX_MESSAGE_SIZE: Maximum allowed plaintext message size (64 KiB).
    HEADER_SIZE: Size of the encrypted record header in bytes (12).
    NONCE_SIZE: Size of AES-GCM nonce in bytes (12).
    KEY_SIZE: Size of AES-256 key in bytes (32).

References:
    - NIST FIPS 203: Module-Lattice-Based Key-Encapsulation Mechanism Standard
    - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard
    - NIST SP 800-185: SHA-3 Derived Functions (cSHAKE, KMAC)
"""

from __future__ import annotations

import hashlib
import logging
import secrets
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------------------
# QSCG module imports
# ---------------------------------------------------------------------------

try:
    from ..ml_kem.ml_kem import MLKEM
    from ..ml_dsa.ml_dsa import MLDSA
    from ..common.constants import SecurityLevel
except ImportError:
    # Fallback stub implementations for standalone testing.
    # These are *not* secure and exist only so the module can be imported
    # when the parent QSCG package is not available.

    class SecurityLevel(IntEnum):  # type: ignore[no-redef]
        """Post-quantum security parameter sets."""

        LEVEL_1 = 1
        LEVEL_3 = 3
        LEVEL_5 = 5

    class MLKEM:  # type: ignore[no-redef]
        """Stub ML-KEM implementation for standalone imports."""

        ML_KEM_512_PK_SIZE = 800
        ML_KEM_512_CT_SIZE = 768
        ML_KEM_768_PK_SIZE = 1184
        ML_KEM_768_CT_SIZE = 1088
        ML_KEM_1024_PK_SIZE = 1568
        ML_KEM_1024_CT_SIZE = 1568

        def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> None:
            """Initialize ML-KEM with given security level.

            Args:
                level: NIST security level (1, 3, or 5).
            """
            self.level = level

        def KeyGen(self) -> Tuple[bytes, bytes]:
            """Generate encapsulation/decapsulation keypair.

            Returns:
                Tuple of (encapsulation_key, decapsulation_key).
            """
            if self.level == SecurityLevel.LEVEL_1:
                pk_size = self.ML_KEM_512_PK_SIZE
                dk_size = 1632
            elif self.level == SecurityLevel.LEVEL_5:
                pk_size = self.ML_KEM_1024_PK_SIZE
                dk_size = 3168
            else:
                pk_size = self.ML_KEM_768_PK_SIZE
                dk_size = 2400
            return secrets.token_bytes(pk_size), secrets.token_bytes(dk_size)

        def Encaps(self, ek: bytes) -> Tuple[bytes, bytes]:
            """Encapsulate a shared secret.

            Args:
                ek: Encapsulation (public) key.

            Returns:
                Tuple of (ciphertext, shared_secret).
            """
            if self.level == SecurityLevel.LEVEL_1:
                ct_size = self.ML_KEM_512_CT_SIZE
            elif self.level == SecurityLevel.LEVEL_5:
                ct_size = self.ML_KEM_1024_CT_SIZE
            else:
                ct_size = self.ML_KEM_768_CT_SIZE
            return secrets.token_bytes(ct_size), secrets.token_bytes(32)

        def Decaps(self, dk: bytes, ciphertext: bytes) -> bytes:
            """Decapsulate shared secret.

            Args:
                dk: Decapsulation (secret) key.
                ciphertext: Encapsulated ciphertext.

            Returns:
                32-byte shared secret.
            """
            return secrets.token_bytes(32)

    class MLDSA:  # type: ignore[no-redef]
        """Stub ML-DSA implementation for standalone imports."""

        def __init__(self, level: SecurityLevel = SecurityLevel.LEVEL_3) -> None:
            """Initialize ML-DSA with given security level.

            Args:
                level: NIST security level (1, 3, or 5).
            """
            self.level = level

        def keygen(self) -> Tuple[bytes, bytes]:
            """Generate signature keypair.

            Returns:
                Tuple of (public_key, secret_key).
            """
            return secrets.token_bytes(2592), secrets.token_bytes(4896)

        def sign(self, sk: bytes, message: bytes) -> bytes:
            """Sign a message.

            Args:
                sk: Secret key.
                message: Message to sign.

            Returns:
                Signature bytes.
            """
            return secrets.token_bytes(4627)

        def verify(self, pk: bytes, message: bytes, signature: bytes) -> bool:
            """Verify a signature.

            Args:
                pk: Public key.
                message: Signed message.
                signature: Signature to verify.

            Returns:
                True if the signature is valid, False otherwise.
            """
            return True

# ---------------------------------------------------------------------------
# Module constants
# ---------------------------------------------------------------------------

__version__ = "1.0.0"
DEFAULT_PORT = 8443
MAX_MESSAGE_SIZE = 64 * 1024  # 64 KiB
HEADER_SIZE = 12  # seq_num(8) + len(4)
NONCE_SIZE = 12
KEY_SIZE = 32
HANDSHAKE_VERSION = b"QTLS\x01\x00"  # Quantum TLS v1.0

logger = logging.getLogger(__name__)


class HandshakeError(Exception):
    """Raised when the quantum-safe TLS handshake fails."""

    pass


class AuthenticationError(Exception):
    """Raised when ML-DSA signature verification fails."""

    pass


class ProtocolError(Exception):
    """Raised on a protocol-level violation."""

    pass


@dataclass
class TLSConfig:
    """Configuration parameters for the quantum-safe TLS tunnel.

    Attributes:
        security_level: NIST post-quantum security level (1, 3, 5).
        host: Bind/connect host address.
        port: Bind/connect port number.
        timeout: Socket timeout in seconds.
        max_message_size: Maximum allowed plaintext message size.
        max_seq_num: Maximum sequence number before re-keying.
    """

    security_level: SecurityLevel = SecurityLevel.LEVEL_3
    host: str = "127.0.0.1"
    port: int = DEFAULT_PORT
    timeout: float = 30.0
    max_message_size: int = MAX_MESSAGE_SIZE
    max_seq_num: int = 2**32 - 1


@dataclass
class HandshakeResult:
    """Result of a completed TLS handshake.

    Attributes:
        shared_secret: The 32-byte shared secret derived from ML-KEM.
        server_public_key: The server's ML-DSA public key (client only).
        handshake_time_ms: Round-trip handshake time in milliseconds.
        kem_ciphertext_size: Size of the ML-KEM ciphertext in bytes.
        signature_size: Size of the ML-DSA signature in bytes.
    """

    shared_secret: bytes
    server_public_key: Optional[bytes] = None
    handshake_time_ms: float = 0.0
    kem_ciphertext_size: int = 0
    signature_size: int = 0


class QuantumSafeTLS:
    """Quantum-safe TLS tunnel using ML-KEM + ML-DSA + AES-GCM.

    Protocol flow:
        1. Client -> Server: ``ClientHello`` (handshake version + ephemeral ML-KIM ek)
        2. Server -> Client: ``ServerHello`` (ML-DSA signed ciphertext + server_pk)
        3. Client: Verify ML-DSA signature, decapsulate -> shared_secret
        4. Both: Derive AES-256-GCM keys from shared_secret via SHA3-256
        5. Encrypted data exchange over the authenticated tunnel

    The protocol provides:
        * **Confidentiality**: AES-256-GCM with keys derived from ML-KEM
        * **Authentication**: ML-DSA signatures on the KEM ciphertext
        * **Integrity**: AES-GCM authentication tag (128-bit)
        * **Forward Secrecy**: Ephemeral ML-KEM keys per session

    Attributes:
        config: TLSConfig instance with protocol parameters.
        level: SecurityLevel for ML-KEM/ML-DSA parameter selection.
        mldsa: ML-DSA instance for server authentication.
        mlkem: ML-KEM instance for ephemeral key exchange.
    """

    def __init__(self, config: Optional[TLSConfig] = None) -> None:
        """Initialize the quantum-safe TLS handler.

        Args:
            config: Optional TLSConfig.  Defaults to LEVEL_3 parameters.
        """
        self.config = config or TLSConfig()
        self.level = self.config.security_level
        self.mlkem = MLKEM(self.level)
        self.mldsa = MLDSA(self.level)

    # ---- Server Side ----

    def server_handshake(
        self, conn: socket.socket, server_sk: bytes, server_pk: bytes
    ) -> HandshakeResult:
        """Execute the server-side quantum-safe handshake.

        Expects the client to send its ephemeral ML-KEM encapsulation key,
        then encapsulates a shared secret, signs the ciphertext with the
        server's ML-DSA secret key, and transmits the result back.

        Args:
            conn: Accepted client connection socket.
            server_sk: Server's ML-DSA secret key.
            server_pk: Server's ML-DSA public key.

        Returns:
            HandshakeResult containing the shared secret and metadata.

        Raises:
            HandshakeError: If the client hello is malformed.
            AuthenticationError: If local signing fails.
        """
        t0 = time.perf_counter()

        # Step 1: Receive handshake version prefix (6 bytes)
        version_prefix = self._recv_exact(conn, 6)
        if version_prefix != HANDSHAKE_VERSION:
            raise HandshakeError(
                f"Unsupported handshake version: {version_prefix.hex()}"
            )

        # Step 2: Receive client ephemeral ML-KEM public key
        ek_len_data = self._recv_exact(conn, 2)
        ek_len = struct.unpack("!H", ek_len_data)[0]
        if ek_len < 64 or ek_len > 8192:
            raise HandshakeError(f"Invalid encapsulation key size: {ek_len}")

        client_ek = self._recv_exact(conn, ek_len)
        logger.debug("Received client ephemeral ML-KEM ek (%d bytes)", ek_len)

        # Step 3: Encapsulate shared secret against client's ephemeral key
        ciphertext, shared_secret = self.mlkem.Encaps(client_ek)
        logger.debug(
            "ML-KEM encapsulation complete: ct=%d bytes, ss=%d bytes",
            len(ciphertext),
            len(shared_secret),
        )

        # Step 4: Sign the ciphertext with server's ML-DSA secret key
        sig = self.mldsa.sign(server_sk, ciphertext)
        logger.debug("ML-DSA signature complete: sig=%d bytes", len(sig))

        # Step 5: Send handshake response
        #  Format: [version(6)] [ct_len(2)] [ciphertext] [sig_len(2)] [sig] [pk_len(2)] [server_pk]
        payload = HANDSHAKE_VERSION
        payload += struct.pack("!H", len(ciphertext)) + ciphertext
        payload += struct.pack("!H", len(sig)) + sig
        payload += struct.pack("!H", len(server_pk)) + server_pk
        conn.sendall(payload)
        logger.debug("Sent ServerHello (%d bytes total)", len(payload))

        elapsed = (time.perf_counter() - t0) * 1000.0
        logger.info("Server handshake completed in %.2f ms", elapsed)

        return HandshakeResult(
            shared_secret=shared_secret,
            kem_ciphertext_size=len(ciphertext),
            signature_size=len(sig),
            handshake_time_ms=elapsed,
        )

    def server_handshake_with_keygen(
        self, conn: socket.socket,
    ) -> Tuple[HandshakeResult, bytes, bytes]:
        """Server handshake that also generates a fresh ML-DSA keypair.

        This is useful for short-lived or ephemeral servers where key
        persistence is not required.

        Args:
            conn: Accepted client connection socket.

        Returns:
            Tuple of (HandshakeResult, server_sk, server_pk).
        """
        server_pk, server_sk = self.mldsa.keygen()
        result = self.server_handshake(conn, server_sk, server_pk)
        return result, server_sk, server_pk

    # ---- Client Side ----

    def client_handshake(
        self, conn: socket.socket,
    ) -> HandshakeResult:
        """Execute the client-side quantum-safe handshake.

        Generates an ephemeral ML-KEM keypair, sends the encapsulation key,
        receives the server's signed ciphertext, verifies the ML-DSA
        signature, and decapsulates the shared secret.

        Args:
            conn: Connected server socket.

        Returns:
            HandshakeResult containing the shared secret and server public key.

        Raises:
            AuthenticationError: If the server signature is invalid.
            HandshakeError: If the server response is malformed.
        """
        t0 = time.perf_counter()

        # Step 1: Generate ephemeral ML-KEM keypair
        ek, dk = self.mlkem.KeyGen()
        logger.debug(
            "Generated ephemeral ML-KEM keypair: ek=%d bytes, dk=%d bytes",
            len(ek),
            len(dk),
        )

        # Step 2: Send ClientHello = version + ephemeral public key
        client_hello = HANDSHAKE_VERSION + struct.pack("!H", len(ek)) + ek
        conn.sendall(client_hello)
        logger.debug("Sent ClientHello (%d bytes)", len(client_hello))

        # Step 3: Receive ServerHello
        version_prefix = self._recv_exact(conn, 6)
        if version_prefix != HANDSHAKE_VERSION:
            raise HandshakeError(
                f"Unsupported server handshake version: {version_prefix.hex()}"
            )

        ct_len = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        if ct_len < 1 or ct_len > 8192:
            raise HandshakeError(f"Invalid ciphertext length: {ct_len}")
        ciphertext = self._recv_exact(conn, ct_len)

        sig_len = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        if sig_len < 1 or sig_len > 16384:
            raise HandshakeError(f"Invalid signature length: {sig_len}")
        sig = self._recv_exact(conn, sig_len)

        pk_len = struct.unpack("!H", self._recv_exact(conn, 2))[0]
        if pk_len < 32 or pk_len > 8192:
            raise HandshakeError(f"Invalid server public key length: {pk_len}")
        server_pk = self._recv_exact(conn, pk_len)

        logger.debug(
            "Received ServerHello: ct=%d, sig=%d, pk=%d bytes",
            ct_len,
            sig_len,
            pk_len,
        )

        # Step 4: Verify server ML-DSA signature over the ciphertext
        valid = self.mldsa.verify(server_pk, ciphertext, sig)
        if not valid:
            raise AuthenticationError(
                "Server ML-DSA signature verification failed! Possible MITM attack."
            )
        logger.info("Server ML-DSA signature verified successfully")

        # Step 5: Decapsulate shared secret
        shared_secret = self.mlkem.Decaps(dk, ciphertext)
        logger.info("Shared secret decapsulated (%d bytes)", len(shared_secret))

        elapsed = (time.perf_counter() - t0) * 1000.0
        logger.info("Client handshake completed in %.2f ms", elapsed)

        return HandshakeResult(
            shared_secret=shared_secret,
            server_public_key=server_pk,
            kem_ciphertext_size=ct_len,
            signature_size=sig_len,
            handshake_time_ms=elapsed,
        )

    # ---- Helpers ----

    @staticmethod
    def _recv_exact(conn: socket.socket, num_bytes: int) -> bytes:
        """Receive exactly *num_bytes* from the socket.

        Args:
            conn: Active socket connection.
            num_bytes: Exact number of bytes to read.

        Returns:
            The received byte string of length *num_bytes*.

        Raises:
            HandshakeError: If the connection is closed before enough
                data is received.
        """
        buf = b""
        while len(buf) < num_bytes:
            chunk = conn.recv(num_bytes - len(buf))
            if not chunk:
                raise HandshakeError(
                    f"Connection closed while reading (got {len(buf)}/{num_bytes} bytes)"
                )
            buf += chunk
        return buf

    @staticmethod
    def derive_aes_key(shared_secret: bytes) -> bytes:
        """Derive a 32-byte AES-256 key from the ML-KEM shared secret.

        Uses SHA3-256 as the key derivation function (KDF) to produce a
        uniform key suitable for AES-256-GCM.

        Args:
            shared_secret: Raw shared secret from ML-KEM.

        Returns:
            32-byte AES-256 key.
        """
        return hashlib.sha3_256(shared_secret).digest()


class QuantumTunnel:
    """High-level quantum-safe encrypted tunnel over a TCP socket.

    Wraps an existing socket with AES-256-GCM authenticated encryption
    using keys derived from an ML-KEM shared secret.  Provides
    sequence-number based anti-replay protection and automatic
    fragmentation for large messages.

    Attributes:
        aes: AESGCM cipher instance.
        _seq_num: Outgoing sequence number (monotonically increasing).
        _recv_seq_num: Highest received sequence number for replay detection.
        _max_message_size: Maximum plaintext length per record.
    """

    def __init__(
        self,
        shared_secret: bytes,
        max_message_size: int = MAX_MESSAGE_SIZE,
    ) -> None:
        """Initialize the encrypted tunnel.

        Derives the AES-256 key from the shared secret using SHA3-256.

        Args:
            shared_secret: 32-byte shared secret from ML-KEM handshake.
            max_message_size: Maximum allowed plaintext per send call.
        """
        key = QuantumSafeTLS.derive_aes_key(shared_secret)
        self.aes: AESGCM = AESGCM(key)
        self._seq_num: int = 0
        self._recv_seq_num: int = -1
        self._max_message_size: int = max_message_size
        self._lock = threading.Lock()

    def send(self, sock: socket.socket, plaintext: bytes) -> None:
        """Encrypt and send data over the tunnel.

        The data is encrypted with AES-256-GCM using a 12-byte nonce
        derived from the current sequence number.  The transmitted
        record format is::

            [seq_num: uint64_be] [ct_len: uint32_be] [ciphertext+tag]

        Args:
            sock: Connected socket.
            plaintext: Data to encrypt and send.

        Raises:
            ValueError: If *plaintext* exceeds :attr:`_max_message_size`.
            ConnectionError: If the socket connection is broken.
        """
        if len(plaintext) > self._max_message_size:
            raise ValueError(
                f"Message too large: {len(plaintext)} > {self._max_message_size}"
            )

        with self._lock:
            seq_num = self._seq_num
            nonce = seq_num.to_bytes(NONCE_SIZE, "big")
            ciphertext = self.aes.encrypt(nonce, plaintext, None)

            packet = struct.pack("!Q", seq_num)
            packet += struct.pack("!I", len(ciphertext))
            packet += ciphertext

            self._seq_num += 1

        try:
            sock.sendall(packet)
        except OSError as exc:
            raise ConnectionError(f"Failed to send encrypted record: {exc}") from exc

    def recv(self, sock: socket.socket) -> bytes:
        """Receive and decrypt data from the tunnel.

        Reads a full encrypted record from the socket, verifies the
        sequence number (basic anti-replay), and decrypts using
        AES-256-GCM.

        Args:
            sock: Connected socket.

        Returns:
            Decrypted plaintext bytes.

        Raises:
            ConnectionError: If the connection is closed mid-read.
            ProtocolError: If a replayed or out-of-order record is detected.
        """
        # Read 12-byte header: seq_num(8) + ct_len(4)
        header = self._recv_all(sock, HEADER_SIZE)
        seq_num = struct.unpack("!Q", header[:8])[0]
        ct_len = struct.unpack("!I", header[8:])[0]

        # Basic replay / out-of-order detection
        if seq_num <= self._recv_seq_num:
            raise ProtocolError(
                f"Replay or out-of-order record detected (seq={seq_num}, "
                f"expected > {self._recv_seq_num})"
            )

        # Sanity check on ciphertext length
        if ct_len < 16 or ct_len > self._max_message_size + 16:
            raise ProtocolError(f"Invalid ciphertext length: {ct_len}")

        ciphertext = self._recv_all(sock, ct_len)
        nonce = seq_num.to_bytes(NONCE_SIZE, "big")
        plaintext = self.aes.decrypt(nonce, ciphertext, None)

        self._recv_seq_num = seq_num
        return plaintext

    def send_message(self, sock: socket.socket, plaintext: bytes) -> None:
        """Send a possibly large message, fragmenting if needed.

        Args:
            sock: Connected socket.
            plaintext: Message payload.
        """
        offset = 0
        while offset < len(plaintext):
            chunk = plaintext[offset : offset + self._max_message_size]
            self.send(sock, chunk)
            offset += len(chunk)

    def recv_message(self, sock: socket.socket) -> bytes:
        """Receive a full message (single fragment).

        For multi-fragment messages, the caller should call this
        repeatedly until the expected payload is complete.

        Args:
            sock: Connected socket.

        Returns:
            Decrypted plaintext fragment.
        """
        return self.recv(sock)

    @staticmethod
    def _recv_all(sock: socket.socket, num_bytes: int) -> bytes:
        """Blocking read of exactly *num_bytes*.

        Args:
            sock: Active socket.
            num_bytes: Exact byte count to read.

        Returns:
            Byte string of length *num_bytes*.

        Raises:
            ConnectionError: If the connection is closed prematurely.
        """
        buf = b""
        while len(buf) < num_bytes:
            chunk = sock.recv(num_bytes - len(buf))
            if not chunk:
                raise ConnectionError(
                    f"Connection closed while reading (got {len(buf)}/{num_bytes})"
                )
            buf += chunk
        return buf


# ---- Convenience Server / Client ----


def run_server(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    config: Optional[TLSConfig] = None,
) -> None:
    """Run a blocking quantum-safe TLS echo server.

    Generates a fresh ML-DSA keypair on startup, accepts a single
    connection, performs the handshake, and echoes back any received
    messages until the client sends ``b"QUIT"``.

    Args:
        host: Interface to bind (``"0.0.0.0"`` for all interfaces).
        port: TCP port to listen on.
        config: Optional TLSConfig; defaults to LEVEL_3.
    """
    tls = QuantumSafeTLS(config)

    # Generate long-term server identity key
    server_pk, server_sk = tls.mldsa.keygen()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.listen(1)

    print(f"Quantum-Safe TLS Server listening on {host}:{port}")
    print(f"  Security Level : {tls.level.name}")
    print(f"  Server ML-DSA  : {server_pk[:16].hex()}...")
    print(f"  Handshake ver  : {HANDSHAKE_VERSION.hex()}")
    print("-" * 50)

    conn, addr = sock.accept()
    print(f"Connection from {addr}")

    try:
        # Handshake
        result = tls.server_handshake(conn, server_sk, server_pk)
        print(f"  Handshake time : {result.handshake_time_ms:.2f} ms")
        print(f"  KEM ciphertext : {result.kem_ciphertext_size} bytes")
        print(f"  ML-DSA sig     : {result.signature_size} bytes")
        print(f"  Shared secret  : {result.shared_secret[:8].hex()}...")
        print("-" * 50)

        # Encrypted tunnel
        tunnel = QuantumTunnel(result.shared_secret)

        # Echo server loop
        while True:
            msg = tunnel.recv(conn)
            if msg == b"QUIT":
                print("Client requested disconnect.")
                break
            print(f"  [decrypted] {msg.decode('utf-8', errors='replace')}")
            tunnel.send(conn, b"Echo: " + msg)

    except (HandshakeError, AuthenticationError) as exc:
        print(f"Handshake FAILED: {exc}")
    except ConnectionError as exc:
        print(f"Connection error: {exc}")
    finally:
        conn.close()
        sock.close()
        print("Server shut down.")


def run_client(
    host: str = "127.0.0.1",
    port: int = DEFAULT_PORT,
    config: Optional[TLSConfig] = None,
) -> None:
    """Run a quantum-safe TLS client that sends a test message.

    Connects to the server, performs the handshake, sends
    ``b"Hello Quantum World!"``, prints the echoed response, and
    disconnects gracefully.

    Args:
        host: Server hostname or IP address.
        port: Server TCP port.
        config: Optional TLSConfig; defaults to LEVEL_3.
    """
    tls = QuantumSafeTLS(config)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect((host, port))
        print(f"Connected to {host}:{port}")

        # Handshake
        result = tls.client_handshake(sock)
        print(f"  Handshake time : {result.handshake_time_ms:.2f} ms")
        print(f"  Server ML-DSA  : {result.server_public_key[:16].hex()}...")
        print(f"  Shared secret  : {result.shared_secret[:8].hex()}...")
        print("-" * 50)

        # Encrypted tunnel
        tunnel = QuantumTunnel(result.shared_secret)

        # Send test message
        tunnel.send(sock, b"Hello Quantum World!")
        response = tunnel.recv(sock)
        print(f"  Server -> {response.decode('utf-8', errors='replace')}")

        # Graceful disconnect
        tunnel.send(sock, b"QUIT")
        print("Disconnected gracefully.")

    except (HandshakeError, AuthenticationError) as exc:
        print(f"Handshake FAILED: {exc}")
    except ConnectionError as exc:
        print(f"Connection error: {exc}")
    finally:
        sock.close()


def benchmark_handshake(
    iterations: int = 100,
    level: SecurityLevel = SecurityLevel.LEVEL_3,
) -> Dict[str, float]:
    """Benchmark the quantum-safe handshake performance.

    Runs *iterations* client-server handshakes over localhost TCP
    sockets and reports timing statistics.

    Args:
        iterations: Number of handshake iterations.
        level: SecurityLevel to benchmark.

    Returns:
        Dictionary with ``min``, ``max``, ``mean``, and ``median``
        handshake times in milliseconds.
    """
    import statistics

    times_ms: List[float] = []
    config = TLSConfig(security_level=level)

    # Generate server keypair once
    tls = QuantumSafeTLS(config)
    server_pk, server_sk = tls.mldsa.keygen()

    for _ in range(iterations):
        # Ephemeral listener
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        port = listener.getsockname()[1]

        def server_thread() -> None:
            conn, _ = listener.accept()
            try:
                tls.server_handshake(conn, server_sk, server_pk)
            finally:
                conn.close()
                listener.close()

        srv = threading.Thread(target=server_thread)
        srv.start()

        client_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_sock.connect(("127.0.0.1", port))
        t0 = time.perf_counter()
        tls.client_handshake(client_sock)
        elapsed = (time.perf_counter() - t0) * 1000.0
        times_ms.append(elapsed)
        client_sock.close()
        srv.join()

    return {
        "min_ms": min(times_ms),
        "max_ms": max(times_ms),
        "mean_ms": statistics.mean(times_ms),
        "median_ms": statistics.median(times_ms),
        "iterations": iterations,
        "level": level.name,
    }


if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    if len(sys.argv) > 1 and sys.argv[1] == "server":
        run_server()
    elif len(sys.argv) > 1 and sys.argv[1] == "client":
        run_client()
    elif len(sys.argv) > 1 and sys.argv[1] == "bench":
        result = benchmark_handshake(iterations=10)
        print("\n=== Handshake Benchmark ===")
        for k, v in result.items():
            print(f"  {k}: {v}")
    else:
        print("Usage: python tls_tunnel.py [server|client|bench]")
        print("  server  - Start quantum-safe TLS echo server")
        print("  client  - Connect and send test message")
        print("  bench   - Run handshake performance benchmark")
