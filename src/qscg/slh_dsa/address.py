"""ADRS (Address) structure for SLH-DSA / SPHINCS+ (FIPS 205, Section 4.2).

The Address (ADRS) is a 32-byte structure that uniquely identifies the
position of a hash function call within the SLH-DSA hypertree.  It is
used as a domain separator to ensure that every invocation of the hash
function within the scheme is associated with a unique context.

Implemented routines
--------------------
- :class:`ADRS` — mutable 32-byte address structure with typed fields.

Usage example
-------------
>>> from qscg.slh_dsa.address import ADRS
>>> adrs = ADRS()
>>> adrs.layer = 3
>>> adrs.tree_address = 0x123456789ABCDEF0
>>> adrs.type = ADRS.WOTS_HASH
>>> adrs.keypair_address = 42
>>> adrs.chain_address = 7
>>> adrs.hash_address = 1
>>> bytes(adrs).hex()
'00000003...'
"""

from __future__ import annotations

import struct
from typing import Optional


class ADRS:
    """SLH-DSA Address (ADRS) — 32-byte structure.

    The ADRS encodes the *position* within the tree structure so that every
    hash invocation can be domain-separated.  The layout follows FIPS 205,
    Section 4.2:

    .. list-table:: ADRS byte layout
       :widths: 10 15 75
       :header-rows: 1

       * - Bytes
         - Field
         - Description
       * - 0–3
         - ``layer``
         - Hypertree layer (big-endian 32-bit unsigned)
       * - 4–15
         - ``tree_address``
         - Tree address (big-endian 96-bit unsigned, only lower 64 bits used)
       * - 16–19
         - ``type``
         - Address type — one of the ``WOTS_HASH``, ``WOTS_PK``,
           ``FORS_TREE``, ``FORS_ROOTS``, or ``TREE`` constants
       * - 20–23
         - ``keypair_address``
         - Key-pair address (OTS or FORS index within the tree)
       * - 24–27
         - ``chain_address``
         - Chain address (Winternitz chain index or tree height)
       * - 28–31
         - ``hash_address``
         - Hash address (Winternitz hash index or tree index)

    The structure is **mutable** — field setters update the internal
    ``bytearray`` in place.  Use :meth:`copy` to obtain an independent
    duplicate.

    Parameters
    ----------
    data:
        Optional 32-byte initial value.  If *None* (the default), the ADRS
        is initialised to all zeros.
    """

    # ------------------------------------------------------------------
    # Address type constants (FIPS 205, Section 4.2)
    # ------------------------------------------------------------------

    WOTS_HASH: int = 0
    """Address type for WOTS+ hash chains."""

    WOTS_PK: int = 1
    """Address type for WOTS+ public-key compression."""

    TREE: int = 2
    """Address type for Merkle-tree hashing (XMSS / hypertree)."""

    FORS_TREE: int = 3
    """Address type for FORS tree hashing."""

    FORS_ROOTS: int = 4
    """Address type for FORS roots compression."""

    # ------------------------------------------------------------------
    # Construction / initialisation
    # ------------------------------------------------------------------

    def __init__(self, data: Optional[bytes] = None) -> None:
        if data is None:
            self._data: bytearray = bytearray(32)
        else:
            if not isinstance(data, (bytes, bytearray)):
                raise TypeError(
                    f"ADRS: expected bytes-like, got {type(data).__name__}"
                )
            self._data = bytearray(data[:32])
            # Pad to 32 bytes if the input was shorter
            while len(self._data) < 32:
                self._data.append(0)

    # ------------------------------------------------------------------
    # Byte-level access
    # ------------------------------------------------------------------

    def __bytes__(self) -> bytes:
        """Return a copy of the 32-byte ADRS as an immutable ``bytes`` object."""
        return bytes(self._data)

    def __repr__(self) -> str:
        return (
            f"ADRS(layer={self.layer}, "
            f"tree=0x{self.tree_address:016x}, "
            f"type={self.type})"
        )

    def __eq__(self, other: object) -> bool:
        """Two ADRS instances are equal iff their 32-byte payloads are identical."""
        if not isinstance(other, ADRS):
            return NotImplemented
        return bytes(self._data) == bytes(other._data)

    def __hash__(self) -> int:
        """ADRS instances are hashable (immutable view via ``bytes``)."""
        return hash(bytes(self._data))

    # ------------------------------------------------------------------
    # Typed field properties — layer (bytes 0–3)
    # ------------------------------------------------------------------

    @property
    def layer(self) -> int:
        """Hypertree layer — big-endian 32-bit unsigned integer (bytes 0–3).

        Returns
        -------
        int
            Layer index in ``[0, d-1]`` where *d* is the number of layers.
        """
        return struct.unpack('>I', self._data[0:4])[0]

    @layer.setter
    def layer(self, value: int) -> None:
        """Set the hypertree layer (bytes 0–3).

        Parameters
        ----------
        value:
            32-bit unsigned integer.
        """
        self._data[0:4] = struct.pack('>I', int(value) & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # Typed field properties — tree_address (bytes 4–15)
    # ------------------------------------------------------------------

    @property
    def tree_address(self) -> int:
        """Tree address — lower 64 bits of the 96-bit field (bytes 4–11).

        The full tree-address field spans bytes 4–15 (96 bits), but in
        typical SLH-DSA instantiations only the lower 64 bits are used.
        This property reads/writes those 64 bits.

        Returns
        -------
        int
            Tree address as an unsigned 64-bit integer.
        """
        return struct.unpack('>Q', self._data[4:12])[0]

    @tree_address.setter
    def tree_address(self, value: int) -> None:
        """Set the tree address (bytes 4–11, 64-bit).

        Parameters
        ----------
        value:
            64-bit unsigned integer.
        """
        self._data[4:12] = struct.pack('>Q', int(value) & 0xFFFFFFFFFFFFFFFF)

    # ------------------------------------------------------------------
    # Full 96-bit tree address access (bytes 4–15, advanced use)
    # ------------------------------------------------------------------

    @property
    def tree_address_full(self) -> bytes:
        """Return the full 96-bit (12-byte) tree address field (bytes 4–15).

        Returns
        -------
        bytes
            12-byte big-endian tree address.
        """
        return bytes(self._data[4:16])

    @tree_address_full.setter
    def tree_address_full(self, value: bytes) -> None:
        """Set the full 96-bit tree address field (bytes 4–15).

        Parameters
        ----------
        value:
            Up to 12 bytes; shorter values are left-padded with zeros.
        """
        padded = bytearray(12)
        src = value[-12:] if len(value) > 12 else value
        padded[-len(src):] = src
        self._data[4:16] = padded

    # ------------------------------------------------------------------
    # Typed field properties — type (bytes 16–19)
    # ------------------------------------------------------------------

    @property
    def type(self) -> int:
        """Address type — big-endian 32-bit unsigned integer (bytes 16–19).

        One of the class constants: ``WOTS_HASH``, ``WOTS_PK``, ``TREE``,
        ``FORS_TREE``, or ``FORS_ROOTS``.

        Returns
        -------
        int
            Address type value.
        """
        return struct.unpack('>I', self._data[16:20])[0]

    @type.setter
    def type(self, value: int) -> None:
        """Set the address type (bytes 16–19).

        Parameters
        ----------
        value:
            32-bit unsigned integer.  Prefer the class constants.
        """
        self._data[16:20] = struct.pack('>I', int(value) & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # Typed field properties — keypair_address (bytes 20–23)
    # ------------------------------------------------------------------

    @property
    def keypair_address(self) -> int:
        """Key-pair address — big-endian 32-bit unsigned (bytes 20–23).

        In WOTS+ contexts this is the OTS index within the XMSS tree.
        In FORS contexts this is the FORS key-pair index.

        Returns
        -------
        int
            Key-pair address.
        """
        return struct.unpack('>I', self._data[20:24])[0]

    @keypair_address.setter
    def keypair_address(self, value: int) -> None:
        """Set the key-pair address (bytes 20–23).

        Parameters
        ----------
        value:
            32-bit unsigned integer.
        """
        self._data[20:24] = struct.pack('>I', int(value) & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # Typed field properties — chain_address (bytes 24–27)
    # ------------------------------------------------------------------

    @property
    def chain_address(self) -> int:
        """Chain address — big-endian 32-bit unsigned (bytes 24–27).

        In WOTS+ this is the Winternitz chain index.
        In XMSS/FORS tree hashing this is the tree height.

        Returns
        -------
        int
            Chain address.
        """
        return struct.unpack('>I', self._data[24:28])[0]

    @chain_address.setter
    def chain_address(self, value: int) -> None:
        """Set the chain address (bytes 24–27).

        Parameters
        ----------
        value:
            32-bit unsigned integer.
        """
        self._data[24:28] = struct.pack('>I', int(value) & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # Typed field properties — hash_address (bytes 28–31)
    # ------------------------------------------------------------------

    @property
    def hash_address(self) -> int:
        """Hash address — big-endian 32-bit unsigned (bytes 28–31).

        In WOTS+ this is the Winternitz hash index within a chain.
        In XMSS/FORS tree hashing this is the tree index at a given height.

        Returns
        -------
        int
            Hash address.
        """
        return struct.unpack('>I', self._data[28:32])[0]

    @hash_address.setter
    def hash_address(self, value: int) -> None:
        """Set the hash address (bytes 28–31).

        Parameters
        ----------
        value:
            32-bit unsigned integer.
        """
        self._data[28:32] = struct.pack('>I', int(value) & 0xFFFFFFFF)

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def copy(self) -> ADRS:
        """Return an independent deep copy of this ADRS.

        Returns
        -------
        ADRS
            New ADRS instance with identical 32-byte payload.
        """
        return ADRS(bytes(self._data))

    def reset(self) -> None:
        """Reset all 32 bytes to zero."""
        self._data[:] = bytearray(32)

    def to_bytes(self) -> bytes:
        """Alias for ``bytes(self)`` — returns the 32-byte encoding.

        Returns
        -------
        bytes
            Immutable copy of the 32-byte ADRS.
        """
        return bytes(self._data)

    @classmethod
    def from_bytes(cls, data: bytes) -> ADRS:
        """Construct an ADRS from a 32-byte (or shorter) byte string.

        Parameters
        ----------
        data:
            Up to 32 bytes; shorter input is zero-padded on the right.

        Returns
        -------
        ADRS
            New ADRS instance.
        """
        return cls(data)

    def set_tree_address(self, tree: int, leaf: int) -> None:
        """Convenience setter for combined tree + leaf addressing.

        Sets ``tree_address`` to *tree* and ``keypair_address`` to *leaf*.
        This covers the common XMSS addressing pattern.

        Parameters
        ----------
        tree:
            Tree address (64-bit).
        leaf:
            Leaf / key-pair index within the tree (32-bit).
        """
        self.tree_address = tree
        self.keypair_address = leaf

    def set_chain_params(self, chain: int, hash_idx: int) -> None:
        """Set the Winternitz chain-specific parameters.

        Sets ``chain_address`` to *chain* and ``hash_address`` to
        *hash_idx*.  This is used within WOTS+ hash chain evaluations.

        Parameters
        ----------
        chain:
            Winternitz chain index (32-bit).
        hash_idx:
            Hash step index within the chain (32-bit).
        """
        self.chain_address = chain
        self.hash_address = hash_idx
