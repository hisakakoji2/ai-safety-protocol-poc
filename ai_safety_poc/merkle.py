"""Merkle tree hashing, inclusion proofs and consistency proofs.

Follows the algorithms of RFC 9162 (Certificate Transparency Version 2.0),
sections 2.1.1 to 2.1.4, using SHA-256.
"""

from __future__ import annotations

import hashlib
from typing import Sequence

HASH_SIZE = 32


def leaf_hash(data: bytes) -> bytes:
    """Hash of a leaf: SHA-256(0x00 || data)."""
    return hashlib.sha256(b"\x00" + data).digest()


def node_hash(left: bytes, right: bytes) -> bytes:
    """Hash of an interior node: SHA-256(0x01 || left || right)."""
    return hashlib.sha256(b"\x01" + left + right).digest()


def empty_root() -> bytes:
    """Root of an empty tree: SHA-256 of the empty string."""
    return hashlib.sha256(b"").digest()


def _split(n: int) -> int:
    """Largest power of two strictly smaller than n (n >= 2)."""
    k = 1
    while k << 1 < n:
        k <<= 1
    return k


class MerkleTree:
    """An append-only Merkle tree over leaf hashes.

    Subtree roots are cached by (start, end). Because the tree only grows,
    the root of a fixed range of leaves never changes, so the cache stays valid.
    """

    def __init__(self) -> None:
        self._leaves: list[bytes] = []
        self._cache: dict[tuple[int, int], bytes] = {}

    def __len__(self) -> int:
        return len(self._leaves)

    def append_leaf_hash(self, h: bytes) -> int:
        """Append a leaf hash and return its index."""
        if len(h) != HASH_SIZE:
            raise ValueError("leaf hash must be 32 bytes")
        self._leaves.append(h)
        return len(self._leaves) - 1

    def leaf(self, index: int) -> bytes:
        return self._leaves[index]

    def _mth(self, start: int, end: int) -> bytes:
        n = end - start
        if n == 0:
            return empty_root()
        if n == 1:
            return self._leaves[start]
        key = (start, end)
        cached = self._cache.get(key)
        if cached is not None:
            return cached
        k = _split(n)
        value = node_hash(self._mth(start, start + k), self._mth(start + k, end))
        self._cache[key] = value
        return value

    def root(self, size: int | None = None) -> bytes:
        """Root of the first `size` leaves (default: the whole tree)."""
        size = len(self._leaves) if size is None else size
        if not 0 <= size <= len(self._leaves):
            raise ValueError("size out of range")
        return self._mth(0, size)

    def inclusion_proof(self, index: int, size: int | None = None) -> list[bytes]:
        """Audit path for leaf `index` in the tree of the first `size` leaves."""
        size = len(self._leaves) if size is None else size
        if not 0 <= index < size <= len(self._leaves):
            raise ValueError("index or size out of range")
        return self._path(index, 0, size)

    def _path(self, m: int, start: int, end: int) -> list[bytes]:
        n = end - start
        if n == 1:
            return []
        k = _split(n)
        if m < k:
            return self._path(m, start, start + k) + [self._mth(start + k, end)]
        return self._path(m - k, start + k, end) + [self._mth(start, start + k)]

    def consistency_proof(self, old_size: int, new_size: int | None = None) -> list[bytes]:
        """Proof that the tree of `old_size` leaves is a prefix of `new_size`."""
        new_size = len(self._leaves) if new_size is None else new_size
        if not 0 <= old_size <= new_size <= len(self._leaves):
            raise ValueError("sizes out of range")
        if old_size == 0 or old_size == new_size:
            return []
        return self._subproof(old_size, 0, new_size, True)

    def _subproof(self, m: int, start: int, end: int, complete: bool) -> list[bytes]:
        n = end - start
        if m == n:
            return [] if complete else [self._mth(start, end)]
        k = _split(n)
        if m <= k:
            return self._subproof(m, start, start + k, complete) + [self._mth(start + k, end)]
        return self._subproof(m - k, start + k, end, False) + [self._mth(start, start + k)]


def verify_inclusion(
    leaf: bytes, index: int, size: int, proof: Sequence[bytes], root: bytes
) -> bool:
    """RFC 9162 section 2.1.3.2."""
    if not 0 <= index < size:
        return False
    fn, sn, r = index, size - 1, leaf
    for p in proof:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            r = node_hash(p, r)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            r = node_hash(r, p)
        fn >>= 1
        sn >>= 1
    return sn == 0 and r == root


def verify_consistency(
    old_size: int, new_size: int, old_root: bytes, new_root: bytes, proof: Sequence[bytes]
) -> bool:
    """RFC 9162 section 2.1.4.2."""
    if old_size > new_size:
        return False
    if old_size == 0:
        return len(proof) == 0
    if old_size == new_size:
        return len(proof) == 0 and old_root == new_root
    if len(proof) == 0:
        return False
    path = list(proof)
    if old_size & (old_size - 1) == 0:  # exact power of two
        path = [old_root] + path
    fn, sn = old_size - 1, new_size - 1
    while fn & 1:
        fn >>= 1
        sn >>= 1
    fr = sr = path[0]
    for c in path[1:]:
        if sn == 0:
            return False
        if fn & 1 or fn == sn:
            fr = node_hash(c, fr)
            sr = node_hash(c, sr)
            if not fn & 1:
                while not fn & 1 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = node_hash(sr, c)
        fn >>= 1
        sn >>= 1
    return fr == old_root and sr == new_root and sn == 0
