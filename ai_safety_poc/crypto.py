"""Small helpers for Ed25519 signatures and canonical encoding."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def canonical(obj: Any) -> bytes:
    """Deterministic JSON encoding used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class Signer:
    """An Ed25519 key pair with a short, stable identifier."""

    def __init__(self, name: str, private_key: Ed25519PrivateKey | None = None) -> None:
        self.name = name
        self._key = private_key or Ed25519PrivateKey.generate()
        self.public_key = self._key.public_key()
        raw = self.public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self.key_id = hashlib.sha256(raw).hexdigest()[:16]

    def sign(self, message: bytes) -> bytes:
        return self._key.sign(message)


def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
    try:
        public_key.verify(signature, message)
        return True
    except InvalidSignature:
        return False
