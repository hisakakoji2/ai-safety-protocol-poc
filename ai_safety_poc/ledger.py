"""The record ledger: an append-only transparency log of AI action fingerprints.

An AI company keeps the full content of each action. Only a commitment
(a salted hash of the content) and the declared impact go into the ledger.
The ledger returns a signed receipt for each entry and, on request, a signed
tree head (STH) that commits to every entry so far.
"""

from __future__ import annotations

import hashlib
import os
import time
from dataclasses import dataclass, field

from .crypto import Signer, canonical, verify
from .merkle import MerkleTree, leaf_hash, verify_inclusion


@dataclass(frozen=True)
class Action:
    """An AI action as the company stores it privately."""

    agent_id: str
    seq: int
    declared_impact: int  # yen at stake, declared before the lottery
    content: dict  # the full action, kept by the company
    salt: bytes = field(default_factory=lambda: os.urandom(16))

    def commitment(self) -> str:
        """Salted hash of the content. Reveals nothing until the company opens it."""
        return hashlib.sha256(self.salt + canonical(self.content)).hexdigest()

    def entry(self) -> dict:
        """What is written to the public ledger."""
        return {
            "agent_id": self.agent_id,
            "seq": self.seq,
            "declared_impact": self.declared_impact,
            "commitment": self.commitment(),
        }

    def opens(self, commitment: str) -> bool:
        """Check that this content matches a published commitment."""
        return self.commitment() == commitment


@dataclass(frozen=True)
class Receipt:
    """Signed promise that an entry was appended at a given index."""

    log_id: str
    index: int
    leaf_hash: bytes
    timestamp: float
    signature: bytes

    def message(self) -> bytes:
        return canonical(
            {
                "type": "receipt",
                "log_id": self.log_id,
                "index": self.index,
                "leaf_hash": self.leaf_hash.hex(),
                "timestamp": self.timestamp,
            }
        )


@dataclass(frozen=True)
class SignedTreeHead:
    """A signed commitment to the first `tree_size` entries of the log."""

    log_id: str
    tree_size: int
    root_hash: bytes
    timestamp: float
    signature: bytes

    def message(self) -> bytes:
        return canonical(
            {
                "type": "sth",
                "log_id": self.log_id,
                "tree_size": self.tree_size,
                "root_hash": self.root_hash.hex(),
                "timestamp": self.timestamp,
            }
        )


class Ledger:
    """A transparency log operator.

    In production this would be a service run by several organisations; here
    it is an in-memory object so the protocol can be run and tested locally.
    """

    def __init__(self, name: str = "ledger") -> None:
        self.signer = Signer(name)
        self.log_id = self.signer.key_id
        self.tree = MerkleTree()
        self.entries: list[dict] = []

    # --- writing -----------------------------------------------------------
    def append(self, entry: dict) -> Receipt:
        lh = leaf_hash(canonical(entry))
        index = self.tree.append_leaf_hash(lh)
        self.entries.append(entry)
        ts = time.time()
        unsigned = Receipt(self.log_id, index, lh, ts, b"")
        return Receipt(self.log_id, index, lh, ts, self.signer.sign(unsigned.message()))

    def signed_tree_head(self) -> SignedTreeHead:
        size = len(self.tree)
        root = self.tree.root(size)
        ts = time.time()
        unsigned = SignedTreeHead(self.log_id, size, root, ts, b"")
        return SignedTreeHead(self.log_id, size, root, ts, self.signer.sign(unsigned.message()))

    # --- proofs --------------------------------------------------------------
    def inclusion_proof(self, index: int, tree_size: int) -> list[bytes]:
        return self.tree.inclusion_proof(index, tree_size)

    def consistency_proof(self, old_size: int, new_size: int) -> list[bytes]:
        return self.tree.consistency_proof(old_size, new_size)


def verify_receipt(receipt: Receipt, log_public_key) -> bool:
    return verify(log_public_key, receipt.signature, receipt.message())


def verify_sth(sth: SignedTreeHead, log_public_key) -> bool:
    return verify(log_public_key, sth.signature, sth.message())


def verify_entry_in_sth(entry: dict, index: int, sth: SignedTreeHead, proof: list[bytes]) -> bool:
    """Check that an entry sits at `index` in the tree an STH commits to."""
    return verify_inclusion(leaf_hash(canonical(entry)), index, sth.tree_size, proof, sth.root_hash)
