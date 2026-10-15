"""Witnesses: independent parties that cosign the ledger's tree heads.

A witness only cosigns a new tree head if the log proves that it was built by
appending to the last tree head the witness saw. One honest witness is enough
to catch a log that rewrites history. Comparing cosigned tree heads across
witnesses catches a log that shows different histories to different people
(a split view).
"""

from __future__ import annotations

from dataclasses import dataclass

from .crypto import Signer, canonical, verify
from .ledger import SignedTreeHead, verify_sth
from .merkle import verify_consistency


class WitnessAlarm(Exception):
    """Raised when a witness sees evidence that the log misbehaved."""


@dataclass(frozen=True)
class Cosignature:
    witness_name: str
    witness_key_id: str
    sth: SignedTreeHead
    signature: bytes

    def message(self) -> bytes:
        return canonical({"type": "cosignature", "sth": self.sth.message().decode()})


class Witness:
    def __init__(self, name: str, log_public_key) -> None:
        self.signer = Signer(name)
        self.name = name
        self.log_public_key = log_public_key
        self.last: SignedTreeHead | None = None

    def observe(self, sth: SignedTreeHead, consistency_proof: list[bytes]) -> Cosignature:
        """Verify a new tree head against the last one seen, then cosign it."""
        if not verify_sth(sth, self.log_public_key):
            raise WitnessAlarm(f"{self.name}: bad log signature")
        if self.last is not None:
            old = self.last
            if sth.tree_size < old.tree_size:
                raise WitnessAlarm(f"{self.name}: log rolled back from {old.tree_size} to {sth.tree_size}")
            if not verify_consistency(
                old.tree_size, sth.tree_size, old.root_hash, sth.root_hash, consistency_proof
            ):
                raise WitnessAlarm(
                    f"{self.name}: tree of size {sth.tree_size} is not an extension of size {old.tree_size}"
                )
        self.last = sth
        unsigned = Cosignature(self.name, self.signer.key_id, sth, b"")
        return Cosignature(self.name, self.signer.key_id, sth, self.signer.sign(unsigned.message()))


def verify_cosignature(cosig: Cosignature, witness_public_key) -> bool:
    return verify(witness_public_key, cosig.signature, cosig.message())


def find_split_view(cosignatures: list[Cosignature]) -> list[tuple[Cosignature, Cosignature]]:
    """Return pairs of cosigned tree heads with the same size but different roots."""
    conflicts = []
    by_size: dict[int, Cosignature] = {}
    for c in cosignatures:
        seen = by_size.get(c.sth.tree_size)
        if seen is None:
            by_size[c.sth.tree_size] = c
        elif seen.sth.root_hash != c.sth.root_hash:
            conflicts.append((seen, c))
    return conflicts


def is_trusted(
    sth: SignedTreeHead, cosignatures: list[Cosignature], keys: dict[str, object], quorum: int
) -> bool:
    """Trust a tree head only with `quorum` valid cosignatures on it from distinct known witnesses."""
    valid = {
        c.witness_name
        for c in cosignatures
        if c.sth.message() == sth.message()
        and c.witness_name in keys
        and verify_cosignature(c, keys[c.witness_name])
    }
    return len(valid) >= quorum
