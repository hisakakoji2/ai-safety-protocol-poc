"""Lottery audit: pick actions for deep audit with public randomness.

The audit probability of an action depends only on what is already fixed in
the ledger (its declared impact), and the random draw uses a public beacon
value that is published only after the period's tree head is cosigned. So a
company cannot know in advance which actions will be audited.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass

from .ledger import Action

DEFAULT_CAP = 1_000_000  # yen: actions with at least this impact are always audited
DEFAULT_MIN_PROBABILITY = 0.001


def audit_probability(
    declared_impact: int, cap: int = DEFAULT_CAP, p_min: float = DEFAULT_MIN_PROBABILITY
) -> float:
    """p = impact / cap, between p_min and 1.

    With honest declarations (damage <= declared impact) the fine
    damage / p never exceeds max(cap, damage): actions below `cap` are fined
    at most `cap`, and actions at or above `cap` are always audited and fined
    exactly their damage, with no multiplier.
    """
    if declared_impact < 0:
        raise ValueError("impact must be non-negative")
    return min(1.0, max(p_min, declared_impact / cap))


def lottery_draw(beacon: bytes, leaf_hash: bytes) -> float:
    """A uniform number in [0, 1) that anyone can recompute from public data."""
    digest = hashlib.sha256(beacon + leaf_hash).digest()
    return int.from_bytes(digest, "big") / 2**256


def is_selected(beacon: bytes, leaf_hash: bytes, p: float) -> bool:
    return lottery_draw(beacon, leaf_hash) < p


@dataclass(frozen=True)
class Finding:
    """Result of auditing one action."""

    violation: bool
    damage: int
    reason: str
    max_penalty: bool = False  # breaks the protocol itself: charge the maximum fine


class Auditor:
    """An expert (human plus AI) who audits selected actions.

    `true_detection_rate` is the chance of catching a real violation. It is
    unknown to the protocol, which estimates it with canaries.
    """

    def __init__(self, name: str, true_detection_rate: float, rng: random.Random) -> None:
        if not 0 < true_detection_rate <= 1:
            raise ValueError("detection rate must be in (0, 1]")
        self.name = name
        self.true_detection_rate = true_detection_rate
        self.rng = rng

    def audit(self, action: Action | None, commitment: str) -> Finding:
        # A company that cannot open its commitment is treated as a violation.
        if action is None or not action.opens(commitment):
            return Finding(True, 0, "commitment not opened", max_penalty=True)
        content = action.content
        true_impact = int(content.get("true_impact", action.declared_impact))
        if true_impact > action.declared_impact:
            # Under-declaring impact lowers the audit chance, so it breaks the protocol itself.
            return Finding(True, 0, "impact under-declared", max_penalty=True)
        if content.get("violation"):
            if self.rng.random() < self.true_detection_rate:
                return Finding(True, int(content.get("damage", 0)), "violation detected")
            return Finding(False, 0, "violation missed")
        return Finding(False, 0, "clean")

    def audit_canary(self) -> bool:
        """Audit a planted test violation. Returns True if it was caught."""
        return self.rng.random() < self.true_detection_rate


def estimate_detection_rate(auditor: Auditor, n_canaries: int) -> float:
    """Plant `n_canaries` fake violations and measure how many are caught."""
    if n_canaries <= 0:
        raise ValueError("need at least one canary")
    caught = sum(auditor.audit_canary() for _ in range(n_canaries))
    # Never return 0: a fine formula divides by this rate.
    return max(caught, 1) / n_canaries
