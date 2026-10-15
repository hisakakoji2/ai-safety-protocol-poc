"""The fine formula and the link to insurance pricing.

fine = damage / (audit probability x detection rate)

A violation is audited with probability p and, if audited, caught with
probability d. Its expected fine is therefore p x d x damage / (p x d) =
damage: on average the company pays exactly the harm it caused, so cheating
does not pay (Becker 1968).

The same weights give an unbiased estimate of total damage across all actions,
audited or not (Horvitz-Thompson), which is the basis for an insurance premium.
"""

from __future__ import annotations

from dataclasses import dataclass


def fine(damage: float, p: float, detection_rate: float) -> float:
    if not 0 < p <= 1 or not 0 < detection_rate <= 1:
        raise ValueError("p and detection_rate must be in (0, 1]")
    return damage / (p * detection_rate)


def max_fine(cap: int, detection_rate: float) -> float:
    """Largest fine for an honestly declared action whose damage is below `cap`.

    Actions at or above `cap` are always audited and fined their damage
    (divided by the detection rate), which can be larger; that part is
    ordinary liability that insurance can cover.
    """
    return cap / detection_rate


@dataclass(frozen=True)
class AuditedViolation:
    damage: float
    p: float


def estimate_total_damage(violations: list[AuditedViolation], detection_rate: float) -> float:
    """Horvitz-Thompson estimate of total damage over all actions in a period."""
    return sum(v.damage / (v.p * detection_rate) for v in violations)


def premium(expected_loss_per_period: float, loading: float = 0.2) -> float:
    """A simple premium: expected loss plus a loading for costs and margin."""
    return expected_loss_per_period * (1 + loading)
