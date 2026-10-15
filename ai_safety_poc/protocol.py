"""One audit period of the protocol, end to end.

1. Companies append their actions' fingerprints to the ledger and keep receipts.
2. The period closes: the ledger signs a tree head and witnesses cosign it.
3. A public beacon value is published after the cosigned tree head.
4. The lottery selects actions; companies open the selected ones to the auditor.
5. Detected violations are fined; the results feed the insurance estimate.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .audit import Auditor, audit_probability, is_selected
from .crypto import canonical
from .fines import AuditedViolation, fine, max_fine
from .ledger import Action, Ledger, SignedTreeHead, verify_entry_in_sth
from .merkle import leaf_hash
from .witness import Cosignature, Witness, is_trusted


@dataclass
class Company:
    name: str
    actions: dict[int, Action] = field(default_factory=dict)  # ledger index -> private action
    fines_paid: float = 0.0


@dataclass
class PeriodReport:
    sth: SignedTreeHead
    cosignatures: list[Cosignature]
    beacon: bytes
    selected: int = 0
    findings: list[tuple[str, int, str, float]] = field(default_factory=list)  # company, index, reason, fine
    violations: list[AuditedViolation] = field(default_factory=list)


def public_beacon(round_label: str) -> bytes:
    """Stand-in for a public randomness beacon (for example drand or the NIST beacon)."""
    return hashlib.sha256(f"public-beacon:{round_label}".encode()).digest()


class Protocol:
    def __init__(
        self,
        ledger: Ledger,
        witnesses: list[Witness],
        auditor: Auditor,
        detection_rate_estimate: float,
        cap: int,
        quorum: int,
    ) -> None:
        self.ledger = ledger
        self.witnesses = witnesses
        self.auditor = auditor
        self.d_hat = detection_rate_estimate
        self.cap = cap
        self.quorum = quorum
        self.period_start = 0

    def submit(self, company: Company, action: Action) -> int:
        receipt = self.ledger.append(action.entry())
        company.actions[receipt.index] = action
        return receipt.index

    def close_period(self, companies: list[Company], round_label: str) -> PeriodReport:
        sth = self.ledger.signed_tree_head()
        cosigs = []
        for w in self.witnesses:
            old = w.last.tree_size if w.last else 0
            cosigs.append(w.observe(sth, self.ledger.consistency_proof(old, sth.tree_size)))
        keys = {w.name: w.signer.public_key for w in self.witnesses}
        if not is_trusted(sth, cosigs, keys, self.quorum):
            raise RuntimeError("tree head lacks a witness quorum")

        beacon = public_beacon(round_label)
        report = PeriodReport(sth, cosigs, beacon)
        owner = {i: c for c in companies for i in c.actions}

        for index in range(self.period_start, sth.tree_size):
            entry = self.ledger.entries[index]
            assert verify_entry_in_sth(entry, index, sth, self.ledger.inclusion_proof(index, sth.tree_size))
            p = audit_probability(entry["declared_impact"], self.cap)
            if not is_selected(beacon, leaf_hash(canonical(entry)), p):
                continue
            report.selected += 1
            company = owner[index]
            finding = self.auditor.audit(company.actions.get(index), entry["commitment"])
            if not finding.violation:
                continue
            amount = (
                max_fine(self.cap, self.d_hat)
                if finding.max_penalty
                else fine(finding.damage, p, self.d_hat)
            )
            company.fines_paid += amount
            report.findings.append((company.name, index, finding.reason, amount))
            if not finding.max_penalty:
                report.violations.append(AuditedViolation(finding.damage, p))

        self.period_start = sth.tree_size
        return report
