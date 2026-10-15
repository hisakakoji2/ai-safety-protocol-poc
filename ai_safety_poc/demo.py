"""Run the whole protocol and show that it does what the design claims.

    python -m ai_safety_poc.demo

Part 1  The fine formula, with the worked example from the design document.
Part 2  Economics: an honest and a cheating company over many audit periods.
Part 3  A ledger operator who rewrites history is caught by a witness.
Part 4  A ledger operator who shows different histories is caught by comparing cosignatures.
"""

from __future__ import annotations

import argparse
import random

from .audit import Auditor, audit_probability, estimate_detection_rate
from .crypto import canonical
from .merkle import leaf_hash
from .fines import estimate_total_damage, fine, max_fine, premium
from .ledger import Action, Ledger
from .protocol import Company, Protocol
from .witness import Witness, WitnessAlarm, find_split_view

CAP = 1_000_000


def yen(x: float) -> str:
    return f"{x:,.0f} yen"


def part1_formula() -> None:
    print("\n=== Part 1. The fine formula ===")
    impact = damage = 10_000
    p = audit_probability(impact, CAP)
    f = fine(damage, p, 1.0)
    print(f"Action with impact {yen(impact)} -> audit probability {p:.1%}")
    print(f"A detected violation causing {yen(damage)} is fined {yen(f)}")
    print(f"Expected fine = {p:.1%} x {yen(f)} = {yen(p * f)}  (= the damage)")
    print(f"Largest fine for an honestly declared action below {yen(CAP)}: {yen(max_fine(CAP, 1.0))}")
    print(f"Actions of {yen(CAP)} or more are always audited and fined exactly their damage")


def random_impact(rng: random.Random) -> int:
    # Log-uniform between 1,000 and 2,000,000 yen: many small actions, a few large ones.
    return int(10 ** rng.uniform(3, 6.3))


def part2_economics(periods: int, actions: int, violation_rate: float, detection: float, seed: int) -> None:
    print("\n=== Part 2. Does cheating pay? ===")
    for corrected in (True, False):
        rng = random.Random(seed)
        auditor = Auditor("auditor", detection, rng)
        d_hat = estimate_detection_rate(auditor, 2_000) if corrected else 1.0
        ledger = Ledger()
        witnesses = [Witness(n, ledger.signer.public_key) for n in ("university", "insurer", "rival-lab")]
        proto = Protocol(ledger, witnesses, auditor, d_hat, CAP, quorum=2)
        honest, cheater = Company("honest"), Company("cheater")
        true_damage = gain = estimated = 0.0

        for period in range(periods):
            for _ in range(actions):
                impact = random_impact(rng)
                proto.submit(honest, Action("agent-h", len(honest.actions), impact, {"op": "work"}))
                content = {"op": "work"}
                if rng.random() < violation_rate:
                    damage = int(impact * rng.uniform(0.2, 1.0))
                    content = {"op": "work", "violation": True, "damage": damage}
                    true_damage += damage
                    gain += damage  # the cheater saves what it pushes onto others
                proto.submit(cheater, Action("agent-c", len(cheater.actions), impact, content))
            report = proto.close_period([honest, cheater], f"round-{period}")
            estimated += estimate_total_damage(report.violations, d_hat)

        label = "with canary-corrected detection rate" if corrected else "WITHOUT correcting for missed violations"
        print(f"\n-- Fines {label} (true detection {detection:.0%}, estimated {d_hat:.1%})")
        print(f"   {periods} periods x {actions} actions per company")
        print(f"   Honest company paid in fines:   {yen(honest.fines_paid)}")
        print(f"   Cheater gained from violations: {yen(gain)}")
        print(f"   Cheater paid in fines:          {yen(cheater.fines_paid)}")
        print(f"   Cheater net gain:               {yen(gain - cheater.fines_paid)}"
              f"  ({(gain - cheater.fines_paid) / gain:+.0%} of gain)")
        print(f"   True total damage:              {yen(true_damage)}")
        print(f"   Estimated from audits only:     {yen(estimated)}  ({estimated / true_damage - 1:+.1%})")
        print(f"   Suggested premium per period:   {yen(premium(estimated / periods))}")


def part3_rewrite() -> None:
    print("\n=== Part 3. The ledger operator rewrites history ===")
    ledger = Ledger()
    witness = Witness("university", ledger.signer.public_key)
    for i in range(8):
        ledger.append(Action("agent", i, 50_000, {"op": i}).entry())
    sth = ledger.signed_tree_head()
    witness.observe(sth, [])
    print(f"Witness cosigned tree of size {sth.tree_size}")

    # The operator quietly replaces entry 3 and keeps appending.
    forged = Action("agent", 3, 50_000, {"op": "edited"}).entry()
    ledger.tree._leaves[3] = leaf_hash(canonical(forged))
    ledger.tree._cache.clear()
    ledger.entries[3] = forged
    for i in range(8, 12):
        ledger.append(Action("agent", i, 50_000, {"op": i}).entry())
    new_sth = ledger.signed_tree_head()
    try:
        witness.observe(new_sth, ledger.consistency_proof(sth.tree_size, new_sth.tree_size))
        print("NOT detected (this should not happen)")
    except WitnessAlarm as alarm:
        print(f"Detected: {alarm}")


def part4_split_view() -> None:
    print("\n=== Part 4. The ledger operator shows two different histories ===")
    shown_to_a = Ledger()
    shown_to_b = Ledger()
    shown_to_b.signer, shown_to_b.log_id = shown_to_a.signer, shown_to_a.log_id  # same operator key
    for i in range(5):
        entry = Action("agent", i, 50_000, {"op": i}).entry()
        shown_to_a.append(entry)
        shown_to_b.append(entry)
    shown_to_a.append(Action("agent", 5, 50_000, {"op": "real"}).entry())
    shown_to_b.append(Action("agent", 5, 50_000, {"op": "fake"}).entry())

    a = Witness("insurer", shown_to_a.signer.public_key)
    b = Witness("rival-lab", shown_to_a.signer.public_key)
    cosigs = [a.observe(shown_to_a.signed_tree_head(), []), b.observe(shown_to_b.signed_tree_head(), [])]
    print("Each witness alone sees a valid, consistent log and cosigns it.")
    conflicts = find_split_view(cosigs)
    for x, y in conflicts:
        print(f"Detected when cosignatures are compared: size {x.sth.tree_size} has two roots "
              f"({x.witness_name}: {x.sth.root_hash.hex()[:12]}..., {y.witness_name}: {y.sth.root_hash.hex()[:12]}...)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--periods", type=int, default=40)
    parser.add_argument("--actions", type=int, default=1_000, help="actions per company per period")
    parser.add_argument("--violation-rate", type=float, default=0.05)
    parser.add_argument("--detection", type=float, default=0.7, help="auditor's true detection rate")
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args()

    part1_formula()
    part2_economics(args.periods, args.actions, args.violation_rate, args.detection, args.seed)
    part3_rewrite()
    part4_split_view()


if __name__ == "__main__":
    main()
