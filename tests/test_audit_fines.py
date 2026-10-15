import random
import unittest

from ai_safety_poc.audit import (
    Auditor,
    audit_probability,
    estimate_detection_rate,
    is_selected,
    lottery_draw,
)
from ai_safety_poc.fines import AuditedViolation, estimate_total_damage, fine, max_fine
from ai_safety_poc.ledger import Action


class LotteryTest(unittest.TestCase):
    def test_probability_scales_with_impact(self):
        self.assertAlmostEqual(audit_probability(10_000, 1_000_000), 0.01)
        self.assertEqual(audit_probability(5_000_000, 1_000_000), 1.0)
        self.assertEqual(audit_probability(0, 1_000_000, p_min=0.001), 0.001)

    def test_draw_is_reproducible_and_roughly_uniform(self):
        beacon = b"beacon"
        self.assertEqual(lottery_draw(beacon, b"leaf"), lottery_draw(beacon, b"leaf"))
        hits = sum(is_selected(beacon, i.to_bytes(4, "big"), 0.2) for i in range(20_000))
        self.assertAlmostEqual(hits / 20_000, 0.2, delta=0.02)


class FineTest(unittest.TestCase):
    def test_worked_example(self):
        self.assertEqual(fine(10_000, 0.01, 1.0), 1_000_000)
        self.assertEqual(max_fine(1_000_000, 0.5), 2_000_000)

    def test_honest_declaration_bounds_the_fine(self):
        rng = random.Random(1)
        for _ in range(1_000):
            impact = rng.randint(1, 3_000_000)
            damage = rng.randint(0, impact)
            p = audit_probability(impact, 1_000_000)
            # The penalty multiplier only applies below the cap: fine <= max(cap, damage).
            self.assertLessEqual(fine(damage, p, 1.0), max(1_000_000, damage) + 1e-6)

    def test_expected_fine_equals_damage(self):
        rng = random.Random(2)
        p, d, damage, n = 0.05, 0.7, 20_000, 400_000
        paid = sum(fine(damage, p, d) for _ in range(n) if rng.random() < p and rng.random() < d)
        self.assertAlmostEqual(paid / n, damage, delta=damage * 0.05)

    def test_horvitz_thompson_is_unbiased(self):
        rng = random.Random(3)
        totals, estimates = [], []
        for _ in range(300):
            items = [(rng.randint(1_000, 200_000), rng.uniform(0.01, 1.0)) for _ in range(200)]
            totals.append(sum(dmg for dmg, _ in items))
            caught = [AuditedViolation(dmg, p) for dmg, p in items if rng.random() < p * 0.8]
            estimates.append(estimate_total_damage(caught, 0.8))
        self.assertAlmostEqual(sum(estimates) / sum(totals), 1.0, delta=0.03)


class AuditorTest(unittest.TestCase):
    def test_findings(self):
        auditor = Auditor("a", 1.0, random.Random(0))
        clean = Action("x", 0, 10_000, {"op": 1})
        bad = Action("x", 1, 10_000, {"op": 1, "violation": True, "damage": 3_000})
        under = Action("x", 2, 10_000, {"op": 1, "true_impact": 50_000})
        self.assertFalse(auditor.audit(clean, clean.commitment()).violation)
        self.assertEqual(auditor.audit(bad, bad.commitment()).damage, 3_000)
        self.assertTrue(auditor.audit(under, under.commitment()).max_penalty)
        self.assertTrue(auditor.audit(None, clean.commitment()).max_penalty)
        self.assertTrue(auditor.audit(clean, bad.commitment()).max_penalty)

    def test_canaries_estimate_detection_rate(self):
        auditor = Auditor("a", 0.6, random.Random(4))
        self.assertAlmostEqual(estimate_detection_rate(auditor, 10_000), 0.6, delta=0.02)


if __name__ == "__main__":
    unittest.main()
