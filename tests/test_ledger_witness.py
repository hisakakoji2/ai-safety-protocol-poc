import unittest

from ai_safety_poc.crypto import canonical
from ai_safety_poc.ledger import Action, Ledger, verify_entry_in_sth, verify_receipt, verify_sth
from ai_safety_poc.merkle import leaf_hash
from ai_safety_poc.witness import Witness, WitnessAlarm, find_split_view, is_trusted


def action(i: int, content=None) -> Action:
    return Action("agent", i, 10_000, content or {"op": i})


class LedgerTest(unittest.TestCase):
    def test_receipts_tree_heads_and_inclusion(self):
        ledger = Ledger()
        receipts = [ledger.append(action(i).entry()) for i in range(7)]
        sth = ledger.signed_tree_head()
        self.assertTrue(verify_sth(sth, ledger.signer.public_key))
        for r in receipts:
            self.assertTrue(verify_receipt(r, ledger.signer.public_key))
            entry = ledger.entries[r.index]
            proof = ledger.inclusion_proof(r.index, sth.tree_size)
            self.assertTrue(verify_entry_in_sth(entry, r.index, sth, proof))

    def test_commitment_hides_and_binds_content(self):
        a = action(1, {"op": "secret"})
        self.assertNotIn("secret", str(a.entry()))
        self.assertTrue(a.opens(a.entry()["commitment"]))
        other = Action("agent", 1, 10_000, {"op": "different"}, salt=a.salt)
        self.assertFalse(other.opens(a.entry()["commitment"]))


class WitnessTest(unittest.TestCase):
    def test_witness_cosigns_honest_growth(self):
        ledger = Ledger()
        w = Witness("w", ledger.signer.public_key)
        last = 0
        for step in range(5):
            for i in range(3):
                ledger.append(action(step * 3 + i).entry())
            sth = ledger.signed_tree_head()
            w.observe(sth, ledger.consistency_proof(last, sth.tree_size))
            last = sth.tree_size

    def test_witness_catches_rewrite(self):
        ledger = Ledger()
        w = Witness("w", ledger.signer.public_key)
        for i in range(6):
            ledger.append(action(i).entry())
        old = ledger.signed_tree_head()
        w.observe(old, [])
        ledger.tree._leaves[2] = leaf_hash(canonical(action(2, {"op": "edited"}).entry()))
        ledger.tree._cache.clear()
        ledger.append(action(6).entry())
        new = ledger.signed_tree_head()
        with self.assertRaises(WitnessAlarm):
            w.observe(new, ledger.consistency_proof(old.tree_size, new.tree_size))

    def test_witness_catches_rollback_and_bad_signature(self):
        ledger = Ledger()
        w = Witness("w", ledger.signer.public_key)
        ledger.append(action(0).entry())
        small = ledger.signed_tree_head()
        ledger.append(action(1).entry())
        big = ledger.signed_tree_head()
        w.observe(big, [])
        with self.assertRaises(WitnessAlarm):
            w.observe(small, [])
        impostor = Ledger()
        impostor.append(action(0).entry())
        with self.assertRaises(WitnessAlarm):
            Witness("v", ledger.signer.public_key).observe(impostor.signed_tree_head(), [])

    def test_split_view_and_quorum(self):
        a_view, b_view = Ledger(), Ledger()
        b_view.signer, b_view.log_id = a_view.signer, a_view.log_id
        a_view.append(action(0, {"op": "real"}).entry())
        b_view.append(action(0, {"op": "fake"}).entry())
        wa = Witness("a", a_view.signer.public_key)
        wb = Witness("b", a_view.signer.public_key)
        ca = wa.observe(a_view.signed_tree_head(), [])
        cb = wb.observe(b_view.signed_tree_head(), [])
        self.assertEqual(len(find_split_view([ca, cb])), 1)

        keys = {"a": wa.signer.public_key, "b": wb.signer.public_key}
        self.assertTrue(is_trusted(ca.sth, [ca], keys, quorum=1))
        self.assertFalse(is_trusted(ca.sth, [ca, cb], keys, quorum=2))


if __name__ == "__main__":
    unittest.main()
