import unittest

from ai_safety_poc.merkle import (
    MerkleTree,
    empty_root,
    leaf_hash,
    node_hash,
    verify_consistency,
    verify_inclusion,
)


def build(n: int) -> MerkleTree:
    t = MerkleTree()
    for i in range(n):
        t.append_leaf_hash(leaf_hash(f"leaf-{i}".encode()))
    return t


class MerkleTest(unittest.TestCase):
    def test_small_roots_match_definition(self):
        t = build(3)
        a, b, c = (t.leaf(i) for i in range(3))
        self.assertEqual(t.root(0), empty_root())
        self.assertEqual(t.root(1), a)
        self.assertEqual(t.root(2), node_hash(a, b))
        self.assertEqual(t.root(3), node_hash(node_hash(a, b), c))

    def test_inclusion_proofs_for_every_leaf(self):
        t = build(40)
        for n in range(1, 41):
            root = t.root(n)
            for i in range(n):
                proof = t.inclusion_proof(i, n)
                self.assertTrue(verify_inclusion(t.leaf(i), i, n, proof, root))
                self.assertFalse(verify_inclusion(leaf_hash(b"other"), i, n, proof, root))

    def test_consistency_proofs_for_every_pair(self):
        t = build(40)
        for n in range(1, 41):
            for m in range(0, n + 1):
                proof = t.consistency_proof(m, n)
                self.assertTrue(verify_consistency(m, n, t.root(m), t.root(n), proof))
                if 0 < m < n:
                    self.assertFalse(verify_consistency(m, n, leaf_hash(b"x"), t.root(n), proof))

    def test_rewritten_history_is_not_consistent(self):
        honest = build(10)
        forged = build(10)
        forged._leaves[3] = leaf_hash(b"edited")
        forged._cache.clear()
        for i in range(10, 16):
            forged.append_leaf_hash(leaf_hash(f"leaf-{i}".encode()))
        proof = forged.consistency_proof(10, 16)
        self.assertFalse(verify_consistency(10, 16, honest.root(10), forged.root(16), proof))


if __name__ == "__main__":
    unittest.main()
