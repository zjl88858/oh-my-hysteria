# SPDX-License-Identifier: MIT-0
import json
from pathlib import Path
import unittest
import mariner_reference as ref


class MarinerReferenceTests(unittest.TestCase):
    def test_golden(self):
        expected = json.loads((Path(__file__).parent / 'vectors/mariner-v1.json').read_text())
        self.assertEqual(expected, ref.vectors())

    def test_lengths(self):
        counts = 0
        for r in range(16, 21):
            p = dict(density=r)
            cap = 64 * 1232 // (64 + r) - 62
            for fragment in range(1, cap + 1):
                n = 62 + fragment
                for delta in range(min(3, 1232 - ref.base(p, n)) + 1):
                    length = ref.base(p, n) + delta
                    padding = 64 * length // (64 + r) - n
                    self.assertTrue(0 <= padding <= 3)
                    counts += 1
        self.assertGreater(counts, 17000)
        self.assertEqual(83 - ref.base(dict(density=16), 63), 4)

    def test_affine_rejection(self):
        self.assertTrue(ref.affine(list(range(256))))
        self.assertTrue(ref.affine([x ^ 0x5a for x in range(256)]))
        self.assertTrue(all(not ref.affine(t) for t in ref.profile()['tables']))


if __name__ == '__main__':
    unittest.main()
