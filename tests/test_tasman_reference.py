# SPDX-License-Identifier: MIT-0
import json
from pathlib import Path
import unittest

import tasman_reference as ref


class TasmanReferenceTests(unittest.TestCase):
    def test_golden(self):
        self.assertEqual(json.loads((Path(__file__).parent / "vectors/tasman-v1.json").read_text()), ref.vectors())

    def test_field(self):
        for a in range(1, 256):
            self.assertEqual(ref.mul(a, ref.inverse(a)), 1)
        self.assertNotEqual(ref.profile(0), ref.profile(1))


if __name__ == "__main__":
    unittest.main()
