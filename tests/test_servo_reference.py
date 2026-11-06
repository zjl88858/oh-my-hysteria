# SPDX-License-Identifier: MIT-0

import json
from pathlib import Path
import unittest

from servo_reference import Stream, chacha_block, hchacha, vectors


class ServoReferenceTests(unittest.TestCase):
    def test_chacha_rfc8439_zero_block(self):
        self.assertEqual(chacha_block(bytes(32)).hex(),
                         "76b8e0ada0f13d90405d6ae55386bd28bdd219b8a08ded1aa836efcc8b770dc7da"
                         "41597c5157488d7724e03fb8d84a376a43b8f41518a11cc387b669b2ee6586")

    def test_hchacha_published_vector(self):
        # draft-irtf-cfrg-xchacha-03 section 2.2.1
        self.assertEqual(hchacha(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex(),
                         "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")

    def test_frozen_vectors(self):
        path = Path(__file__).parent / "vectors/servo-v1.json"
        self.assertEqual(vectors(), json.loads(path.read_text(encoding="utf-8")))

    def test_rejection_mapping_and_bound(self):
        s = Stream(bytes(32))
        # 65535 rejected for n=7; 14 is then accepted as 0 (big-endian).
        s.stream = iter([255, 255, 0, 14])
        self.assertEqual(s.below(7), 0)
        s.stream = iter([255, 255] * 128)
        with self.assertRaises(ValueError):
            s.below(7)


if __name__ == "__main__":
    unittest.main()
