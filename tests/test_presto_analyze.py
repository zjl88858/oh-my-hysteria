# SPDX-License-Identifier: MIT-0
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("presto_analyze", Path(__file__).parent / "network" / "presto_analyze.py")
analyze = importlib.util.module_from_spec(spec)
spec.loader.exec_module(analyze)


class PrestoAnalysisTests(unittest.TestCase):
    def test_density_and_distance(self):
        self.assertEqual(analyze.density([0, 0, 1], 2), [2 / 3, 1 / 3])
        self.assertEqual(analyze.density([], 2), [0, 0])
        self.assertEqual(analyze.distance([1, 0], [0, 1]), 2)
        with self.assertRaises(ValueError):
            analyze.distance([1], [1, 2])

    def test_no_private_metadata_features(self):
        events = [{"length": 500 + i, "at_ns": i * 100000} for i in range(16)]
        record = {"C2S": events, "S2C": events, "key_index": 0, "ClientStats": {"secret": 1}}
        expected = analyze.feature_groups(record)
        record.update(key_index=15, ClientStats={"secret": 999}, password="not a feature")
        self.assertEqual(expected, analyze.feature_groups(record))
        self.assertEqual(len(expected["length"]), 64)
        self.assertEqual(len(expected["transition"]), 128)

    def test_centroid_holdout(self):
        samples = [{"key": key, "session": session, "v": [float(key)]} for key in range(16) for session in range(8)]
        result = analyze.classify(samples, "v")
        self.assertEqual(result["total"], 64)
        self.assertEqual(result["accuracy"], 1)
        self.assertTrue(all(p["session"] >= 4 for p in result["predictions"]))


if __name__ == "__main__":
    unittest.main()
