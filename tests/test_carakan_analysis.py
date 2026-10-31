# SPDX-License-Identifier: MIT-0
import unittest

from analyze_carakan import entropy, total_variation, positional_metrics


class CarakanAnalysisTests(unittest.TestCase):
    def test_entropy_and_units(self):
        self.assertEqual(entropy([1, 1]), 1)
        self.assertEqual(entropy([3, 0, 0]), 0)
        self.assertEqual(entropy([1] * 256), 8)

    def test_variation_and_scale(self):
        self.assertEqual(total_variation([5, 5], [8192, 8192]), 0)
        self.assertEqual(total_variation([10, 0], [0, 100]), 1)

    def test_empty_rejected(self):
        with self.assertRaises(ValueError):
            entropy([0, 0])
        with self.assertRaises(ValueError):
            total_variation([0], [1])

    def test_positional_counts_and_coarse_metric_limit(self):
        data = bytes(16) + bytes([1]) * 16
        wire = {"Bytes": 32, "Packets": 1, "PositionBins": [[0] * 256 for _ in range(16)],
                "Prefix": [[0] * 256 for _ in range(8)], "Suffix": [[0] * 256 for _ in range(8)],
                "UnrotatedLast": [0] * 256, "Transitions": [[0] * 16 for _ in range(16)]}
        wire["UnrotatedLast"][1] = 1
        for i, b in enumerate(data):
            wire["PositionBins"][i // 2][b] += 1
            if i < 8:
                wire["Prefix"][i][b] += 1
            if 31 - i < 8:
                wire["Suffix"][31 - i][b] += 1
            if i:
                wire["Transitions"][data[i - 1] >> 4][b >> 4] += 1
        group = [{"KeyIndex": 0, "C2S": wire, "S2C": wire}]
        spectrum = [8192, 8192] + [0] * 254
        result = positional_metrics(group, {0: spectrum})
        self.assertEqual(result["relative_position_bin_mean_tv"], [.5] * 16)
        self.assertEqual(result["same_packets_unrotated_last_mean_tv"], .5)
        # Upper-nibble bins merge symbols 0 and 1: this coarse statistic can
        # miss an obviously dependent stream, so never label it an IID proof.
        self.assertEqual(result["coarse_adjacent_joint_tv_to_empirical_product_mean"], 0)
        self.assertTrue(result["joint_metric_is_not_a_general_independence_test"])
        wire["PositionBins"][0][0] += 1
        with self.assertRaises(ValueError):
            positional_metrics(group, {0: spectrum})

    def test_legacy_captures_do_not_invent_positional_evidence(self):
        self.assertEqual(positional_metrics([{"C2S": {}}], {}), {"positional_capture_available": False})


if __name__ == "__main__":
    unittest.main()
