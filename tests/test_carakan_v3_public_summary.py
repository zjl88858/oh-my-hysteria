# SPDX-License-Identifier: MIT-0
"""Synthetic FEC fingerprint joins: no sockets or public connections."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).parent / "network"))
from carakan_v3_public_summary import direction


class V3FingerprintTests(unittest.TestCase):
    def records(self, indices, delivered=True, late_data=None):
        sender = {"Stats": {"MaxFragmentPayload": 250}, "Events": [
            {"Layer": "outer", "Op": "write", "Digest": str(i), "Group": 1, "Bytes": 100, "AtUS": i}
            for i in range(7)
        ] + [{"Layer": "inner", "Op": "write", "Digest": "inner", "Group": 1, "Bytes": 1200, "AtUS": 9}]}
        receiver = {"Stats": {}, "Events": [
            {"Layer": "outer", "Op": "read", "Digest": str(i), "Group": 0, "Bytes": 100, "AtUS": 10 + i}
            for i in indices
        ]}
        if delivered:
            receiver["Events"].append({"Layer": "inner", "Op": "read", "Digest": "inner", "Group": 0, "Bytes": 1200, "AtUS": 30})
        if late_data is not None:
            receiver["Events"].append({"Layer": "outer", "Op": "read", "Digest": str(late_data), "Group": 0, "Bytes": 100, "AtUS": 40})
        captures = [{"direction": "server_to_client", "digest": str(i)} for i in range(7)]
        return sender, receiver, captures

    def join(self, **kwargs):
        return direction(*self.records(**kwargs), "server_to_client")

    def test_data_only_delivery_does_not_need_all_repairs(self):
        result = self.join(indices=range(5))
        self.assertEqual(result["delivered_inner_groups"], 1)
        self.assertEqual(result["incomplete_wire_but_delivered_groups"], 1)
        self.assertEqual(result["inferred_fec_recovered_groups"], 0)

    def test_repair_recovers_missing_systematic(self):
        result = self.join(indices=(0, 2, 3, 4, 5))
        self.assertEqual(result["inferred_fec_recovered_groups"], 1)
        self.assertEqual(result["inferred_fec_recovered_data_shards"], 1)

    def test_late_data_does_not_erase_recovery_evidence(self):
        result = self.join(indices=(0, 2, 3, 4, 5), late_data=1)
        group = result["groups"][0]
        self.assertEqual(group["data_read_by_trace_end"], 5)
        self.assertEqual(group["data_read_at_delivery"], 4)
        self.assertTrue(group["inferred_fec_recovery_at_delivery"])

    def test_insufficient_shards_remain_undelivered(self):
        result = self.join(indices=(0, 2, 3, 5), delivered=False)
        self.assertEqual(result["delivered_inner_groups"], 0)


if __name__ == "__main__":
    unittest.main()
