# SPDX-License-Identifier: MIT-0
"""Offline synthetic checks for the diagnostic fingerprint join, not networking."""
import importlib.util
from pathlib import Path
import unittest


spec = importlib.util.spec_from_file_location(
    "carakan_public_diagnosis", Path(__file__).parent / "network/carakan_public_diagnosis.py"
)
diagnosis = importlib.util.module_from_spec(spec)
spec.loader.exec_module(diagnosis)


class FingerprintJoinTests(unittest.TestCase):
    def records(self, received=("a", "b"), inner_delivered=True):
        sender = {"Events": [
            {"Layer": "outer", "Op": "write", "Digest": digest, "Group": 1, "Bytes": 100, "AtUS": i}
            for i, digest in enumerate(("a", "b"))
        ] + [{"Layer": "inner", "Op": "write", "Digest": "inner", "Group": 1, "Bytes": 1200, "AtUS": 2}]}
        names = ("ReceivedPackets", "DeliveredBytes", "Reassembled", "AuthDrops", "MalformedDrops",
                 "RateDrops", "ReplayDrops", "ResourceDrops", "FreshnessDrops", "ExpiredAssemblies", "EvictedAssemblies")
        receiver = {"Role": "client", "ConnectSeconds": 1, "Stats": dict.fromkeys(names, 0), "Events": [
            {"Layer": "outer", "Op": "read", "Digest": digest, "Group": 0, "Bytes": 100, "AtUS": i + 10}
            for i, digest in enumerate(received)
        ]}
        if inner_delivered:
            receiver["Events"].append({"Layer": "inner", "Op": "read", "Digest": "inner", "Group": 0, "Bytes": 1200, "AtUS": 13})
        capture = [{"direction": "server_to_client", "digest": digest} for digest in ("a", "b")]
        return sender, receiver, capture

    def check(self, **kwargs):
        return diagnosis.direction(*self.records(**kwargs), "server_to_client")

    def test_all_received_and_delivered(self):
        row = self.check()
        self.assertEqual(row["delivered_inner_groups"], 1)
        self.assertEqual(row["incomplete_outer_groups"], 0)

    def test_missing_outer_fragment_not_decoder_failure(self):
        row = self.check(received=("a",), inner_delivered=False)
        self.assertEqual(row["sender_fingerprints_seen_at_vps_interface"], 2)
        self.assertEqual(row["sender_fingerprints_read_at_receiver"], 1)
        self.assertEqual(row["groups"][0]["missing_receiver_fragment_ordinals_zero_based"], [1])
        self.assertEqual(row["incomplete_outer_groups"], 1)
        self.assertEqual(row["complete_outer_but_not_delivered_groups"], 0)
        self.assertEqual(row["incomplete_groups_with_other_fragments_arriving_before_client_connect_return"], 1)

    def test_received_but_not_delivered_kept_separate(self):
        row = self.check(inner_delivered=False)
        self.assertEqual(row["all_fragments_received_groups"], 1)
        self.assertEqual(row["complete_outer_but_not_delivered_groups"], 1)

    def test_unknown_receiver_fingerprint(self):
        row = self.check(received=("a", "b", "unknown"))
        self.assertEqual(row["receiver_fingerprints_without_sender_match"], 1)

    def test_post_connect_fragments_not_marked_handshake(self):
        sender, receiver, capture = self.records(received=("a",), inner_delivered=False)
        receiver["Events"][0]["AtUS"] = 2_000_000
        row = diagnosis.direction(sender, receiver, capture, "server_to_client")
        self.assertEqual(row["incomplete_groups_with_other_fragments_arriving_before_client_connect_return"], 0)


if __name__ == "__main__":
    unittest.main()
