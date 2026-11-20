# SPDX-License-Identifier: MIT-0
"""Offline controls for the release experiment's loss and renewal attribution."""
import importlib.util
from pathlib import Path
import unittest


spec=importlib.util.spec_from_file_location("netfront_qa_common",Path(__file__).parent/"network/netfront_matrix/common.py")
qa=importlib.util.module_from_spec(spec)
spec.loader.exec_module(qa)


class NetFrontMeasurementTests(unittest.TestCase):
    def test_four_distinct_loss_points_and_duplicates(self):
        c={"sent":[0,1,2,3,4,5],"received":[4,0,0,7],"bad_payloads":1}
        s={"received":[0,2,3,4,5],"replied":[0,2,4,5],"bad_payloads":2}
        r=qa.reconcile(c,s,7)
        self.assertEqual((r["not_submitted"],r["missing_before_echo"],r["missing_echo_write"],r["missing_after_echo"]),
                         ([6],[1],[3],[2,5]))
        self.assertEqual(r["unexpected"],[[],[],[7]])
        self.assertEqual(r["duplicates"],[0,0,0,1])
        self.assertEqual(r["bad_payloads"],3)

    def test_udp_identity_and_renewal(self):
        tag=bytes(range(8))
        for i in range(72):
            b=qa.udp_payload(tag,i)
            self.assertEqual(qa.decode_id(b,tag,72),i)
            self.assertIsNone(qa.decode_id(b[:-1],tag,72))
            self.assertIsNone(qa.decode_id(b,tag[::-1],72))
        row={"rx":{"epochs":{"1:1":{"probe":1,"data":1},"1:2":{"probe":1,"cover":1},"1:3":{"probe":1}}},
             "tx":{"epochs":{"1:1":{"offer":1,"data":1},"1:2":{"offer":1,"cover":1},"1:3":{"offer":1}}}}
        self.assertEqual(qa.epoch_proofs(row),["1:1","1:2"])
        self.assertTrue(qa.renewed(qa.epoch_proofs(row)))
        self.assertFalse(qa.renewed(["1:1","2:1"]))
