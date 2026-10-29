# SPDX-License-Identifier: MIT-0

import unittest

from tests.network.traffic_budget import TrafficBudget, ipv4_udp_ip_bytes


def packet(source=12345, destination=443, payload=100):
    ethernet = bytearray(14)
    ethernet[12:14] = b"\x08\x00"
    ip = bytearray(20)
    ip[0], ip[9] = 0x45, 17
    ip[2:4] = (28 + payload).to_bytes(2, "big")
    ip[6:8] = b"\x40\x00"  # DF, not fragmentation.
    udp = source.to_bytes(2, "big") + destination.to_bytes(2, "big") + (8 + payload).to_bytes(2, "big") + b"\0\0"
    return ethernet + ip + udp + bytes(payload)


class TrafficBudgetTests(unittest.TestCase):
    def test_both_directions_count_ip_headers_not_only_payload(self):
        self.assertEqual(ipv4_udp_ip_bytes(packet(), 443), 128)
        self.assertEqual(ipv4_udp_ip_bytes(packet(443, 12345), 443), 128)
        self.assertEqual(ipv4_udp_ip_bytes(packet(22, 12345), 443), 0)
        self.assertEqual(ipv4_udp_ip_bytes(b"", 443), 0)

    def test_vlan_padding_and_non_udp(self):
        data = packet()
        tagged = data[:12] + b"\x81\x00\0\x01\x08\x00" + data[14:]
        self.assertEqual(ipv4_udp_ip_bytes(tagged + bytes(20), 443), 128)
        data[23] = 6
        self.assertEqual(ipv4_udp_ip_bytes(data, 443), 0)

    def test_fail_closed_on_fragmentation_and_truncation(self):
        data = packet()
        data[20:22] = b"\x20\x00"
        with self.assertRaises(ValueError):
            ipv4_udp_ip_bytes(data, 443)
        with self.assertRaises(ValueError):
            ipv4_udp_ip_bytes(packet()[:-1], 443)
        with self.assertRaises(ValueError):
            ipv4_udp_ip_bytes(packet(), 0)

    def test_budget_preserves_observed_overrun_and_never_resets(self):
        budget = TrafficBudget(256)
        self.assertTrue(budget.account(128))
        self.assertTrue(budget.account(128))
        self.assertFalse(budget.account(1))
        self.assertFalse(budget.account(0))
        self.assertEqual((budget.used_bytes, budget.packets), (257, 3))
        with self.assertRaises(ValueError):
            budget.account(-1)
        with self.assertRaises(ValueError):
            TrafficBudget(0)
