# SPDX-License-Identifier: MIT-0
"""Accounting helpers for bounded IPv4 UDP experiments, not carrier billing.

The capture caller must select the public interface and test port, stop owned
processes on parser errors or exhausted budget, and never record packet payloads.
Observed IP lengths exclude Ethernet, carrier tunnels and unobserved link-layer
retries. Offload and capture loss can also make them differ from billed traffic.
"""

from dataclasses import dataclass


def ipv4_udp_ip_bytes(frame, port):
    """Return the IPv4 total length of a matching Ethernet UDP frame, or zero.

    Fail closed for truncated / fragmented IPv4 UDP: silently ignoring such
    traffic could hide a budget overrun. Tests use explicit IPv4 endpoints.
    """
    if not 1 <= port <= 65535:
        raise ValueError("invalid UDP port")
    if len(frame) < 14:
        return 0
    offset, protocol = 14, int.from_bytes(frame[12:14], "big")
    for _ in range(2):
        if protocol not in (0x8100, 0x88A8):
            break
        if len(frame) < offset + 4:
            raise ValueError("truncated VLAN header")
        protocol = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
    if protocol != 0x0800:
        return 0
    if len(frame) < offset + 20:
        raise ValueError("truncated IPv4 header")
    if frame[offset] >> 4 != 4 or frame[offset + 9] != 17:
        return 0
    header = (frame[offset] & 15) * 4
    length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    if header < 20 or length < header + 8 or len(frame) < offset + length:
        raise ValueError("invalid or truncated IPv4 UDP packet")
    if int.from_bytes(frame[offset + 6:offset + 8], "big") & 0x3FFF:
        raise ValueError("fragmented IPv4 UDP cannot be safely port-accounted")
    udp = offset + header
    source = int.from_bytes(frame[udp:udp + 2], "big")
    destination = int.from_bytes(frame[udp + 2:udp + 4], "big")
    return length if port in (source, destination) else 0


@dataclass
class TrafficBudget:
    limit_bytes: int
    used_bytes: int = 0
    packets: int = 0

    def __post_init__(self):
        if self.limit_bytes <= 0 or self.used_bytes < 0 or self.packets < 0:
            raise ValueError("invalid traffic budget")

    def account(self, size):
        if size < 0:
            raise ValueError("negative packet size")
        if size:
            self.used_bytes += size
            self.packets += 1
        return self.used_bytes <= self.limit_bytes
