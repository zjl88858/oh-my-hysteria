# SPDX-License-Identifier: MIT-0
"""Analyze existing loopback captures only; never opens a network socket."""
import argparse
import collections
import json
import math
from pathlib import Path


def entropy(histogram):
    total = sum(histogram)
    if total <= 0:
        raise ValueError("empty spectrum")
    return -sum(n / total * math.log2(n / total) for n in histogram if n)


def total_variation(observed, frequencies):
    total, nominal = sum(observed), sum(frequencies)
    if total <= 0 or nominal <= 0:
        raise ValueError("empty spectrum")
    return sum(abs(a / total - b / nominal) for a, b in zip(observed, frequencies, strict=True)) / 2


def positional_metrics(group, spectra):
    """Same-key pooling only; preserve an unrotated, same-packet ablation."""
    if not all("PositionBins" in r["C2S"] for r in group):
        return {"positional_capture_available": False}
    bins_tv, prefix_tv, suffix_tv, unrotated_tv, joint_tv = [], [], [], [], []
    for key, spectrum in spectra.items():
        bins = [[0] * 256 for _ in range(16)]
        prefix, suffix = ([[0] * 256 for _ in range(8)] for _ in range(2))
        terminal = [0] * 256
        transitions = [[0] * 16 for _ in range(16)]
        for record in group:
            if record["KeyIndex"] != key:
                continue
            for name in ("C2S", "S2C"):
                wire = record[name]
                if sum(map(sum, wire["PositionBins"])) != wire["Bytes"]:
                    raise ValueError("invalid positional totals")
                if sum(wire["UnrotatedLast"]) != wire["Packets"]:
                    raise ValueError("invalid ablation totals")
                if sum(map(sum, wire["Transitions"])) != wire["Bytes"] - wire["Packets"]:
                    raise ValueError("invalid within-packet transition totals")
                for destination, field in ((bins, "PositionBins"), (prefix, "Prefix"),
                                            (suffix, "Suffix"), (transitions, "Transitions")):
                    for i, hist in enumerate(wire[field]):
                        destination[i] = [a + b for a, b in zip(destination[i], hist, strict=True)]
                terminal = [a + b for a, b in zip(terminal, wire["UnrotatedLast"], strict=True)]
        bins_tv.append([total_variation(hist, spectrum) for hist in bins])
        prefix_tv.append([total_variation(hist, spectrum) for hist in prefix])
        suffix_tv.append([total_variation(hist, spectrum) for hist in suffix])
        unrotated_tv.append(total_variation(terminal, spectrum))
        total = sum(map(sum, transitions))
        left = [sum(row) / total for row in transitions]
        right = [sum(row[j] for row in transitions) / total for j in range(16)]
        joint_tv.append(sum(abs(transitions[i][j] / total - left[i] * right[j])
                            for i in range(16) for j in range(16)) / 2)
    mean_columns = lambda data: [sum(row[i] for row in data) / len(data) for i in range(len(data[0]))]
    return {"positional_capture_available": True,
            "same_packets_unrotated_last_mean_tv": sum(unrotated_tv) / len(unrotated_tv),
            "relative_position_bin_mean_tv": mean_columns(bins_tv),
            "max_per_key_relative_position_bin_tv": max(map(max, bins_tv)),
            "first_eight_bytes_mean_tv": mean_columns(prefix_tv),
            "last_eight_bytes_mean_tv": mean_columns(suffix_tv),
            "coarse_adjacent_joint_tv_to_empirical_product_mean": sum(joint_tv) / len(joint_tv),
            "joint_metric_is_not_a_general_independence_test": True}


def summarize(records):
    groups = collections.defaultdict(list)
    hashes = set()
    all_application = all_wire = all_packets = 0
    spectra = collections.defaultdict(dict)
    for record in records:
        h = record["TargetEntropy"]
        key = record["KeyIndex"]
        groups[h].append(record)
        for name, stats_name in (("C2S", "ClientStats"), ("S2C", "ServerStats")):
            wire, stats = record[name], record[stats_name]
            if wire["Bytes"] != sum(wire["Histogram"]) or wire["Bytes"] != sum(wire["Lengths"]):
                raise ValueError("inconsistent captured byte totals")
            if wire["Packets"] != len(wire["Lengths"]) or max(wire["Lengths"]) > 1232:
                raise ValueError("invalid datagram totals or MTU")
            if sum(wire["First"]) != wire["Packets"] or sum(wire["Last"]) != wire["Packets"]:
                raise ValueError("invalid boundary histograms")
            if wire["Bytes"] != stats["SentWireBytes"] or stats["SentInnerBytes"] != record["ApplicationPerDirection"]:
                raise ValueError("sender/receiver accounting mismatch")
            if any(stats[field] for field in ("AuthDrops", "MalformedDrops", "RateDrops", "ResourceDrops",
                                               "ReplayDrops", "FreshnessDrops", "ExpiredAssemblies")):
                raise ValueError("capture contains receiver drops")
            spectrum = tuple(stats["Spectrum"])
            if sum(spectrum) != 16384:
                raise ValueError("invalid table frequencies")
            previous = spectra[h].setdefault(key, spectrum)
            if previous != spectrum:
                raise ValueError("same key changed spectrum")
            digest = wire["SequenceHash"]
            if digest in hashes:
                raise ValueError("duplicate complete direction sequence")
            hashes.add(digest)
            all_application += stats["SentInnerBytes"]
            all_wire += wire["Bytes"]
            all_packets += wire["Packets"]
    rows = []
    for h, group in sorted(groups.items()):
        packet_counts = []
        application = source = wire_bytes = packets = 0
        per_direction_entropy, variation, payload_limits = [], [], []
        for record in group:
            packet_counts.extend(n for i, n in enumerate(record["MessagePackets"]) if i % 8 == 0 or i % 8 >= 5)
            for direction, stats_name in (("C2S", "ClientStats"), ("S2C", "ServerStats")):
                wire, stats = record[direction], record[stats_name]
                application += stats["SentInnerBytes"]
                source += stats["SentInnerBytes"] + stats.get("SentRepairBytes", 0) + (stats.get("FrameOverhead",84)+2) * stats["SentPackets"]
                wire_bytes += wire["Bytes"]
                packets += wire["Packets"]
                per_direction_entropy.append(entropy(wire["Histogram"]))
                variation.append(total_variation(wire["Histogram"], stats["Spectrum"]))
                payload_limits.append(stats["MaxFragmentPayload"])
        # Different keys permute byte values: pooling histograms across keys
        # would increase H artificially. Report per-key/per-direction H instead.
        first_tv, last_tv, last_mass = [], [], []
        for key, spectrum in spectra[h].items():
            first, last = [0] * 256, [0] * 256
            for record in group:
                if record["KeyIndex"] == key:
                    for direction in ("C2S", "S2C"):
                        first = [a + b for a, b in zip(first, record[direction]["First"], strict=True)]
                        last = [a + b for a, b in zip(last, record[direction]["Last"], strict=True)]
            first_tv.append(total_variation(first, spectrum))
            last_tv.append(total_variation(last, spectrum))
            last_mass.append(max(last) / sum(last))
        rows.append({"target_entropy": h, "sessions": len(group), "passwords": len(spectra[h]),
                     "distinct_password_spectra": len(set(spectra[h].values())),
                     "nominal_spectrum_entropy": group[0]["ClientStats"]["SpectrumEntropy"],
                     "frame_overhead": group[0]["ClientStats"].get("FrameOverhead",84),
                     "observed_direction_entropy_min": min(per_direction_entropy),
                     "observed_direction_entropy_mean": sum(per_direction_entropy) / len(per_direction_entropy),
                     "observed_direction_entropy_max": max(per_direction_entropy),
                     "max_total_variation_to_nominal": max(variation),
                     "per_key_first_byte_mean_total_variation": sum(first_tv) / len(first_tv),
                     "per_key_last_byte_mean_total_variation": sum(last_tv) / len(last_tv),
                     "max_per_key_last_byte_single_symbol_mass": max(last_mass),
                     "application_bytes": application, "udp_payload_bytes": wire_bytes, "packets": packets,
                     "source_bytes_including_lengths": source, "wire_to_source_ratio": wire_bytes / source,
                     "wire_to_inner_ratio": wire_bytes / application, "ideal_symbol_ratio_8_over_H": 8 / h,
                     "fragment_payload_min": min(payload_limits), "fragment_payload_max": max(payload_limits),
                     "observed_1200_packet_fragment_min": min(packet_counts),
                     "observed_1200_packet_fragment_max": max(packet_counts)})
        rows[-1].update(positional_metrics(group, spectra[h]))
    return {"completed_sessions": len(records), "observed_direction_sequence_hashes_distinct": len(hashes),
            "application_bytes": all_application, "udp_payload_bytes": all_wire, "packets": all_packets,
            "rows": rows, "scope": "Loopback native UDP, not proxy throughput or censorship testing",
            "entropy_is_per_direction_not_pooled_across_passwords": True,
            "strict_distribution_goal_met": False,
            "boundary_finding": "Report measured first/last and positional spectra separately. Cyclic interleaving scatters, rather than removes, the canonical termination seam; finite samples are not a strict IID proof.",
            "strict_IID_or_exact_finite_histogram_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    records = [json.loads(p.read_text()) for p in sorted(args.directory.glob("h-*.json"))]
    if not records:
        raise ValueError("no captures")
    data = summarize(records)
    args.output.write_text(json.dumps(data, indent=2), encoding="utf-8")
    print(json.dumps(data, indent=2))


if __name__ == "__main__":
    main()
