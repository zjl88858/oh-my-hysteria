# SPDX-License-Identifier: MIT-0
"""Offline v3 FEC-aware join of sender, VPS and receiver packet fingerprints."""
import argparse
from collections import Counter, defaultdict, deque
import json
import math
from pathlib import Path

from carakan_public_diagnosis import selected, multiset_intersection


def direction(sender, receiver, captures, name):
    sent = selected(sender, "outer", "write")
    received = selected(receiver, "outer", "read")
    capture_ids = [e["digest"] for e in captures if e["direction"] == name]
    sent_ids, received_ids = [e["Digest"] for e in sent], [e["Digest"] for e in received]
    received_set, capture_set = set(received_ids), set(capture_ids)
    received_positions = defaultdict(list)
    inner_reads = defaultdict(deque)
    for position, e in enumerate(receiver["Events"]):
        if e.get("Error"):
            continue
        if e["Layer"] == "outer" and e["Op"] == "read":
            received_positions[e["Digest"]].append(position)
        elif e["Layer"] == "inner" and e["Op"] == "read":
            inner_reads[e["Digest"]].append((position, e["AtUS"]))
    grouped = defaultdict(list)
    for e in sent:
        grouped[e["Group"]].append(e)
    inner_writes = selected(sender, "inner", "write")
    duplicate_inner_hashes = [h for h, n in Counter(e["Digest"] for e in inner_writes).items() if n > 1]
    groups = []
    for inner in inner_writes:
        packets = grouped[inner["Group"]]
        k = math.ceil(inner["Bytes"] / sender["Stats"]["MaxFragmentPayload"])
        repair = min(4, math.ceil(k / 4)) if k > 1 else 0
        assert len(packets) == k + repair, (inner["Group"], k, repair, len(packets))
        total_read = sum(e["Digest"] in received_set for e in packets)
        delivery_at, delivery_position = None, None
        if total_read >= k and inner_reads[inner["Digest"]]:
            delivery_position, delivery_at = inner_reads[inner["Digest"]].popleft()
        read_at_delivery = [
            bool(delivery_position is not None and any(p < delivery_position for p in received_positions[e["Digest"]]))
            for e in packets
        ]
        if delivery_at is not None:
            assert sum(read_at_delivery) >= k, "delivered fingerprint preceded sufficient raw shard reads"
        data_at_delivery = sum(read_at_delivery[:k])
        groups.append({
            "sender_group": inner["Group"], "inner_bytes": inner["Bytes"],
            "data_shards": k, "repair_shards": repair, "wire_packets": len(packets),
            "vps_interface_matches": sum(e["Digest"] in capture_set for e in packets),
            "receiver_matches_by_trace_end": total_read,
            "data_read_by_trace_end": sum(e["Digest"] in received_set for e in packets[:k]),
            "repair_read_by_trace_end": sum(e["Digest"] in received_set for e in packets[k:]),
            "all_wire_packets_read": total_read == len(packets),
            "inner_fingerprint_delivered": delivery_at is not None,
            "receiver_delivery_at_us": delivery_at,
            "data_read_at_delivery": data_at_delivery if delivery_at is not None else None,
            "repair_read_at_delivery": sum(read_at_delivery[k:]) if delivery_at is not None else None,
            "inferred_fec_recovery_at_delivery": delivery_at is not None and data_at_delivery < k,
            "inferred_recovered_data_shards": k - data_at_delivery if delivery_at is not None else 0,
            "recovery_delivery_before_client_connect_return": bool(delivery_at is not None and data_at_delivery < k and receiver.get("Role") == "client" and delivery_at < receiver["ConnectSeconds"] * 1e6),
            "missing_data_ordinals_at_trace_end": [i for i, e in enumerate(packets[:k]) if e["Digest"] not in received_set],
            "missing_repair_ordinals_at_trace_end": [i for i, e in enumerate(packets[k:]) if e["Digest"] not in received_set],
        })
    fields = ("ReceivedPackets", "DeliveredBytes", "AuthDrops", "MalformedDrops", "RateDrops", "ReplayDrops",
              "ResourceDrops", "FreshnessDrops", "ExpiredAssemblies", "EvictedAssemblies", "ReceivedRepairPackets",
              "RedundantRepairPackets", "FECRecoveredMessages", "FECRecoveredShards", "FECRecoveryFailures")
    return {
        "sender_outer_writes": len(sent), "receiver_outer_reads": len(received),
        "vps_interface_packets": len(capture_ids),
        "sender_fingerprints_at_vps": multiset_intersection(sent_ids, capture_ids),
        "sender_fingerprints_at_receiver": multiset_intersection(sent_ids, received_ids),
        "receiver_without_sender_match": sum((Counter(received_ids) - Counter(sent_ids)).values()),
        "inferred_fec_recovered_groups": sum(g["inferred_fec_recovery_at_delivery"] for g in groups),
        "inferred_fec_recovered_data_shards": sum(g["inferred_recovered_data_shards"] for g in groups),
        "inferred_recovery_matches_counter_snapshot": sum(g["inferred_recovered_data_shards"] for g in groups) == receiver["Stats"].get("FECRecoveredShards", 0),
        "recovered_groups_before_client_connect_return": sum(g["recovery_delivery_before_client_connect_return"] for g in groups),
        "incomplete_wire_but_delivered_groups": sum(g["inner_fingerprint_delivered"] and not g["all_wire_packets_read"] for g in groups),
        "delivered_inner_groups": sum(g["inner_fingerprint_delivered"] for g in groups),
        "duplicate_inner_fingerprints_make_per_group_assignment_ambiguous": duplicate_inner_hashes,
        "receiver_stats_snapshot": {k: receiver["Stats"].get(k, 0) for k in fields}, "groups": groups,
    }


def summarize(root):
    raw = json.loads((root / "results.json").read_text())
    traffic, rows = raw["traffic"], []
    assert traffic["prior_ip_bytes"] == 3094326 and traffic["prior_packets"] == 3331
    assert traffic["ip_bytes"] == traffic["prior_ip_bytes"] + sum(s["ip_bytes"] for s in traffic["stages"].values())
    assert traffic["packets"] == traffic["prior_packets"] + sum(s["packets"] for s in traffic["stages"].values())
    for run in raw["runs"]:
        tag = run["tag"]
        if not all((root / (tag + suffix)).exists() for suffix in ("-client.json", "-server.json")):
            rows.append({"tag": tag, "entropy": run["entropy"], "valid": run["valid"], "trace_incomplete": True})
            continue
        client = json.loads((root / (tag + "-client.json")).read_text())
        server = json.loads((root / (tag + "-server.json")).read_text())
        for record in (client, server):
            assert record["WireDomain"] == "oh-my-hysteria/carakan/v3" and record["Stats"]["WireVersion"] == 3
            assert record["NormalTLS"] and not record["PayloadsOrSecretsRecorded"] and record["TraceOverflows"] == 0
        captures = [e for e in traffic["events"] if e["stage"] == tag]
        rows.append({
            "tag": tag, "entropy": run["entropy"], "valid": run["valid"],
            "connected": client["Connected"], "server_authenticated": server["Connected"],
            "complete": client["Complete"], "client_error": client.get("Error"),
            "connect_seconds": client["ConnectSeconds"],
            "application_sent": client["ApplicationSent"], "application_received": client["ApplicationReceived"],
            "observed_ipv4_bytes": traffic["stages"][tag]["ip_bytes"],
            "client_to_server": direction(client, server, captures, "client_to_server"),
            "server_to_client": direction(server, client, captures, "server_to_client"),
        })
    return {
        "wire_domain": "oh-my-hysteria/carakan/v3", "rows": rows,
        "attempts": len(rows), "completed": sum(r["valid"] for r in rows),
        "observed_ipv4_bytes_cumulative": traffic["ip_bytes"], "observed_ipv4_packets_cumulative": traffic["packets"],
        "new_phase_ipv4_bytes": traffic["ip_bytes"] - traffic["prior_ip_bytes"],
        "new_phase_packets": traffic["packets"] - traffic["prior_packets"],
        "prior_seed_counted_once": True, "capture_drops": traffic["capture_drops"], "capture_error": traffic["error"],
        "original_early_stop_threshold": 4718592, "original_budget": 6291456,
        "cleanup": raw.get("cleanup"), "diagnostic_endpoint_not_byte_identical_release": True,
        "limitations": [
            "One cold sample per target, not a stable entropy/loss threshold or throughput benchmark",
            "Instrumented echo endpoint imports unchanged validated v3 core/obfs but is not a byte-identical release speedtest",
            "Fresh secrets/certificate and path/time differ from older v2 tests, not a controlled public v2/v3 comparison",
            "Fingerprints and direct recovery counters are distinct evidence; ciphertext/nonce headers were not retained or independently decrypted",
            "Shard roles are inferred from the frozen sender's systematic-then-repair call order, not parsed from unauthenticated wire bytes",
            "Fingerprints at trace end include closure; per-delivery times avoid treating late systematic shards as proof no recovery occurred",
            "Per-delivery shard presence uses recorder event order, not rounded microsecond timestamp ties",
            "Final stats are sampled before Close and event copying after Close, so some final raw reads can postdate the counter snapshot",
            "A VPS-interface to Windows-socket gap does not locate loss inside carrier, tunnel, process route, OS or socket queues",
            "Capture drops zero does not mean path loss zero; IPv4 lengths are not carrier billing",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("build/carakan-fec/public"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(args.directory)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
