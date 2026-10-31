# SPDX-License-Identifier: MIT-0
"""Offline join of dual-ended packet fingerprints. Never opens a connection."""
import argparse
from collections import Counter
import json
from pathlib import Path


def selected(record, layer, op):
    return [e for e in record["Events"] if e["Layer"] == layer and e["Op"] == op and not e.get("Error")]


def multiset_intersection(a, b):
    return sum((Counter(a) & Counter(b)).values())


def direction(sender, receiver, capture, name):
    sent = selected(sender, "outer", "write")
    received = selected(receiver, "outer", "read")
    captured = [e for e in capture if e["direction"] == name]
    sent_ids = [e["Digest"] for e in sent]
    received_ids = [e["Digest"] for e in received]
    capture_ids = [e["digest"] for e in captured]
    receiver_set, capture_set = set(received_ids), set(capture_ids)
    recv_inner = Counter(e["Digest"] for e in selected(receiver, "inner", "read"))
    grouped = {}
    for e in sent:
        grouped.setdefault(e["Group"], []).append(e)
    groups = []
    for inner in selected(sender, "inner", "write"):
        packets = grouped.get(inner["Group"], [])
        matching = [e for e in received if e["Digest"] in {p["Digest"] for p in packets}]
        all_received = bool(packets) and all(e["Digest"] in receiver_set for e in packets)
        delivered = all_received and recv_inner[inner["Digest"]] > 0
        if delivered:
            recv_inner[inner["Digest"]] -= 1
        groups.append({
            "sender_group": inner["Group"], "sender_inner_bytes": inner["Bytes"],
            "sender_at_us": inner["AtUS"], "outer_packets": len(packets),
            "outer_packets_seen_at_vps_interface": sum(e["Digest"] in capture_set for e in packets),
            "outer_packets_read_at_receiver": sum(e["Digest"] in receiver_set for e in packets),
            "all_outer_packets_read_at_receiver": all_received,
            "inner_payload_fingerprint_delivered": delivered,
            "receiver_arrival_span_us": max(e["AtUS"] for e in matching) - min(e["AtUS"] for e in matching) if matching else None,
            "receiver_first_arrival_us": min(e["AtUS"] for e in matching) if matching else None,
            "receiver_last_arrival_us": max(e["AtUS"] for e in matching) if matching else None,
            "other_fragments_arrived_before_client_connect_return": bool(matching and receiver["Role"] == "client" and max(e["AtUS"] for e in matching) < receiver["ConnectSeconds"] * 1e6),
            "missing_receiver_fragment_ordinals_zero_based": [i for i, e in enumerate(packets) if e["Digest"] not in receiver_set],
        })
    counters = ("ReceivedPackets", "DeliveredBytes", "Reassembled", "AuthDrops", "MalformedDrops",
                "RateDrops", "ReplayDrops", "ResourceDrops", "FreshnessDrops", "ExpiredAssemblies", "EvictedAssemblies")
    return {
        "sender_outer_write_successes": len(sent), "receiver_outer_reads": len(received),
        "vps_interface_capture_packets": len(captured),
        "sender_fingerprints_seen_at_vps_interface": multiset_intersection(sent_ids, capture_ids),
        "sender_fingerprints_read_at_receiver": multiset_intersection(sent_ids, received_ids),
        "vps_interface_fingerprints_read_at_receiver": multiset_intersection(capture_ids, received_ids),
        "receiver_fingerprints_without_sender_match": sum((Counter(received_ids) - Counter(sent_ids)).values()),
        "complete_sender_groups": len(groups),
        "all_fragments_received_groups": sum(g["all_outer_packets_read_at_receiver"] for g in groups),
        "delivered_inner_groups": sum(g["inner_payload_fingerprint_delivered"] for g in groups),
        "incomplete_outer_groups": sum(not g["all_outer_packets_read_at_receiver"] for g in groups),
        "incomplete_groups_with_other_fragments_arriving_before_client_connect_return": sum(not g["all_outer_packets_read_at_receiver"] and g["other_fragments_arrived_before_client_connect_return"] for g in groups),
        "complete_outer_but_not_delivered_groups": sum(g["all_outer_packets_read_at_receiver"] and not g["inner_payload_fingerprint_delivered"] for g in groups),
        "receiver_counters": {k: receiver["Stats"][k] for k in counters},
        "groups": groups,
    }


def summarize(root):
    results = json.loads((root / "results.json").read_text())
    traffic = results.get("traffic", {})
    rows = []
    for run in results["runs"]:
        tag = run["tag"]
        cpath, spath = root / (tag + "-client.json"), root / (tag + "-server.json")
        if not cpath.exists() or not spath.exists():
            rows.append({"tag": tag, "valid": run["valid"], "fingerprint_evidence_incomplete": True})
            continue
        client = json.loads(cpath.read_text())
        server = json.loads(spath.read_text())
        assert not client["PayloadsOrSecretsRecorded"] and not server["PayloadsOrSecretsRecorded"]
        assert client["TraceOverflows"] == server["TraceOverflows"] == 0
        assert client["NormalTLS"] and server["NormalTLS"]
        captures = [e for e in traffic["events"] if e["stage"] == tag]
        rows.append({
            "tag": tag, "target_entropy": run["entropy"], "valid": run["valid"],
            "client_error": client.get("Error"), "client_connect_seconds": client["ConnectSeconds"],
            "client_connected": client["Connected"], "server_authenticated": server["Connected"],
            "completed_application_bytes": client["ApplicationSent"] + client["ApplicationReceived"] if client["Complete"] else 0,
            "client_to_server": direction(client, server, captures, "client_to_server"),
            "server_to_client": direction(server, client, captures, "server_to_client"),
        })
    prior = traffic.get("prior_ip_bytes", results["metadata"]["prior_ip_bytes"])
    if traffic:
        assert traffic["ip_bytes"] == prior + sum(s["ip_bytes"] for s in traffic["stages"].values())
        assert traffic["packets"] == traffic["prior_packets"] + sum(s["packets"] for s in traffic["stages"].values())
    return {
        "rows": rows,
        "new_diagnostic_attempts": len(rows), "new_complete_diagnostic_connections": sum(r["valid"] for r in rows),
        "prior_ip_bytes_not_reset": prior, "observed_ipv4_bytes_cumulative": traffic.get("ip_bytes"),
        "observed_ipv4_packets_cumulative": traffic.get("packets"),
        "diagnostic_phase_observed_ipv4_bytes": traffic["ip_bytes"] - prior if traffic else None,
        "capture_drops": traffic.get("capture_drops"), "capture_error": traffic.get("error"),
        "cleanup": results.get("cleanup"),
        "diagnostic_not_release_binary": True, "normal_tls": True,
        "limitations": [
            "Fingerprints compare UDP write success, VPS interface capture and receiver ReadFrom; they do not locate a missing packet inside the carrier, tunnel, NAT, OS or socket queue",
            "Loss totals include shutdown; inspect early sender groups before attributing handshake failure",
            "Receiver Carakan counters are direct authenticated/decoder/reassembly observations; spectrum checks alone were not used as authentication evidence",
            "Final Carakan stats are taken before graceful close while the event copy is taken after close; a few final raw reads can be recorded after that stats snapshot and do not imply unexplained decoder drops",
            "The diagnostic endpoint adds in-memory hashing/grouping and has an echo-only outbound; it is not a byte-identical release speedtest or a timing-neutral observer",
            "Fresh secrets and certificate differ from earlier cleaned experiments; no strict rerun of the original ciphertext",
            "One cold diagnostic sample per target, not a stable entropy or packet-loss threshold",
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("build/carakan-diagnosis/public"))
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    summary = summarize(args.directory)
    args.output.write_text(json.dumps(summary, indent=2) + "\n")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
