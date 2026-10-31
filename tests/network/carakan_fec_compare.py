# SPDX-License-Identifier: MIT-0
"""Compare frozen local fault-injection cases; no clients or network access."""
import argparse
import collections
import json
import statistics
from pathlib import Path


def summarize(root, plan):
    rows = []
    for case in plan:
        result = json.loads((root / (case["Name"] + ".json")).read_text())
        assert result["Case"] == case
        assert result["LoopbackOnly"] and result["NormalTLS"]
        stats = [result[side] for side in ("Client", "Server")]
        rows.append({
            "name": case["Name"], "entropy": case["Entropy"],
            "profile": "burst3of31" if case["BurstEvery"] else "loss" + str(case["ServerToClientLoss"]),
            "complete": result["TransferComplete"], "connected": result["Connected"],
            "error": result.get("Error"), "connect_seconds": result["ConnectSeconds"],
            "sent_udp_payload_bytes": sum(s["SentWireBytes"] for s in stats),
            "sent_outer_packets": sum(s["SentPackets"] for s in stats),
            "sent_repair_packets": sum(s.get("SentRepairPackets", 0) for s in stats),
            "recovered_messages": sum(s.get("FECRecoveredMessages", 0) for s in stats),
            "recovered_shards": sum(s.get("FECRecoveredShards", 0) for s in stats),
            "recovery_failures": sum(s.get("FECRecoveryFailures", 0) for s in stats),
            "auth_format_rate_resource_freshness_drops": sum(sum(s[k] for k in ("AuthDrops", "MalformedDrops", "RateDrops", "ResourceDrops", "FreshnessDrops")) for s in stats),
            "expired_assemblies": sum(s["ExpiredAssemblies"] for s in stats),
            "replay_or_late_data_drops": sum(s["ReplayDrops"] for s in stats),
            "redundant_repair_packets": sum(s.get("RedundantRepairPackets", 0) for s in stats),
        })
    grouped = collections.defaultdict(list)
    for row in rows:
        grouped[row["profile"], row["entropy"]].append(row)
    groups = []
    for (profile, entropy), group in sorted(grouped.items()):
        groups.append({
            "profile": profile, "entropy": entropy, "trials": len(group),
            "complete": sum(r["complete"] for r in group),
            "connect_seconds_median_including_timeouts": statistics.median(r["connect_seconds"] for r in group),
            "sent_udp_payload_bytes": sum(r["sent_udp_payload_bytes"] for r in group),
            "recovered_messages": sum(r["recovered_messages"] for r in group),
            "recovered_shards": sum(r["recovered_shards"] for r in group),
            "expired_assemblies": sum(r["expired_assemblies"] for r in group),
        })
    return {"cases": len(rows), "complete": sum(r["complete"] for r in rows), "groups": groups, "rows": rows}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("build/carakan-fec"))
    args = parser.parse_args()
    root = args.directory
    plan = json.loads((root / "paired-plan.json").read_text())
    versions = {name: summarize(root / folder, plan) for name, folder in (
        ("v2", "v2-paired"), ("v3_fec", "v3-paired"), ("v3_no_repair_test_only", "v3-no-repair-paired"))}
    clean_cost = []
    for group in versions["v3_fec"]["groups"]:
        if group["profile"] != "loss0":
            continue
        baseline = next(g for g in versions["v2"]["groups"] if g["profile"] == group["profile"] and g["entropy"] == group["entropy"])
        clean_cost.append({"entropy": group["entropy"], "v3_to_v2_whole_connection_udp_payload_ratio": group["sent_udp_payload_bytes"] / baseline["sent_udp_payload_bytes"]})
    report = {
        "versions": versions, "clean_path_cost": clean_cost,
        "plan_frozen_before_product_changes": True, "same_fault_injector_for_v2_and_v3": True,
        "ablation_added_after_first_comparison_without_changing_plan_or_candidate": True,
        "no_new_public_or_ssh_connections": True,
        "prior_public_observed_ipv4_bytes_unchanged": 3094326,
        "limitations": [
            "Three trials per cell, not a stable success probability or general entropy threshold",
            "The same RNG seed does not make TLS ciphertext, QUIC packetization or realized losses identical",
            "v2 to v3 also changes the key domain and equal-width striping; the v3 no-repair overlay isolates the repair policy more narrowly",
            "The no-repair overlay is a local-only noninteroperable test binary, never a release option or protocol fallback",
            "Wire totals include handshake, control, possible QUIC retransmissions, echo and close; not pure FEC packing overhead or carrier billing",
            "Runs were not CPU-isolated and tiny local echo tests cannot rank sustained throughput",
            "User-space independent/burst loss injection is not measured LTE loss, Linux netem or censorship evidence",
        ],
    }
    (root / "comparison.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
