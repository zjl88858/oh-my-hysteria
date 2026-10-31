# SPDX-License-Identifier: MIT-0
"""Offline public-evidence and optional loopback-fault summary. No connections."""
import argparse
import json
import math
from pathlib import Path


def analyze_public(root):
    rows = []
    for phase in ("continuation/recovery", "staircase"):
        folder = root / phase
        raw = json.loads((folder / "results.json").read_text())
        spectra = json.loads((folder / "spectra.json").read_text())
        for run in raw["runs"]:
            if run["obfs"] != "carakan":
                continue
            tag = run["tag"]
            spec = spectra[tag]
            stage = raw["traffic"]["stages"][tag]
            errors = []
            for line in (folder / (tag + ".log")).read_text().splitlines():
                event = json.loads(line)
                if event.get("level") == "fatal":
                    errors.append(event.get("error"))
            directions = {
                name: {
                    "packets": d["packets"],
                    "ip_bytes": d["ip_bytes"],
                    "payload_min": d["payload_min"],
                    "payload_max": d["payload_max"],
                    "peers": d["peers"],
                    "gap_histogram_us": d["gap_histogram_us"],
                    "off_spectrum_bytes": d["spectrum"]["off_spectrum_bytes"],
                }
                for name, d in stage["directions"].items()
            }
            parts = math.ceil(1200 / spec["max_fragment_payload"])
            rows.append({
                "tag": tag,
                "target_entropy": run["entropy"],
                "completed": run["valid"],
                "max_fragment_payload": spec["max_fragment_payload"],
                "parts_per_1200_inner_bytes": parts,
                "client_fatal_errors": errors,
                "directions": directions,
                "idealized_whole_datagram_survival_if_independent_outer_loss": {
                    str(loss): (1 - loss) ** parts for loss in (0.01, 0.05, 0.2)
                },
                "receiver_auth_reassembly_or_drop_stats_available": False,
            })
    return rows


def analyze_loopback(folder):
    if not folder:
        return None
    plan = json.loads((folder / "plan.json").read_text())
    rows = []
    counters = ("AuthDrops", "MalformedDrops", "RateDrops", "ReplayDrops",
                "ResourceDrops", "FreshnessDrops", "ExpiredAssemblies", "EvictedAssemblies")
    for case in plan:
        result = json.loads((folder / (case["Name"] + ".json")).read_text())
        assert result["Case"] == case
        assert result["LoopbackOnly"] and result["NormalTLS"]
        sides = {}
        for name in ("Client", "Server"):
            s = result[name]
            sides[name.lower()] = {
                "sent_packets": s["SentPackets"],
                "received_packets": s["ReceivedPackets"],
                "delivered_inner_bytes": s["DeliveredBytes"],
                "reassembled_messages": s["Reassembled"],
                "max_fragment_payload": s["MaxFragmentPayload"],
                "drop_counters": {k: s[k] for k in counters},
            }
        rows.append({
            "case": case, "connected": result["Connected"],
            "transfer_complete": result["TransferComplete"],
            "connect_seconds": result["ConnectSeconds"], "error": result.get("Error"),
            "client_wire": result["ClientWire"], "server_wire": result["ServerWire"],
            "sides": sides,
        })
    return {
        "case_count": len(rows),
        "connected": sum(r["connected"] for r in rows),
        "complete_transfers": sum(r["transfer_complete"] for r in rows),
        "rows": rows,
        "not_a_public_network_reproduction": True,
        "rng_seed_fixed_but_tls_ciphertext_and_packetization_are_not_deterministic": True,
        "only_one_trial_per_impairment_condition": True,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--public", type=Path, default=Path("build/carakan-refinement/public"))
    parser.add_argument("--loopback", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = {
        "public": analyze_public(args.public),
        "loopback": analyze_loopback(args.loopback),
        "implementation_facts": {
            "fragment_bound_uses_floor_entropy": True,
            "any_missing_fragment_prevents_inner_datagram_delivery": True,
            "reassembly_expiry_seconds": 3,
            "default_quic_handshake_total_timeout_seconds": 10,
            "default_quic_handshake_idle_timeout_seconds": 5,
            "per_source_verify_initial_burst_packets": 1024,
            "global_verify_initial_burst_packets": 2048,
            "sources": ["extras/obfs/carakan_tans.go", "extras/obfs/carakan_state.go",
                        "third_party/quic-go/config.go", "third_party/quic-go/internal/protocol/params.go"],
        },
        "actual_public_failure_cause_established": False,
        "no_new_public_connections": True,
        "limitations": [
            "The public capture retained histograms and lengths, not payloads or authenticated fragment identities",
            "A server egress capture cannot establish delivery at Windows, including its process-routing path",
            "Independent-loss survival probabilities are a model, not measured public loss rates",
            "The captured failed server receive streams have fewer packets than the fresh 1024-packet source burst; they alone cannot exhaust that token bucket",
            "Synthetic userspace loopback impairments are not measured LTE behavior or Linux netem",
            "No threshold, censor-intervention or censorship-bypass conclusion follows",
        ],
    }
    args.output.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
