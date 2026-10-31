# SPDX-License-Identifier: MIT-0
"""Descriptive comparison of existing Carakan summaries; no network activity."""
import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, required=True)
    parser.add_argument("--matched", type=Path, required=True)
    parser.add_argument("--heldout", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    base, matched, heldout = (json.loads(p.read_text()) for p in (args.baseline, args.matched, args.heldout))
    rows = []
    for a, b, c in zip(base["rows"], matched["rows"], heldout["rows"], strict=True):
        if a["target_entropy"] != b["target_entropy"] or b["target_entropy"] != c["target_entropy"]:
            raise ValueError("targets differ")
        if a["application_bytes"] != b["application_bytes"] or b["application_bytes"] != c["application_bytes"]:
            raise ValueError("application budgets differ")
        rows.append({"H": a["target_entropy"], "v1_ratio": a["wire_to_inner_ratio"],
                     "v2_ratio": b["wire_to_inner_ratio"],
                     "wire_reduction_percent": 100 * (1 - b["udp_payload_bytes"] / a["udp_payload_bytes"]),
                     "v1_last_tv": a["per_key_last_byte_mean_total_variation"],
                     "v2_first_tv": b["per_key_first_byte_mean_total_variation"],
                     "v2_last_tv": b["per_key_last_byte_mean_total_variation"],
                     "same_v2_packets_without_rotation_last_tv": b["same_packets_unrotated_last_mean_tv"],
                     "v2_observed_H": b["observed_direction_entropy_mean"],
                     "heldout_observed_H": c["observed_direction_entropy_mean"],
                     "heldout_ratio": c["wire_to_inner_ratio"],
                     "heldout_first_tv": c["per_key_first_byte_mean_total_variation"],
                     "heldout_last_tv": c["per_key_last_byte_mean_total_variation"],
                     "v2_relative_position_max_tv": b["max_per_key_relative_position_bin_tv"],
                     "v2_coarse_joint_tv": b["coarse_adjacent_joint_tv_to_empirical_product_mean"],
                     "v2_1200_fragments": [b["observed_1200_packet_fragment_min"], b["observed_1200_packet_fragment_max"]]})
    result = {"matched_completed": matched["completed_sessions"], "heldout_completed": heldout["completed_sessions"],
              "rows": rows,
              "matched_totals": {k: matched[k] for k in ("application_bytes", "udp_payload_bytes", "packets")},
              "heldout_totals": {k: heldout[k] for k in ("application_bytes", "udp_payload_bytes", "packets")},
              "matched_overall_payload_reduction_percent": 100 * (1 - matched["udp_payload_bytes"] / base["udp_payload_bytes"]),
              "no_strict_IID_or_censorship_claim": True, "different_wire_version_and_fresh_random_sessions": True}
    args.output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
