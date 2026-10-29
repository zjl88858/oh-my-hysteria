#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Summarize bounded benchmark JSON without interpreting it as an algorithm ranking."""

import argparse
import json
from pathlib import Path
import re
import statistics


def mbps(speed):
    match = re.fullmatch(r"([0-9.]+) (bps|Kbps|Mbps|Gbps)", speed)
    if match is None:
        raise ValueError(f"unsupported speed: {speed!r}")
    return float(match[1]) * {"bps": 1e-6, "Kbps": 1e-3, "Mbps": 1, "Gbps": 1e3}[match[2]]


def summarize(data):
    groups = {}
    for entry in data["runs"]:
        key = (entry.get("scenario", "public"), entry["algorithm"])
        group = groups.setdefault(key, {"runs": 0, "valid": 0, "download": [], "upload": [], "wall": []})
        group["runs"] += 1
        records = entry["transfers"]
        size = entry.get("bytes_per_direction", data["metadata"]["bytes_per_direction"])
        if (not entry.get("valid", True) or entry["status"] != 0 or len(records) != 2
                or {r.get("msg") for r in records} != {"download complete", "upload complete"}
                or any(r.get("bytes") != size for r in records)):
            continue
        group["valid"] += 1
        if "wall_seconds" in entry:
            group["wall"].append(entry["wall_seconds"])
        for record in records:
            direction = record["msg"].split()[0]
            group[direction].append(mbps(record["speed"]))
    rows = []
    for (scenario, algorithm), group in sorted(groups.items()):
        row = {"scenario": scenario, "algorithm": algorithm, "runs": group["runs"], "valid": group["valid"]}
        values = group["wall"]
        row["wall_seconds"] = ({"median": statistics.median(values), "min": min(values), "max": max(values)} if values else None)
        for direction in ("download", "upload"):
            values = group[direction]
            row[direction + "_mbps"] = ({"median": statistics.median(values), "min": min(values), "max": max(values)}
                                         if values else None)
        rows.append(row)
    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path)
    options = parser.parse_args()
    print(json.dumps(summarize(json.loads(options.results.read_text())), indent=2))


if __name__ == "__main__":
    main()
