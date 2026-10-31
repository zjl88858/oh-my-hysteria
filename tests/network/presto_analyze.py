# SPDX-License-Identifier: MIT-0
"""Analyze native, length-only Presto traces; never inspect ciphertext/genomes.

Each independent socket session is one sample. Four sessions per password train
the centroid; four are held out. Features use only packet lengths, adjacency,
first-packet lengths, and receiver-side inter-arrival intervals. Known message
boundaries and internal stats are diagnostics only, NOT classifier inputs.
"""

import argparse
import itertools
import json
import math
import statistics
from pathlib import Path


def density(values, bins):
    counts = [0] * bins
    for value in values:
        counts[value] += 1
    total = max(1, sum(counts))
    return [n / total for n in counts]


def distance(a, b):
    return sum((x - y) ** 2 for x, y in zip(a, b, strict=True))


def feature_groups(record):
    groups = {"length": [], "transition": [], "prefix": [], "timing": []}
    for direction in ("C2S", "S2C"):
        events = record[direction]
        lengths = [e["length"] for e in events]
        # First four observed packets, not private knowledge of prelude count.
        groups["prefix"].extend(n / 1232 for n in lengths[:4])
        groups["length"].extend(math.sqrt(v) for v in density((min(31, n // 40) for n in lengths[4:]), 32))
        coarse = [min(7, n // 160) for n in lengths[4:]]
        groups["transition"].extend(math.sqrt(v) for v in density((a * 8 + b for a, b in zip(coarse, coarse[1:])), 64))
        gaps = [(b["at_ns"] - a["at_ns"]) / 1000 for a, b in zip(events, events[1:])]
        bounds = (50, 100, 250, 500, 1000, 2000, 5000)
        groups["timing"].extend(math.sqrt(v) for v in density((sum(g >= b for b in bounds) for g in gaps), 8))
    return groups


def centroid(vectors):
    return [statistics.mean(column) for column in zip(*vectors, strict=True)]


def classify(samples, features):
    centers = {key: centroid([s[features] for s in samples if s["key"] == key and s["session"] < 4]) for key in range(16)}
    predictions = []
    for sample in samples:
        if sample["session"] >= 4:
            prediction = min(centers, key=lambda key: distance(sample[features], centers[key]))
            predictions.append({"key": sample["key"], "session": sample["session"], "prediction": prediction})
    correct = sum(p["key"] == p["prediction"] for p in predictions)
    return {"correct": correct, "total": len(predictions), "accuracy": correct / len(predictions), "predictions": predictions}


def analyze(directory):
    paths = sorted(Path(directory).glob("key-*-session-*.json"))
    assert len(paths) == 128, f"incomplete corpus: {len(paths)}/128"
    samples, diagnostics = [], []
    observed = set()
    for path in paths:
        record = json.loads(path.read_text())
        key, session = record["key_index"], record["session"]
        assert (key, session) not in observed
        observed.add((key, session))
        groups = feature_groups(record)
        morph = groups["length"] + groups["transition"]
        combined = morph + [0.25 * v for v in groups["prefix"] + groups["timing"]]
        samples.append(dict(key=key, session=session, combined=combined, morphology=morph, **groups))
        for direction, stats_key in (("C2S", "ClientStats"), ("S2C", "ServerStats")):
            events, stats = record[direction], record[stats_key]
            assert 0 <= stats["PaddingBytes"] <= stats["SentInnerBytes"] // 3
            assert stats["RateDrops"] == stats["ResourceDrops"] == 0
            assert max(e["length"] for e in events) <= 1232
            diagnostics.append({"key": key, "session": session, "direction": direction,
                                "packets": len(events), "mean_length": statistics.mean(e["length"] for e in events),
                                "prelude_packets": stats["PreludePackets"], "prelude_bytes": stats["PreludeBytes"],
                                "fragmented_messages": stats["FragmentedMessages"], "burst_pauses": stats["BurstPauses"],
                                "outer_payload_ratio": stats["SentWireBytes"] / stats["SentInnerBytes"],
                                "wall_seconds": record["wall_seconds"]})
    assert observed == set(itertools.product(range(16), range(8)))
    separation = {}
    for name in ("length", "transition", "morphology", "timing", "combined"):
        within, between = [], []
        for a, b in itertools.combinations(samples, 2):
            target = within if a["key"] == b["key"] else between
            target.append(distance(a[name], b[name]))
        separation[name] = {"within_median": statistics.median(within), "between_median": statistics.median(between),
                            "within_p90": sorted(within)[math.ceil(0.90 * len(within)) - 1],
                            "between_p10": sorted(between)[math.ceil(0.10 * len(between)) - 1]}
    classifiers = {name: classify(samples, name) for name in ("morphology", "timing", "combined")}
    # Native random sessions must NOT produce a repeated wire-length sequence.
    for key in range(16):
        sequences = [tuple(e["length"] for e in json.loads(p.read_text())["C2S"]) for p in paths if p.name.startswith(f"key-{key:02d}-")]
        assert len(set(sequences)) == 8, ("fixed sequence", key)
    passed = classifiers["combined"]["accuracy"] >= 0.75 and all(
        separation[name]["within_median"] < separation[name]["between_median"] for name in ("length", "transition", "combined"))
    return {"passed": passed, "sessions": len(samples), "passwords": 16, "chance_accuracy": 1 / 16,
            "holdout_policy": "sessions 0..3 train, 4..7 held out; no flow slicing", "classifiers": classifiers,
            "separation": separation, "diagnostics": diagnostics,
            "limitations": ["controlled UDP echo workload on one host; receiver userspace times, not NIC timestamps",
                            "password identification is not application-family or DPI evasion testing",
                            "IPv4/v6 headers, kernel/route jitter, real workloads and network loss may change features",
                            "message counts, compiler values, addresses, ciphertext and internal stats are not classification features"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory")
    parser.add_argument("--output", required=True)
    args = parser.parse_args()
    result = analyze(args.directory)
    Path(args.output).write_text(json.dumps(result, indent=2))
    print(json.dumps({"passed": result["passed"], "sessions": result["sessions"],
                      "accuracies": {k: v["accuracy"] for k, v in result["classifiers"].items()}, "separation": result["separation"]}, indent=2))
    raise SystemExit(0 if result["passed"] else 1)


if __name__ == "__main__":
    main()
