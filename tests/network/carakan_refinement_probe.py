# SPDX-License-Identifier: MIT-0
"""Offline, baseline-pinned rotation probe; no network or production secrets."""
import collections
import hashlib
import hmac
import json
import random
import struct
import sys
import tarfile
import types
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "tests"))
    module = types.ModuleType("carakan_baseline_reference")
    with tarfile.open(root / "build/carakan/source.tar.gz") as archive:
        source = archive.extractfile("tests/test_carakan_reference.py").read()
    exec(compile(source, "<baseline-reference>", "exec"), module.__dict__)
    rows = []
    for code in (100, 250, 400, 450, 750):
        per_key = []
        for key_index in range(4):
            password = hashlib.sha256(f"carakan-offline-probe/{key_index}".encode()).hexdigest().encode()
            table = module.compile_table(password, code)
            maximum = min(684, (1232 - max(table[3])) * (code // 100) // 8 - 2)
            prk = hmac.digest(b"oh-my-hysteria/carakan/v2", password, "sha256")
            key = hmac.digest(prk, f"interleave/{code}".encode() + b"\x01", "sha256")
            rng = random.Random(code * 100 + key_index)
            first, last, rotated_first, rotated_last = ([0] * 256 for _ in range(4))
            offsets = set()
            for _ in range(512):
                raw = rng.randbytes(maximum)
                wire = module.pack(table, raw)
                counts = collections.Counter(wire)
                spec = struct.pack(">H256H", len(wire), *(counts[s] for s in range(256)))
                offset = int.from_bytes(hmac.digest(key, spec, "sha256")[:8], "big") % len(wire)
                shaped = wire[offset:] + wire[:offset]
                counts2 = collections.Counter(shaped)
                assert counts == counts2
                restored = shaped[-offset:] + shaped[:-offset] if offset else shaped
                assert restored == wire
                offsets.add(offset)
                first[wire[0]] += 1
                last[wire[-1]] += 1
                rotated_first[shaped[0]] += 1
                rotated_last[shaped[-1]] += 1
            def tv(hist):
                return sum(abs(a / 512 - b / 16384) for a, b in zip(hist, table[0])) / 2
            per_key.append({"key": key_index, "before_first_tv": tv(first), "before_last_tv": tv(last),
                            "after_first_tv": tv(rotated_first), "after_last_tv": tv(rotated_last),
                            "distinct_offsets": len(offsets), "added_bytes": 0})
        rows.append({"target": code / 100, "keys": per_key})
    output = root / "build/carakan-refinement/rotation-probe.json"
    output.write_text(json.dumps({"scope": "offline synthetic probe only", "rows": rows,
                                  "not_strict_IID": True, "termination_is_scattered_not_removed": True}, indent=2))
    print(output.read_text())


if __name__ == "__main__":
    main()
