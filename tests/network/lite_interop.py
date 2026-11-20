# SPDX-License-Identifier: MIT-0
"""Standard v1.3.0 compatibility and explicit Lite mode admission, on IPv4 loopback."""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import tempfile

sys.path.insert(0, str(Path(__file__).resolve().parent/"netfront_matrix"))
from compat import run
from local_cases import certificate


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--old", required=True, type=Path)
    p.add_argument("--new", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--temp-parent", type=Path)
    a = p.parse_args()
    a.output.mkdir(parents=True, exist_ok=False)
    exes = {"old": a.old.resolve(), "new": a.new.resolve()}
    plan = []
    for base, lite in (("presto", "prestolite"), ("netfront2", "netfrontlite2"), ("netfront3", "netfrontlite3")):
        plan.extend([("standard", "old", "new", base, base), ("standard", "new", "old", base, base),
                     ("lite", "new", "new", lite, lite),
                     ("wrong-mode", "new", "new", lite, base), ("wrong-mode", "new", "new", base, lite)])
    plan.extend([("wrong-ca", "new", "new", "prestolite", "prestolite"),
                 ("wrong-obfs", "new", "new", "netfrontlite3", "netfrontlite3")])
    (a.output/"plan.json").write_text(json.dumps({"cases": plan, "sha256": {
        k: hashlib.sha256(v.read_bytes()).hexdigest() for k,v in exes.items()}}, indent=2))
    rows = []
    with tempfile.TemporaryDirectory(dir=a.temp_parent, prefix="lite-interop-") as td:
        tmp = Path(td)
        certificate(tmp)
        (tmp/"untrusted").mkdir()
        certificate(tmp/"untrusted")
        for name, srv, cli, sm, cm in plan:
            try:
                r = run(tmp, exes[srv], exes[cli], name, mode=sm, client_mode=cm)
            except (OSError, RuntimeError, ValueError) as e:
                r = {"passed": False, "error": str(e)}
            r.update(server_build=srv, client_build=cli, server_mode=sm, client_mode=cm)
            rows.append(r)
            (a.output/"cases.json").write_text(json.dumps(rows, indent=2) + "\n")
            print(name, srv, cli, sm, cm, r["passed"], r.get("four", {}).get("counts"), flush=True)
    if not all(r["passed"] for r in rows):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
