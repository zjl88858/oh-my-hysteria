# SPDX-License-Identifier: MIT-0
"""Bounded local Carakan fuzz driver. No SSH, public listener or LTE traffic."""
import json
import argparse
import subprocess
import time
from pathlib import Path


def main():
    root = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("build/carakan/fuzz"))
    args = parser.parse_args()
    output = root / args.output
    output.mkdir(parents=True, exist_ok=False)
    results = []
    for name in ("Packing", "Decode", "Receive", "AuthenticatedState"):
        command = ["go", "test", "-run", "^$", "-fuzz", f"^FuzzCarakan{name}$",
                   "-fuzztime=20s", "-parallel=2", "./extras/obfs"]
        started = time.monotonic()
        with (output / f"{name}.log").open("wb") as log:
            result = subprocess.run(command, cwd=root, stdout=log, stderr=subprocess.STDOUT, timeout=120)
        results.append({"command": command, "exit_code": result.returncode,
                        "wall_seconds": time.monotonic() - started, "log": f"{name}.log"})
        (output / "commands.json").write_text(json.dumps(results, indent=2))
        print(json.dumps(results[-1]), flush=True)
        if result.returncode:
            raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
