# SPDX-License-Identifier: MIT-0
"""Run on the retained test host, using only an isolated loopback namespace."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    parser.add_argument("--inside", action="store_true")
    parser.add_argument("--remaining", action="store_true", help="Do not repeat completed modules; run race/coverage/vet/MTU checks")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    source = root / "source"
    if not args.inside:
        # --net creates an anonymous namespace that disappears with the child;
        # it has no uplink and never changes the host's routes or qdiscs.
        argv = ["unshare", "--net", sys.executable, __file__, str(root), "--inside"]
        if args.remaining:
            argv.append("--remaining")
        result = subprocess.run(argv,
                                stdin=subprocess.DEVNULL)
        raise SystemExit(result.returncode)
    subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    interfaces = subprocess.check_output(["ip", "-j", "link"], text=True)
    assert [i["ifname"] for i in json.loads(interfaces)] == ["lo"]
    base = Path("/opt/omhy-presto-20261031")
    env = dict(os.environ, PATH=f"{source / '.venv/bin'}:{base / 'toolchain/go/bin'}:{base / 'tools/bin'}:" + os.environ["PATH"],
               GOMAXPROCS="2", GOMEMLIMIT="600MiB", GOTOOLCHAIN="local", GOPROXY="off")
    for name in ("OMHY_PRESTO_SSH_PASSWORD", "OMHY_TRIDENT_SSH_PASSWORD"):
        env.pop(name, None)
    results = {"tests": {}, "only_loopback": True, "public_or_lte_started": False,
               "source_sha256": hashlib.sha256((root / "source.tar.gz").read_bytes()).hexdigest()}

    def save():
        (root / "results.json").write_text(json.dumps(results, indent=2))

    def command(name, argv, timeout=900):
        with (root / (name + ".log")).open("x") as log:
            try:
                status = subprocess.run(argv, cwd=source, env=env, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=log, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                status = "timeout"
        results["tests"][name] = {"command": argv, "status": status}
        save()
        print(name, status, flush=True)
        if status:
            raise RuntimeError(name + " failed; evidence retained")

    try:
        if not args.remaining:
            command("modules", ["go", "test", "-p", "1", "-count=1", "-timeout=5m", "./core/...", "./extras/...", "./app/..."])
        command("race", ["go", "test", "-p", "1", "-race", "-count=1", "-timeout=5m", "./extras/obfs", "./core/internal/pmtud", "./app/cmd", "-run=Trident|Presto|Blink|Gecko|Salamander|PacketConnLimits"])
        command("coverage", ["go", "test", "-p", "1", "-count=1", "-coverprofile=" + str(root / "coverage.out"), "./extras/obfs"])
        command("vet", ["go", "vet", "-p", "1", "./core/...", "./extras/...", "./app/..."])
        command("build-integration", ["go", "test", "-p", "1", "-c", "-o", str(root / "cmd.test"), "./app/cmd"])
        subprocess.run(["ip", "link", "set", "lo", "mtu", "1280"], check=True)
        subprocess.run(["tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "20ms"], check=True)
        command("isolated-mtu1280-delay", [str(root / "cmd.test"), "-test.run=^TestTridentTLSAndTransfer$", "-test.timeout=3m", "-test.v"])
    except Exception as exc:
        results["error"] = str(exc)
    finally:
        results["remaining_listeners"] = subprocess.check_output(["ss", "-H", "-luntp"], text=True).strip()
        save()
        with tarfile.open(root / "evidence.tar.gz", "w:gz") as archive:
            for path in root.iterdir():
                if path.suffix in (".log", ".json", ".out"):
                    archive.add(path, arcname=path.name)
    print(json.dumps(results, indent=2), flush=True)
    raise SystemExit(bool(results.get("error")) or bool(results["remaining_listeners"]))


if __name__ == "__main__":
    main()
