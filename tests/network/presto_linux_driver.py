# SPDX-License-Identifier: MIT-0
"""Owned VPS-local validation. No public listener or Windows LTE traffic."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root")
    args = parser.parse_args()
    root = Path(args.root).resolve()
    source = root / "source"
    source.mkdir()
    with tarfile.open(root / "source.tar.gz") as archive:
        archive.extractall(source, filter="data")
    base = root.parent
    go = base / "toolchain/go/bin"
    tools = base / "tools/bin"
    env = dict(os.environ, PATH=f"{source / '.venv/bin'}:{go}:{tools}:" + os.environ["PATH"],
               GOMAXPROCS="2", GOMEMLIMIT="600MiB", GOTOOLCHAIN="local")
    # Never pass SSH credentials to test processes.
    env.pop("OMHY_PRESTO_SSH_PASSWORD", None)
    results = {"source_sha256": hashlib.sha256((root / "source.tar.gz").read_bytes()).hexdigest(),
               "tests": {}, "public_presto_or_lte_started": False}

    def save():
        (root / "results.json").write_text(json.dumps(results, indent=2))

    def command(name, argv, extra=None, timeout=900):
        child_env = dict(env, **(extra or {}))
        with (root / (name + ".log")).open("w") as log:
            try:
                status = subprocess.run(argv, cwd=source, env=child_env, stdin=subprocess.DEVNULL,
                                        stdout=log, stderr=log, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                status = "timeout"
        results["tests"][name] = status
        save()
        print(name, status, flush=True)
        if status:
            raise RuntimeError(name + " failed; evidence preserved")

    namespace = "omhy-presto-" + root.name
    namespace_created = False
    try:
        command("python-deps", [str(tools / "uv"), "sync", "--locked", "--python", "/usr/bin/python3"])
        command("preflight", ["go", "test", "-p", "1", "-count=1", "-timeout=3m", "-v", "./extras/obfs", "./app/cmd", "-run=Presto"])
        command("native-grammar", ["go", "test", "-p", "1", "-count=1", "-timeout=6m", "-v", "./extras/obfs", "-run=^TestPrestoTrafficGrammarExperiment$"],
                {"OMHY_PRESTO_TRACE_DIR": str(root / "traces")})
        command("analyze", ["python3", "tests/network/presto_analyze.py", str(root / "traces"), "--output", str(root / "grammar-summary.json")])
        command("modules", ["go", "test", "-p", "1", "-count=1", "-timeout=5m", "./core/...", "./extras/...", "./app/..."])
        command("race", ["go", "test", "-p", "1", "-race", "-count=1", "-timeout=5m", "./extras/obfs", "./core/internal/pmtud", "./app/cmd", "-run=Presto|Blink|Gecko|Salamander|PacketConnLimits"])
        for name, duration in (("Decode", 20), ("Receive", 20), ("AuthenticatedState", 30)):
            command("fuzz-" + name.lower(), ["go", "test", "-p", "1", "-run=^$", "-fuzz=^FuzzPresto" + name + "$", "-fuzztime=" + str(duration) + "s", "-parallel=2", "./extras/obfs"])
        command("coverage", ["go", "test", "-p", "1", "-count=1", "-coverprofile=" + str(root / "coverage.out"), "./extras/obfs"])
        command("planner-bench", ["go", "test", "-p", "1", "-run=^$", "-bench=^BenchmarkPrestoPlanner$", "-benchmem", "-benchtime=2s", "./extras/obfs"])
        command("vet", ["go", "vet", "-p", "1", "./core/...", "./extras/...", "./app/..."])
        command("python", ["python3", "-m", "unittest", "discover", "-s", "tests"])
        command("build-integration", ["go", "test", "-p", "1", "-c", "-o", str(root / "cmd.test"), "./app/cmd"])
        subprocess.run(["ip", "netns", "add", namespace], check=True)
        namespace_created = True
        subprocess.run(["ip", "-n", namespace, "link", "set", "lo", "up", "mtu", "1280"], check=True)
        subprocess.run(["ip", "netns", "exec", namespace, "tc", "qdisc", "add", "dev", "lo", "root", "netem", "delay", "20ms"], check=True)
        command("isolated-mtu1280-delay", ["ip", "netns", "exec", namespace, str(root / "cmd.test"), "-test.run=^TestPrestoTLSAndTransfer$", "-test.timeout=3m", "-test.v"])
    except Exception as exc:
        results["error"] = str(exc)
    finally:
        if namespace_created:
            pids = subprocess.check_output(["ip", "netns", "pids", namespace], text=True).split()
            results["namespace_remaining_pids"] = pids
            if not pids:
                subprocess.run(["ip", "netns", "delete", namespace], check=True)
        results["udp443"] = subprocess.check_output(["ss", "-H", "-lunp", "sport = :443"], text=True).strip()
        results["namespaces"] = subprocess.check_output(["ip", "netns", "list"], text=True).strip()
        owned = []
        for proc in Path("/proc").iterdir():
            if not proc.name.isdigit() or int(proc.name) == os.getpid():
                continue
            try:
                if (proc / "stat").read_text().split()[2] == "Z":
                    continue
                if str(root).encode() in (proc / "cmdline").read_bytes() or (proc / "cwd").resolve().is_relative_to(root):
                    owned.append(int(proc.name))
            except (FileNotFoundError, PermissionError, ProcessLookupError):
                pass
        results["owned_processes"] = owned
        save()
        with tarfile.open(root / "evidence.tar.gz", "w:gz") as archive:
            for path in root.iterdir():
                if path.suffix in (".log", ".json", ".out") or path.name == "traces":
                    archive.add(path, arcname=path.name)
    print(json.dumps(results, indent=2), flush=True)
    raise SystemExit(bool(results.get("error")) or bool(results["udp443"]) or bool(results["namespaces"]) or bool(results["owned_processes"]))


if __name__ == "__main__":
    main()
