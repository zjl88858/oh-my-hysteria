#!/usr/bin/env python3
# SPDX-License-Identifier: MIT-0
"""Bounded, Gecko-only Linux QUIC benchmark in isolated network namespaces.

No default routes, NAT or public-interface qdiscs are created. Requires root,
iproute2, ping, and a locally built oh-my-hysteria binary. The private server
template supplies obfs/auth and TLS cert/key paths; it is never copied to output.
"""

import argparse
import json
import os
from pathlib import Path
import random
import signal
import subprocess
import tempfile
import threading
import time
import uuid


MODES = {
    "geodesic": {"type": "geodesic"},
    "copa": {"type": "copa"},
    "bbr": {"type": "bbr", "slowStart": "legacy", "bbrProfile": "standard"},
    "bbr3": {"type": "bbr3"},
    "bbr3-conservative": {"type": "bbr3", "bbrProfile": "conservative"},
    "bbr3-aggressive": {"type": "bbr3", "bbrProfile": "aggressive"},
    "cubic-legacy": {"type": "cubic", "slowStart": "legacy"},
    "cubic-hystart": {"type": "cubic", "slowStart": "hystart++"},
    "reno-legacy": {"type": "reno", "slowStart": "legacy"},
    "reno-hystart": {"type": "reno", "slowStart": "hystart++"},
}

# Keep the original default workload; profile experiments require explicit modes.
DEFAULT_MODES = ["bbr", "bbr3", "cubic-legacy", "cubic-hystart", "reno-legacy", "reno-hystart"]


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, **kwargs).stdout


def log_records(text):
    result = []
    for line in text.splitlines():
        try:
            entry = json.loads(line)
            if isinstance(entry, dict):
                result.append(entry)
        except json.JSONDecodeError:
            pass
    return result


def transfer_summary(text):
    return [entry for entry in log_records(text)
            if entry.get("msg") in ("download complete", "upload complete")]


def transfer_valid(status, records, size):
    return (status == 0 and len(records) == 2
            and {entry.get("msg") for entry in records} == {"download complete", "upload complete"}
            and all(entry.get("bytes") == size for entry in records))


def stop(process):
    if process is not None and process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()


class Network:
    def __init__(self):
        self.prefix = "omh" + uuid.uuid4().hex[:6]
        self.names = {role: self.prefix + role for role in ("c", "r", "s")}
        self.created = []
        self.links = []

    def run(self, role, args, **kwargs):
        return command(["ip", "netns", "exec", self.names[role], *args], **kwargs)

    def setup(self):
        for name in self.names.values():
            command(["ip", "netns", "add", name])
            self.created.append(name)
            command(["ip", "-n", name, "link", "set", "lo", "up"])
        for edge, subnet in (("c", "1"), ("s", "2")):
            left, right = self.prefix + edge, self.prefix + "r" + edge
            command(["ip", "link", "add", left, "type", "veth", "peer", "name", right])
            self.links.append(left)
            command(["ip", "link", "set", left, "netns", self.names[edge]])
            command(["ip", "link", "set", right, "netns", self.names["r"]])
            for role, device, address in ((edge, left, "2"), ("r", right, "1")):
                self.run(role, ["ip", "link", "set", device, "name", "eth" + edge])
                self.run(role, ["ip", "addr", "add", f"10.203.{subnet}.{address}/30", "dev", "eth" + edge])
                self.run(role, ["ip", "link", "set", "eth" + edge, "up"])
                # GSO/GRO can make emulated packet loss and queues unrealistic.
                self.run(role, ["ethtool", "-K", "eth" + edge, "tso", "off", "gso", "off", "gro", "off"])
        self.run("c", ["ip", "route", "add", "10.203.2.0/30", "via", "10.203.1.1"])
        self.run("s", ["ip", "route", "add", "10.203.1.0/30", "via", "10.203.2.1"])
        self.run("r", ["sysctl", "-q", "-w", "net.ipv4.ip_forward=1"])

    def shape(self, rate_mbit, rtt_ms, queue_ms, loss_percent):
        for role in ("c", "s"):
            self.run(role, ["tc", "qdisc", "replace", "dev", "eth" + role,
                            "root", "netem", "delay", f"{rtt_ms / 2:g}ms",
                            "loss", f"{loss_percent:g}%", "limit", "10000"])
        # Separate FIFO bottleneck from propagation delay in each direction.
        limit = max(32768 + 1500, int(rate_mbit * 1_000_000 / 8 * queue_ms / 1000))
        for edge in ("c", "s"):
            self.run("r", ["tc", "qdisc", "replace", "dev", "eth" + edge,
                            "root", "tbf", "rate", f"{rate_mbit:g}mbit",
                            "burst", "32kb", "limit", str(limit)])

    def stats(self):
        return {role + edge: json.loads(self.run(role, ["tc", "-s", "-j", "qdisc", "show", "dev", "eth" + edge]))
                for role, edge in (("c", "c"), ("s", "s"), ("r", "c"), ("r", "s"))}

    def close(self):
        for name in reversed(self.created):
            subprocess.run(["ip", "netns", "delete", name], capture_output=True)
        # Handle failures before a newly created veth was moved into its namespace.
        for name in self.links:
            subprocess.run(["ip", "link", "delete", name], capture_output=True)


def client_run(network, binary, config, output, tag, size, path_change=None):
    args = ["ip", "netns", "exec", network.names["c"], str(binary),
            "speedtest", "-c", str(config), "--data-size", str(size), "--log-format", "json"]
    started = time.monotonic()
    change = {"applied": False, "error": None} if path_change else None
    timer = None
    if path_change:
        def apply_change():
            try:
                network.shape(*path_change)
                change.update(applied=True, elapsed_seconds=time.monotonic() - started,
                              target=dict(zip(("rate_mbit", "rtt_ms", "queue_ms", "loss_percent"), path_change)))
            except Exception as exc:
                change["error"] = str(exc)
        timer = threading.Timer(2, apply_change)
        timer.daemon = True
        timer.start()
    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=120)
        text = result.stdout + result.stderr
        status = result.returncode
    except subprocess.TimeoutExpired as exc:
        text = (exc.stdout or b"").decode() + (exc.stderr or b"").decode()
        status = "timeout"
    finally:
        if timer is not None:
            timer.cancel()
            timer.join()
    (output / (tag + ".log")).write_text(text)
    records = transfer_summary(text)
    valid = transfer_valid(status, records, size)
    if change is not None:
        valid = valid and change["applied"] and change["error"] is None
    return {"mode": tag, "status": status, "valid": valid, "bytes_per_direction": size,
            "wall_seconds": time.monotonic() - started, "transfers": records,
            **({"path_change": change} if change is not None else {})}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--server-template", type=Path, required=True)
    parser.add_argument("--server-name", required=True, help="DNS name on the existing TLS certificate")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--data-size", type=int, default=4 * 1024 * 1024)
    parser.add_argument("--seed", type=int, default=9406)
    parser.add_argument("--modes", nargs="+", choices=list(MODES), default=DEFAULT_MODES)
    parser.add_argument("--stress", action="store_true", help="also test 80/350 ms RTT with 1%% random loss (isolated namespaces only)")
    parser.add_argument("--path-change", action="store_true", help="also step isolated RTT 80->240 / 240->80 ms after two seconds")
    parser.add_argument("--path-change-data-size", type=int, help="optional 4..32 MiB per direction for RTT-step samples only")
    options = parser.parse_args()
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        parser.error("network namespaces require root")
    if not 1 <= options.repeats <= 10 or not 0 < options.data_size <= 32 * 1024 * 1024:
        parser.error("bounded runs require repeats 1..10 and data-size <=32 MiB")
    if options.path_change_data_size is not None and (not options.path_change or not 4 * 1024 * 1024 <= options.path_change_data_size <= 32 * 1024 * 1024):
        parser.error("--path-change-data-size requires --path-change and a size within 4..32 MiB")
    change_size = options.path_change_data_size if options.path_change_data_size is not None else options.data_size
    if options.path_change and change_size < 4 * 1024 * 1024:
        parser.error("--path-change requires at least 4 MiB per direction so the scheduled step can occur")
    template = json.loads(options.server_template.read_text())
    if template.get("obfs", {}).get("type") != "gecko":
        parser.error("refusing a non-Gecko server template")
    if not template.get("tls", {}).get("cert") or not template.get("tls", {}).get("key"):
        parser.error("provide existing TLS certificate/key (no ACME in isolated network)")
    options.binary = options.binary.resolve()
    options.output.mkdir(parents=True, exist_ok=False)
    randomizer = random.Random(options.seed)
    network = Network()
    # Give finally blocks a chance to stop owned processes and remove namespaces.
    def interrupted(signum, frame):
        raise KeyboardInterrupt(f"signal {signum}")

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGHUP, interrupted)
    scenarios = [("rtt200-shallow", 10, 200, 50, 0),
                 ("rtt200-deep", 10, 200, 400, 0),
                 ("rtt200-loss01", 10, 200, 100, 0.1)]
    if options.stress:
        scenarios.extend([("rtt80-loss1", 20, 80, 40, 1),
                           ("rtt350-loss1", 5, 350, 150, 1)])
    changes = {}
    if options.path_change:
        scenarios.extend([("rtt80-to240", 10, 80, 100, 0),
                          ("rtt240-to80", 10, 240, 100, 0)])
        changes = {"rtt80-to240": (10, 240, 100, 0), "rtt240-to80": (10, 80, 100, 0)}
    results = {"metadata": {"rate_unit": "Mbit/s", "gecko": True,
                             "bytes_per_direction": options.data_size, "repeats": options.repeats,
                             "order_seed": options.seed, "scenarios": scenarios,
                             "path_changes": changes,
                             "path_change_bytes_per_direction": change_size if changes else None,
                             "limitations": "TBF burst 32KiB; stochastic netem loss; single shared VM CPU; no fairness claim"},
               "runs": []}
    try:
        network.setup()
        with tempfile.TemporaryDirectory(prefix="omhy-gecko-") as scratch:
            os.chmod(scratch, 0o700)
            for scenario, rate, rtt, queue, loss in scenarios:
                network.shape(rate, rtt, queue, loss)
                baseline = network.run("c", ["ping", "-n", "-c", "5", "-i", "0.2", "10.203.2.2"])
                (options.output / (scenario + "-ping.log")).write_text(baseline)
                for repeat in range(options.repeats):
                    modes = list(options.modes)
                    randomizer.shuffle(modes)
                    for mode in modes:
                        if scenario in changes:
                            network.shape(rate, rtt, queue, loss)
                        tag = f"{scenario}-{repeat + 1}-{mode}"
                        server_config = {"listen": "10.203.2.2:24443", "tls": template["tls"],
                                         "obfs": template["obfs"], "auth": template["auth"],
                                         "congestion": MODES[mode], "ignoreClientBandwidth": True, "speedTest": True}
                        client_config = {"server": "10.203.2.2:24443", "tls": {"sni": options.server_name},
                                         "obfs": template["obfs"], "auth": template["auth"]["password"],
                                         "congestion": MODES[mode]}
                        server_file, client_file = Path(scratch) / "server.json", Path(scratch) / "client.json"
                        for path, data in ((server_file, server_config), (client_file, client_config)):
                            path.write_text(json.dumps(data))
                            path.chmod(0o600)
                        server = ping = None
                        before = network.stats()
                        with (options.output / (tag + "-server.log")).open("w") as log:
                            try:
                                server = subprocess.Popen(["ip", "netns", "exec", network.names["s"],
                                                           str(options.binary), "server", "-c", str(server_file),
                                                           "--log-format", "json"], stdout=log, stderr=log)
                                time.sleep(0.25)
                                if server.poll() is not None:
                                    raise RuntimeError(f"server exited; see {tag}-server.log")
                                with (options.output / (tag + "-loaded-ping.log")).open("w") as pinglog:
                                    ping = subprocess.Popen(["ip", "netns", "exec", network.names["c"],
                                                             "ping", "-n", "-i", "0.2", "10.203.2.2"],
                                                            stdout=pinglog, stderr=pinglog)
                                    size = change_size if scenario in changes else options.data_size
                                    entry = client_run(network, options.binary, client_file, options.output, tag, size,
                                                       path_change=changes.get(scenario))
                            finally:
                                stop(ping)
                                stop(server)
                        entry.update(scenario=scenario, repeat=repeat + 1, algorithm=mode,
                                     qdisc_before=before, qdisc_after=network.stats())
                        results["runs"].append(entry)
                        (options.output / "results.json").write_text(json.dumps(results, indent=2))
                        print(json.dumps({k: entry[k] for k in ("mode", "status", "wall_seconds", "transfers")}), flush=True)
                        if not entry["valid"]:
                            raise RuntimeError(f"incomplete transfer; see {tag}.log")
    finally:
        network.close()


if __name__ == "__main__":
    main()
