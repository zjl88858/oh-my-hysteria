# SPDX-License-Identifier: MIT-0
"""Receiver-measured file transfers through the real OMHY CLI. IPv4 loopback only."""
import argparse
from contextlib import contextmanager
import hashlib
import itertools
import json
import os
from pathlib import Path
import secrets
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent / "netfront_matrix"))
from local_cases import certificate

LO = "127.0.0.1"
MIB = 1 << 20
CC = {"type": "bbr3", "bbrProfile": "standard"}
BLOCKS = (("A", "up"), ("B", "down"), ("C", "up"), ("A", "down"), ("B", "up"), ("C", "down"))


def plan():
    # Each side-count pair stays adjacent, standard goes first in three of
    # its six comparisons. Each family occupies each block position twice.
    rows = []
    for i, ((key, direction), order) in enumerate(zip(BLOCKS, itertools.permutations((0, 2, 3)))):
        for sides in order:
            base = "netfront" if sides else "presto"
            for lite in ((i + (sides == 2)) % 2, (i + (sides == 2) + 1) % 2):
                rows.append({"key": key, "direction": direction, "mode": base + ("lite" if lite else ""), "sides": sides})
    return rows


def dump(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def exact(sock, n):
    out = bytearray()
    while len(out) < n:
        buf = sock.recv(n - len(out))
        if not buf:
            raise EOFError("incomplete receipt")
        out.extend(buf)
    return bytes(out)


@contextmanager
def cli(exe, role, tmp, config, marker):
    path = tmp / (role + ".json")
    dump(path, config)
    p = subprocess.Popen([str(exe), role, "-c", str(path), "-f", "json"], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    ready = threading.Event()
    tx = []
    errors = []

    def read_logs():
        for line in p.stderr:
            if not line.startswith(b"{"):
                continue
            rec = json.loads(line)
            if rec.get("msg") == "connected to server":
                tx.append(rec.get("tx"))
            if rec.get("msg") == marker:
                ready.set()
            if rec.get("level") in ("error", "fatal"):
                errors.append(rec.get("msg", "error"))

    th = threading.Thread(target=read_logs, daemon=True)
    th.start()
    try:
        if not ready.wait(6) or p.poll() is not None:
            raise RuntimeError(f"{role} did not become ready: {errors}")
        yield tx
    finally:
        if p.poll() is None:
            p.terminate()
        try:
            p.wait(2)
        except subprocess.TimeoutExpired:
            p.kill()
            p.wait()
        th.join(2)
        p.stderr.close()
        path.unlink(missing_ok=True)


def udp_ports(n):
    socks = []
    try:
        for _ in range(n):
            sock = socket.socket(type=socket.SOCK_DGRAM)
            socks.append(sock)
            sock.bind((LO, 0))
        return [s.getsockname()[1] for s in socks]
    finally:
        for sock in socks:
            sock.close()


def transfer(exe, tmp, fixture, digest, row):
    n = fixture.stat().st_size
    stamps = []
    issues = []

    def exchange(sock, send):
        sock.settimeout(25)
        if send:
            if exact(sock, 1) != b"G":
                raise ValueError("bad file request")
            with fixture.open("rb") as f:
                while chunk := f.read(256 << 10):
                    sock.sendall(chunk)
            if exact(sock, 32) != digest:
                raise ValueError("wrong receiver digest")
            sock.sendall(b"Y")
        else:
            buf = memoryview(bytearray(256 << 10))
            h = hashlib.sha256()
            stamps.append(time.perf_counter_ns())
            sock.sendall(b"G")
            for _ in range(4):
                left = n // 4
                while left:
                    got = sock.recv_into(buf[:min(left, len(buf))])
                    if not got:
                        raise EOFError("incomplete file")
                    h.update(buf[:got])
                    left -= got
                stamps.append(time.perf_counter_ns())
            if h.digest() != digest:
                raise ValueError("receiver SHA256 mismatch")
            sock.sendall(h.digest())
            if exact(sock, 1) != b"Y":
                raise ValueError("receipt not acknowledged")

    with socket.socket() as origin:
        origin.bind((LO, 0))
        origin.listen(1)
        origin.settimeout(12)
        target = origin.getsockname()[1]
        with socket.socket() as s:
            s.bind((LO, 0))
            entry = s.getsockname()[1]
        ports = udp_ports(1 + row["sides"])
        addr = f"{LO}:{ports[0]}"
        kind = row["mode"]
        password = hashlib.sha256(("OMHY: public loopback-only QA fixture: " + row["key"]).encode()).hexdigest()
        opts = {"password": password}
        if row["sides"]:
            opts["extraPorts"] = ports[1:]
        obfs = {"type": kind, kind: opts}
        auth = secrets.token_urlsafe(32)
        server = {"listen": addr, "auth": {"type": "password", "password": auth}, "obfs": obfs, "congestion": CC,
                  "ignoreClientBandwidth": True, "tls": {"cert": str(tmp/"server.pem"), "key": str(tmp/"server.key")},
                  "acl": {"rules": [{"outbound": "direct", "match": f'proto == "tcp" && dst.host == "{LO}" && dst.port == {target}'},
                                    {"outbound": "reject", "match": "true"}]}}
        client = {"server": addr, "auth": auth, "obfs": obfs, "congestion": CC,
                  "tls": {"sni": "netfront.test.invalid", "ca": str(tmp/"ca.pem")},
                  "tcpForwarding": [{"listen": f"{LO}:{entry}", "remote": f"{LO}:{target}"}]}

        def serve():
            try:
                conn, _ = origin.accept()
                with conn:
                    exchange(conn, row["direction"] == "down")
            except (OSError, EOFError, ValueError) as e:
                issues.append(str(e))

        with cli(exe, "server", tmp, server, "server up and running"):
            with cli(exe, "client", tmp, client, "TCP forwarding listening") as tx:
                th = threading.Thread(target=serve, daemon=True)
                th.start()
                try:
                    with socket.create_connection((LO, entry), timeout=6) as app:
                        exchange(app, row["direction"] == "up")
                finally:
                    th.join(28)
                if th.is_alive() or issues or len(stamps) != 5 or tx != [0]:
                    raise RuntimeError(f"file or negotiation incomplete: {issues}; tx={tx}")
    mbps = lambda amount, ns: round(amount * 8000 / ns, 3)
    return {**row, "success": True, "negotiated_tx": 0, "received_bytes": n, "sha256": digest.hex(),
            "mbps": mbps(n, stamps[-1] - stamps[0]), "elapsed_ns": stamps[-1] - stamps[0],
            "windows_mbps": [mbps(n//4, b-a) for a, b in zip(stamps, stamps[1:])]}


def summarize(out, rows):
    by = {(r["key"], r["direction"], r["mode"], r["sides"]): r for r in rows}
    summary = []
    for sides in (0, 2, 3):
        base = "netfront" if sides else "presto"
        for direction in ("up", "down"):
            pairs = [(by[k, direction, base, sides], by[k, direction, base+"lite", sides]) for k in "ABC"]
            med = statistics.median
            summary.append({"standard": base, "lite": base+"lite", "sides": sides, "direction": direction,
                "standard_median": med(x["mbps"] for x,y in pairs), "lite_median": med(y["mbps"] for x,y in pairs),
                "paired_ratios": [round(y["mbps"]/x["mbps"], 3) for x,y in pairs],
                "standard_values": [x["mbps"] for x,y in pairs], "lite_values": [y["mbps"] for x,y in pairs],
                "standard_tail_median": med(3/sum(1/v for v in x["windows_mbps"][1:]) for x,y in pairs),
                "lite_tail_median": med(3/sum(1/v for v in y["windows_mbps"][1:]) for x,y in pairs)})
    dump(out/"summary.json", summary)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--exe", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--temp-parent", type=Path)
    parser.add_argument("--mib", type=int, default=64)
    a = parser.parse_args()
    if a.mib < 4 or a.mib % 4:
        parser.error("--mib must be a positive multiple of four")
    a.output.mkdir(parents=True, exist_ok=False)
    exe = a.exe.resolve()
    os.environ["OH_MY_HYSTERIA_BBR3_DEBUG"] = "0"
    runs = plan()
    rows = []
    with tempfile.TemporaryDirectory(prefix="omhy-lite-modes-", dir=a.temp_parent) as work:
        tmp = Path(work)
        certificate(tmp)
        fixture = tmp/"fixture.bin"
        h = hashlib.sha256()
        with fixture.open("xb") as f:
            for _ in range(a.mib):
                b = os.urandom(MIB)
                f.write(b)
                h.update(b)
        dump(a.output/"plan.json", {"cases": runs, "bytes_per_file": a.mib*MIB, "fixture_sha256": h.hexdigest(),
             "loopback": LO, "cc": CC, "app": "SHA256-confirmed TCP forwarding; receiver timer, 4 equal windows",
             "exe_sha256": hashlib.sha256(exe.read_bytes()).hexdigest(), "version": subprocess.check_output([str(exe), "version"], text=True)})
        for i, row in enumerate(runs, 1):
            try:
                result = transfer(exe, tmp, fixture, h.digest(), row)
            except (OSError, RuntimeError, EOFError, ValueError) as e:
                result = {**row, "success": False, "error": str(e)}
            rows.append(result)
            dump(a.output/"cases.json", rows)
            print(i, row["key"], row["direction"], row["mode"], row["sides"], result.get("mbps", result.get("error")), flush=True)
    if not all(row["success"] for row in rows):
        raise SystemExit(1)
    assert len(rows) == 36 and all(x["received_bytes"] == a.mib*MIB and x["sha256"] == h.hexdigest() for x in rows)
    summarize(a.output, rows)


if __name__ == "__main__":
    main()
