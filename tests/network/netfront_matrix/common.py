# SPDX-License-Identifier: MIT-0
"""Publicly reproducible inputs and reconciliation. No network or credentials."""
import hashlib
import math
import struct


SIZES = (16, 32, 64, 112, 48, 80, 24, 56, 96, 40, 256, 1056)
MODES = ("presto", "netfront2", "netfront3")
ORDERS = ((0, 1, 2), (1, 2, 0), (2, 0, 1), (2, 1, 0), (0, 2, 1), (1, 0, 2))
EARLY = 9 * 1024 * 1024 // 2
HARD = 6 * 1024 * 1024
MAX_SECONDS = 300


def cases():
    for i, order in enumerate(ORDERS):
        for index in order:
            yield f"b{i+1}-{MODES[index]}", i % 3, MODES[index], "short"
    for mode in ("presto", "netfront3"):
        yield f"renew-{mode}", 1, mode, "renew"


def nmessages(load):
    return {"short": 72, "renew": 180, "local-fault": 384}[load]


def send_at(i, load):
    if load == "short":
        return (i // 6) * .2 + (i % 6) * .023
    if load == "local-fault":
        return i*.125
    return (i // 4) * .6 + (0., .025, .060, .120)[i % 4]


def udp_payload(tag, i):
    header = tag + struct.pack(">H", i)
    return header + hashlib.shake_256(header).digest(SIZES[i % len(SIZES)] - len(header))


def decode_id(b, tag, count):
    if len(b) < 10 or b[:8] != tag:
        return None
    i = int.from_bytes(b[8:10], "big")
    return i if i < count and b == udp_payload(tag, i) else None


def obfuscation(cfg):
    which = "presto" if cfg["mode"] == "presto" else "netfront"
    opts = {"password": cfg["psk"]}
    if which == "netfront":
        opts["extraPorts"] = cfg["ports"][1:]
    return {"type": which, which: opts}


def reconcile(client, server, count):
    points = [client["sent"], server["received"], server["replied"], client["received"]]
    sets = list(map(set, points))
    return {
        "counts": [len(s) for s in sets],
        "not_submitted": sorted(set(range(count)) - sets[0]),
        "missing_before_echo": sorted(sets[0] - sets[1]),
        "missing_echo_write": sorted(sets[1] - sets[2]),
        "missing_after_echo": sorted(sets[2] - sets[3]),
        "unexpected": [sorted(b-a) for a,b in zip(sets, sets[1:])],
        "duplicates": [len(p)-len(s) for p,s in zip(points,sets)],
        "bad_payloads": client["bad_payloads"] + server["bad_payloads"],
    }


def epoch_proofs(row):
    """Same (client-session label, sequence) proven in both directions."""
    rx, tx = row["rx"]["epochs"], row["tx"]["epochs"]
    return sorted(k for k in rx.keys() & tx.keys()
                  if rx[k].get("probe") and tx[k].get("offer")
                  and (rx[k].get("data") or rx[k].get("cover"))
                  and (tx[k].get("data") or tx[k].get("cover")))


def renewed(epochs):
    generations = {}
    for key in epochs:
        session, seq = key.split(":")
        generations.setdefault(session,set()).add(int(seq))
    return any(len(s)>1 for s in generations.values())


def observations(cfg, client, meter):
    """Separate unusable measurements and integrity failures from ordinary UDP loss."""
    issues = []
    if client.get("error") or meter.get("error"):
        issues.append("client/monitor error")
    if not client["tcp_ok"] or client["connections"] != 1 or meter["echo"]["tcp_bytes"] != [16384,16384]:
        issues.append("TLS/TCP through one connection")
    if meter["capture_drops"] or meter["echo"]["write_errors"]:
        issues.append("capture or echo write error")
    f = reconcile(client, meter["echo"], nmessages(cfg["load"]))
    if f["bad_payloads"] or any(f["duplicates"]) or any(f["unexpected"]) or f["not_submitted"] or f["missing_echo_write"]:
        issues.append("four-point integrity")
    ports = cfg["ports"]
    rows = [meter["ports"][str(p)] for p in ports]
    if not all(rows[0][d]["packets"] and rows[0][d]["max_udp"] <= 1232 for d in ("rx","tx")):
        issues.append("primary bounds")
    for d in ("rx","tx"):
        if rows[0][d]["packets"] <= sum(r[d]["packets"] for r in rows[1:]):
            issues.append("not primary-majority " + d)
    for i,r in enumerate(rows[1:],1):
        epochs = epoch_proofs(r)
        if not epochs:
            issues.append(f"lane {i} lacks two-way proof")
        if cfg["load"] == "renew" and not renewed(epochs):
            issues.append(f"lane {i} lacks proven renewal")
        if any(r[d]["max_udp"] > 384 or r[d]["kinds"].get("other",0) for d in ("rx","tx")):
            issues.append(f"lane {i} wire")
    return f, issues


def percentile(values, q):
    ordered = sorted(values)
    return round(ordered[max(0,math.ceil(len(ordered)*q)-1)], 2) if ordered else None
