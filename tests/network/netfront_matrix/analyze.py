# SPDX-License-Identifier: MIT-0
"""Audit individual receipts before issuing the predeclared release recommendation."""
import argparse
import hashlib
import json
from pathlib import Path
import re

from common import MODES, cases, epoch_proofs, nmessages, observations


def functional(field, field_hash, summary, apps, interop):
    from matrix import previous_ledger
    from proxy_app import passed
    candidate = field["sha256"]
    nf = [r for r in field["records"] if r["public"] and r["mode"] != "presto"]
    app_rows = [r for r in apps["records"] if r["public"]]
    checks = {
        "same_real_candidate": candidate == apps["sha256"] and all("v1.2.1+netfront.2" in x["linux_version"] for x in (field,apps)),
        "linked_receipts": apps["seed_sha256"] == field_hash and apps["seed"] == field["ledger"]
                          and apps["ledger"] == previous_ledger(apps,field["host_key"]),
        "transport_matrix_complete": len(summary["rows"]) == 20 and len(nf) == 13 and not field.get("failure"),
        "netfront_proxy_transport": all(r["client"]["tcp_ok"] and r["client"]["connections"]==1
                                        and not r["issues"] and r["four"]["counts"][3]>0 and
                                        not r["four"]["bad_payloads"] and not any(r["four"]["duplicates"]) for r in nf),
        "controlled_recovery_and_rotation": not any(r["issues"] for r in summary["controls"]) and bool(summary["rotations"]),
        "mixed_versions_and_rejections": [r["case"] for r in interop]==["client1-server2","client2-server1","wrong-ca","wrong-auth","wrong-obfs"]
                                         and all(r["passed"] for r in interop),
        "application_cases_complete": [r["mode"] for r in app_rows]==list(MODES[1:]) and not apps.get("failure"),
        "origin_verified_transactions": all(passed(r["client"],r["meter"],{
            "page_hash":r["origin_expected_sha256"]["page"],"file_hash":r["origin_expected_sha256"]["file"],
        }) for r in apps["records"]),
        "bounded_and_cleaned": not apps["unknown_public_cost"] and apps["ledger"]["bytes"]<apps["limits"]["early_bytes"]
                               and apps["ledger"]["ms"]<apps["limits"]["ms"] and all(
                                   x["cleanup"]["temporary_directory_removed"] and not x["cleanup"]["owned_processes_after"] and
                                   all(x["cleanup"]["ports_free"].values()) for x in (field,apps)),
    }
    return dict(passed=all(checks.values()),checks=checks,netfront_transport_sessions=len(nf),
                public_application_results=[{k:r["client"][k] for k in ("connections","http_get","https_connect","socks5_https","socks5_dns")} for r in app_rows],
                final_ledger=apps["ledger"],application_cost={k:v-apps["seed"][k] for k,v in apps["ledger"].items()})


def analyze(raw, controls, rotation):
    gates=[]; rows=[]; totals={};ledger=raw["seed"].copy()
    public=[r for r in raw["records"] if r["public"]]
    if [r["label"] for r in public] != [x[0] for x in cases()]:gates.append("incomplete planned public sample")
    linux=[r for r in raw["records"] if not r["public"]]
    if len(linux)!=3 or raw.get("native_linux_tests")!="pass":gates.append("native Linux controls incomplete")
    for r in raw["records"]:
        if not all(k in r for k in ("client","meter","four")):
            gates.append(r["label"]+": no final receipt");continue
        m,c=r["meter"],r["client"];ports=[int(p) for p in m["ports"]]
        f,issues=observations({**r,"ports":ports},c,m)
        if (f,issues)!=(r["four"],r["issues"]):gates.append(r["label"]+": receipt reconciliation mismatch")
        for s in issues:gates.append(r["label"]+": "+s)
        measures=[(i,d,m["ports"][str(p)][d]) for i,p in enumerate(ports) for d in ("rx","tx")]
        if sum(x["packets"] for _,_,x in measures)!=m["packets"] or sum(x["ip_bytes"] for _,_,x in measures)!=m["ipv4_bytes"]:
            gates.append(r["label"]+": port sum mismatch")
        if not r["public"]:
            if f["counts"]!=[nmessages(r["load"])]*4:gates.append(r["label"]+": loopback loss")
            continue
        for name,val in (("bytes",m["ipv4_bytes"]),("packets",m["packets"]),("ms",m["active_ms"])):ledger[name]+=val
        item={k:r[k] for k in ("label","mode","key","load")}
        item.update(four=f["counts"],up=f["missing_before_echo"],down=f["missing_after_echo"],bytes=m["ipv4_bytes"],
                    packets=m["packets"],main_packets=sum(x["packets"] for i,_,x in measures if i==0),
                    side_data={d:sum(x["kinds"].get("data",0) for i,dx,x in measures if i and dx==d) for d in ("rx","tx")},
                    side_epochs={p:epoch_proofs(m["ports"][str(p)]) for p in ports[1:]},
                    side_port_packets=[sum(m["ports"][str(p)][d]["packets"] for d in ("rx","tx")) for p in ports[1:]],
                    max_side_udp=max((x["max_udp"] for i,_,x in measures if i),default=0),
                    client_ready_s=c.get("ready_s"),app_rtt_p50=c.get("rtt_ms_p50"),app_rtt_p95=c.get("rtt_ms_p95"))
        rows.append(item)
    if raw.get("failure"):gates.append("runner: "+raw["failure"])
    if raw.get("unknown_public_cost") or ledger!=raw["ledger"]:gates.append("unreconciled ledger")
    if ledger["bytes"]>=raw["limits"]["early_bytes"] or ledger["ms"]>=raw["limits"]["ms"]:gates.append("budget stop")
    clean=raw.get("cleanup",{})
    if not clean.get("temporary_directory_removed") or not all(clean.get("ports_free",{}).values()) or clean.get("owned_processes_after")!=[]:
        gates.append("cleanup unverified")
    for load in ("short","renew"):
        totals[load]={}
        for mode in (MODES if load=="short" else ("presto","netfront3")):
            subset=[r for r in rows if r["load"]==load and r["mode"]==mode]
            if not subset:continue
            f=list(map(sum,zip(*(r["four"] for r in subset))))
            p=sum(r["packets"] for r in subset);main=sum(r["main_packets"] for r in subset)
            data={d:sum(r["side_data"][d] for r in subset) for d in ("rx","tx")}
            total=dict(cases=len(subset),four=f,before_echo=f[0]-f[1],after_echo=f[2]-f[3],
                       echo_percent=round(100*f[3]/f[0],3) if f[0] else None,
                       ip_bytes=sum(r["bytes"] for r in subset),main_packets=main,packets=p,
                       main_percent=round(100*main/p,2) if p else None,side_data=data)
            totals[load][mode]=total
            if mode!="presto" and min(data.values())<=0:gates.append(load+" "+mode+": real frames not observed in both directions")
            if load=="short" and any(r["four"][3]*10<9*nmessages(load) for r in subset):
                gates.append(mode+": individual delivery below 90%")
    by_mode=totals["short"]
    if "presto" in by_mode:
        for mode in MODES[1:]:
            if mode in by_mode:
                a,b=by_mode[mode]["four"],by_mode["presto"]["four"]
                if min(a[0],b[0]) and 100*(b[3]*a[0]-a[3]*b[0])>2*a[0]*b[0]:
                    gates.append(mode+": observed aggregate deficit exceeds 2 percentage points")
    control_issues=[s for r in controls["cases"] for s in r["issues"]]
    if control_issues:gates+=control_issues
    if len(controls["cases"])!=2 or [r["mode"] for r in controls["bulk"]]!=list(MODES):gates.append("incomplete local tests")
    for r in controls["bulk"]:
        if r["echo_errors"] or [c["bytes_each_direction"] for c in r["clients"]]!=[2097152]*2:gates.append("bulk: "+r["mode"])
    match=re.search(r"actual duration (.*?), (\d+) verified echoes, (\d+) client / (\d+) server sender IDs",rotation)
    if not match or min(map(int,match.groups()[2:]))<2 or "PASS: TestNetFrontLongSocketSoak" not in rotation:
        gates.append("real-clock rotation incomplete")
    return dict(gate_failures=gates,candidate_sha256=raw["sha256"],totals=totals,rows=rows,
                ledger=ledger,seed=raw["seed"],new_public={k:v-raw["seed"][k] for k,v in ledger.items()},
                loopback=[(r["label"],r.get("four",{}).get("counts")) for r in linux],
                rotations=match.groups() if match else None,controls=[{k:c[k] for k in ("load","four","stable_sent","missing_in_stable","issues")} for c in controls["cases"]],
                bulk=controls["bulk"],cleanup=clean)


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("evidence",type=Path);p.add_argument("controls",type=Path)
    p.add_argument("rotation",type=Path);p.add_argument("--output",required=True,type=Path)
    p.add_argument("--apps",type=Path);p.add_argument("--interop",type=Path);a=p.parse_args()
    if bool(a.apps)!=bool(a.interop):p.error("provide both --apps and --interop")
    field=json.loads(a.evidence.read_text())
    r=analyze(field,json.loads(a.controls.read_text()),a.rotation.read_text(encoding="utf-8-sig"))
    r["evidence_sha256"]={f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in (a.evidence,a.controls,a.rotation)}
    if a.apps:
        r["proxy_functional"]=functional(field,hashlib.sha256(a.evidence.read_bytes()).hexdigest(),r,
                                         json.loads(a.apps.read_text()),json.loads(a.interop.read_text()))
        r["evidence_sha256"]["applications"]=hashlib.sha256(a.apps.read_bytes()).hexdigest()
        r["evidence_sha256"]["interop"]=hashlib.sha256(a.interop.read_bytes()).hexdigest()
    a.output.write_text(json.dumps(r,indent=2),encoding="utf-8")
    print(json.dumps({k:r[k] for k in ("gate_failures","totals","new_public","ledger","rotations","cleanup")},indent=2))
    if "proxy_functional" in r:print("Proxy application acceptance:",r["proxy_functional"]["passed"])
