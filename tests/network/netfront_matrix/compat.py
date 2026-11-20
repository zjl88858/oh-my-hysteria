# SPDX-License-Identifier: MIT-0
"""Cross-build compatibility and negative TLS/password controls; loopback only."""
import argparse
import json
from pathlib import Path
import secrets
import tempfile

from client import exercise
from common import reconcile
from endpoint import Echo
from local_cases import LO, certificate, cli, group, server_config


def run(tmp, server_exe, client_exe, case, *, mode="netfront3", client_mode=None):
    cfg=dict(auth=secrets.token_urlsafe(32),psk=secrets.token_urlsafe(40),tag=secrets.token_hex(8),
             mode=mode,load="short",host=LO,ports=group(mode))
    echo=Echo(cfg)
    try:
        with cli(server_exe,"server",tmp/"server-config.json",server_config(tmp,cfg,echo.tp,echo.up),b"server up and running"):
            local={**cfg,"tcp":echo.tp,"udp":echo.up}
            if client_mode is not None:local["mode"]=client_mode
            if case=="wrong-obfs":local["psk"]=secrets.token_urlsafe(40)
            if case=="wrong-auth":local["auth"]=secrets.token_urlsafe(32)
            ca=(tmp/"untrusted" if case=="wrong-ca" else tmp)/"ca.pem"
            app=exercise(client_exe,tmp,ca,local)
    finally:echo.close()
    f=reconcile(app,echo.stats,72)
    negative=case.startswith("wrong-")
    if negative:
        ok=bool(app["error"]) and not app["connections"] and not app["tcp_ok"] and echo.stats["tcp_bytes"]==[0,0] and not any(f["counts"])
    else:
        ok=(app["tcp_ok"] and not app["error"] and app["connections"]==1 and f["counts"]==[72]*4 and
            not f["bad_payloads"] and not any(f["duplicates"]) and not echo.stats["write_errors"])
    return dict(case=case,expected="reject" if negative else "transfer",passed=ok,connections=app["connections"],
                four=f,tcp_bytes=echo.stats["tcp_bytes"],client_error=app["error"])


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("--old",type=Path,required=True);p.add_argument("--new",type=Path,required=True)
    p.add_argument("--output",type=Path,required=True);p.add_argument("--temp-parent",type=Path);a=p.parse_args()
    if a.output.exists():raise FileExistsError(a.output)
    old,new=a.old.resolve(),a.new.resolve();rows=[]
    with tempfile.TemporaryDirectory(dir=a.temp_parent,prefix="nf-interop-") as td:
        tmp=Path(td);certificate(tmp);(tmp/"untrusted").mkdir();certificate(tmp/"untrusted")
        try:
            for name,server,client in [("client1-server2",new,old),("client2-server1",old,new),
                                       ("wrong-ca",new,new),("wrong-auth",new,new),("wrong-obfs",new,new)]:
                r=run(tmp,server,client,name);rows.append(r);print(name,r["passed"],r["four"]["counts"],flush=True)
        finally:a.output.write_text(json.dumps(rows,indent=2),encoding="utf-8")
    if not all(r["passed"] for r in rows):raise SystemExit(1)
