# SPDX-License-Identifier: MIT-0
"""Run one candidate client; only the OMHY executable contacts the remote endpoint."""
import json
import os
from pathlib import Path
import select
import socket
import subprocess
import sys
import threading
import time

from common import decode_id, nmessages, obfuscation, percentile, send_at, udp_payload


def free_port(kind):
    with socket.socket(type=kind) as s:
        s.bind(("127.0.0.1",0))
        return s.getsockname()[1]


def exercise(exe, work, ca, cfg):
    tcp, udp = free_port(socket.SOCK_STREAM), free_port(socket.SOCK_DGRAM)
    conf = {"server":f"{cfg['host']}:{cfg['ports'][0]}", "auth":cfg["auth"],
            "tls":{"sni":"netfront.test.invalid","ca":str(ca)}, "obfs":obfuscation(cfg),
            "congestion":{"type":"bbr","bbrProfile":"standard"},
            "tcpForwarding":[{"listen":f"127.0.0.1:{tcp}","remote":f"127.0.0.1:{cfg['tcp']}"}],
            "udpForwarding":[{"listen":f"127.0.0.1:{udp}","remote":f"127.0.0.1:{cfg['udp']}"}]}
    path=work/"matrix-client-private.json"
    path.write_text(json.dumps(conf),encoding="utf-8")
    start=time.monotonic()
    deadline=start+{"short":10,"renew":37,"local-fault":60}[cfg["load"]]
    ready=threading.Event()
    res={"tcp_ok":False,"tcp_halves":[],"sent":[],"received":[],"bad_payloads":0,"connections":0,"error":None}
    proc=None; reader=None
    try:
        proc=subprocess.Popen([str(exe),"client","-c",str(path)],stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)

        def logs():
            forwards=set()
            for line in proc.stderr:
                if b"connected to server" in line: res["connections"]+=1
                for name in (b"TCP forwarding listening", b"UDP forwarding listening"):
                    if name in line: forwards.add(name)
                if len(forwards)==2: ready.set()
            ready.set()
        reader=threading.Thread(target=logs,daemon=True);reader.start()
        if not ready.wait(5.5) or proc.poll() is not None:
            raise RuntimeError("client exited or forwards did not become ready")
        res["ready_s"]=round(time.monotonic()-start,3)
        with socket.create_connection(("127.0.0.1",tcp),timeout=3) as stream:
            def echo_half():
                data=os.urandom(8192)
                stream.settimeout(max(.01,min(4,deadline-time.monotonic())))
                stream.sendall(data); got=bytearray()
                while len(got)<len(data):
                    part=stream.recv(len(data)-len(got))
                    if not part: raise RuntimeError("premature EOF in the same TCP stream")
                    got.extend(part)
                if got!=data:raise RuntimeError("TCP content mismatch")
                res["tcp_halves"].append(len(data))
            echo_half()
            tag=bytes.fromhex(cfg["tag"]);count=nmessages(cfg["load"])
            with socket.socket(type=socket.SOCK_DGRAM) as sock:
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1<<20)
                sock.bind(("127.0.0.1",0));sock.connect(("127.0.0.1",udp));sock.setblocking(False)
                t0=time.monotonic();stamps={};rtts=[];i=0;end=None;late=0.
                res["udp_start_s"]=round(t0-start,3)
                while True:
                    now=time.monotonic()
                    if now>=deadline:raise TimeoutError("foreground deadline")
                    if end is not None and now>=end:break
                    if i<count and now>=t0+send_at(i,cfg["load"]):
                        b=udp_payload(tag,i)
                        if sock.send(b)!=len(b):raise IOError("short UDP send")
                        stamps[i]=time.monotonic()
                        late=max(late,stamps[i]-t0-send_at(i,cfg["load"]))
                        res["sent"].append(i);i+=1
                        if i==count:end=stamps[i-1]+2
                    wake=min(deadline,end if end is not None else t0+send_at(i,cfg["load"]))
                    if select.select([sock],[],[],max(0.,wake-time.monotonic()))[0]:
                        b=sock.recv(2048);j=decode_id(b,tag,count)
                        if j is None or j not in stamps:res["bad_payloads"]+=1
                        else:
                            res["received"].append(j)
                            rtts.append((time.monotonic()-stamps[j])*1000)
                res["rtt_ms_p50"]=percentile(rtts,.5);res["rtt_ms_p95"]=percentile(rtts,.95)
                res["send_span_s"]=round(stamps[count-1]-stamps[0],3)
                res["max_send_late_ms"]=round(1000*late,2)
            echo_half()
            res["tcp_ok"]=True
    except (OSError,RuntimeError) as e:
        res["error"]=str(e)
    finally:
        if proc is not None:
            if proc.poll() is None:proc.terminate()
            try:proc.wait(.7)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        if reader is not None:reader.join(1)
        path.unlink(missing_ok=True)
        res["wall_s"]=round(time.monotonic()-start,3)
    return res


if __name__=="__main__":
    os.umask(0o077);root=Path.cwd()
    print(json.dumps(exercise(root/"omhy",root,root/"ca.pem",json.loads(sys.stdin.readline()))),flush=True)
