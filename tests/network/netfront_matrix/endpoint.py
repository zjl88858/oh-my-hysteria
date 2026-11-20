# SPDX-License-Identifier: MIT-0
"""One bounded Linux endpoint, controlled over its existing SSH channel."""
import json
import os
from pathlib import Path
import re
import select
import socket
import subprocess
import sys
import threading
import time

from common import decode_id, nmessages, obfuscation
from wire import Meter


def tell(**message):
    print(json.dumps(message),flush=True)


class Echo:
    def __init__(self,cfg):
        self.tag=bytes.fromhex(cfg["tag"]);self.count=nmessages(cfg["load"])
        self.tcp=socket.socket();self.tcp.bind(("127.0.0.1",0));self.tcp.listen(1)
        self.udp=socket.socket(type=socket.SOCK_DGRAM);self.udp.bind(("127.0.0.1",0))
        self.tcp.settimeout(.1);self.udp.settimeout(.1)
        self.tp=self.tcp.getsockname()[1];self.up=self.udp.getsockname()[1]
        self.stop=threading.Event()
        self.stats=dict(received=[],replied=[],bad_payloads=0,write_errors=0,tcp_bytes=[0,0])
        self.threads=[threading.Thread(target=f,daemon=True) for f in (self.stream,self.datagrams)]
        for t in self.threads:t.start()

    def stream(self):
        try:
            while not self.stop.is_set():
                try:c,_=self.tcp.accept()
                except TimeoutError:continue
                with c:
                    c.settimeout(.2)
                    while not self.stop.is_set() and self.stats["tcp_bytes"][0]<16384:
                        try:b=c.recv(8192)
                        except TimeoutError:continue
                        if not b:break
                        self.stats["tcp_bytes"][0]+=len(b)
                        c.sendall(b);self.stats["tcp_bytes"][1]+=len(b)
                return
        except OSError:
            if not self.stop.is_set():self.stats["write_errors"]+=1

    def datagrams(self):
        try:
            while not self.stop.is_set():
                try:b,addr=self.udp.recvfrom(1201)
                except TimeoutError:continue
                i=decode_id(b,self.tag,self.count)
                if i is None:self.stats["bad_payloads"]+=1;continue
                if len(self.stats["received"])>=self.count*2:
                    self.stats["write_errors"]+=1;return
                self.stats["received"].append(i)
                if self.udp.sendto(b,addr)==len(b):self.stats["replied"].append(i)
                else:self.stats["write_errors"]+=1
        except OSError:
            if not self.stop.is_set():self.stats["write_errors"]+=1

    def close(self):
        self.stop.set()
        for t in self.threads:t.join(.5)
        self.tcp.close();self.udp.close()
        if any(t.is_alive() for t in self.threads):raise RuntimeError("echo thread did not stop")


def bound_by(pid,ports):
    owned=set()
    for p in Path(f"/proc/{pid}/fd").glob("*"):
        try:owned.add(os.readlink(p))
        except FileNotFoundError:pass
    got={int(f[1].split(":")[1],16) for row in Path("/proc/net/udp").read_text().splitlines()[1:]
         if len(f:=row.split())>9 and f"socket:[{f[9]}]" in owned}
    return set(ports)<=got


def run(cfg):
    root=Path.cwd();label=cfg["stage"];ports=cfg["ports"]
    assert re.fullmatch("[a-zA-Z0-9-]{1,50}",label)
    assert len(ports)=={"presto":1,"netfront2":3,"netfront3":4}[cfg["mode"]]
    assert len(set(ports))==len(ports) and all(0<p<65536 for p in ports)
    assert 0<cfg["byte_cutoff"]<=768*1024 and 0<cfg["time_cutoff"]<=42
    if cfg["load"]=="app":
        from proxy_app import Origins
        echo=Origins(cfg)
        target=f'((proto == "tcp" && dst.port in [{echo.tp},{echo.secure.server_port}]) || (proto == "udp" && dst.port == {echo.up}))'
    else:
        echo=Echo(cfg)
        target=f'((proto == "tcp" && dst.port == {echo.tp}) || (proto == "udp" && dst.port == {echo.up}))'
    meter=Meter(cfg)
    config=root/f"{label}-server.json"
    config.write_text(json.dumps({
        "listen":f"{cfg['host']}:{ports[0]}", "obfs":obfuscation(cfg),
        "tls":{"cert":"server.pem","key":"server.key"}, "auth":{"type":"password","password":cfg["auth"]},
        "congestion":{"type":"bbr","bbrProfile":"standard"},"ignoreClientBandwidth":True,
        "acl":{"rules":[{"outbound":"direct","match":f'dst.host == "127.0.0.1" && {target}'},
                        {"outbound":"reject","match":"true"}]}}))
    error=None;srv=None;start=None;stopped=None
    def stop():
        nonlocal stopped
        if stopped is None:
            stopped=time.monotonic()
            if srv and srv.poll() is None:srv.terminate()
    try:
        tell(prepared=True,tcp=echo.tp,udp=echo.up,**getattr(echo,"prepared",{}))
        if not select.select([sys.stdin],[],[],45)[0] or sys.stdin.readline().strip()!="START":raise RuntimeError("no START")
        start=time.monotonic()
        with (root/f"{label}-server.log").open("wb") as log:
            srv=subprocess.Popen([str(root/"omhy"),"server","-c",str(config)],stdin=subprocess.DEVNULL,stdout=log,stderr=log)
        while not bound_by(srv.pid,ports):
            if srv.poll() is not None or time.monotonic()-start>2:raise RuntimeError("server did not bind")
            time.sleep(.01)
        tell(ready=True)
        while stopped is None or time.monotonic()-stopped<.3:
            if stopped is None:
                if meter.total>=cfg["byte_cutoff"] or time.monotonic()-start>=cfg["time_cutoff"] or srv.poll() is not None:
                    error="byte/time cutoff or server exited";stop()
            have=select.select([meter.sock] if stopped is not None else [meter.sock,sys.stdin],[],[],.02)[0]
            if sys.stdin in have:
                if sys.stdin.readline().strip()!="STOP":error="unexpected control EOF"
                stop()
            if meter.sock in have:meter.consume()
    except (ValueError,RuntimeError,OSError) as e:error=str(e)
    finally:
        stop()
        if srv:
            try:srv.wait(1)
            except subprocess.TimeoutExpired:srv.kill();srv.wait(1)
        echo.close();config.unlink(missing_ok=True)
        result=meter.finish()
        result.update(echo=echo.stats,active_ms=round(1000*(stopped-start)) if start else 0,error=error)
        (root/f"{label}-receipt.json").write_text(json.dumps(result))
        tell(finished=True,meter=result)


if __name__=="__main__":
    os.umask(0o077)
    run(json.loads(Path(sys.argv[1]).read_text()))
