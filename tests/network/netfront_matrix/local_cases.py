# SPDX-License-Identifier: MIT-0
"""Real CLI controls; every listener, relay, and outbound here is IPv4 loopback."""
import argparse
from contextlib import contextmanager
import datetime
import heapq
import itertools
import json
import os
from pathlib import Path
import secrets
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from client import exercise
from common import MODES, epoch_proofs, nmessages, obfuscation, reconcile, renewed, send_at
from endpoint import Echo
from wire import side_decoder

LO="127.0.0.1"
sys.path.insert(0,str(Path(__file__).resolve().parents[2]))  # independent HChaCha reference


def certificate(tmp):
    now=datetime.datetime.now(datetime.timezone.utc)
    cak,key=(ec.generate_private_key(ec.SECP256R1()) for _ in range(2))
    name=lambda cn:x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,cn)])
    root=name("OMHY temporary loopback authority")
    def base(subject,k):
        return (x509.CertificateBuilder().issuer_name(root).subject_name(subject).public_key(k.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
                .not_valid_after(now+datetime.timedelta(hours=1)))
    ca=base(root,cak).add_extension(x509.BasicConstraints(True,0),True).sign(cak,hashes.SHA256())
    cert=(base(name("netfront.test.invalid"),key).add_extension(x509.SubjectAlternativeName([x509.DNSName("netfront.test.invalid")]),False)
          .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False).sign(cak,hashes.SHA256()))
    for n,c in (("ca.pem",ca),("server.pem",cert)):(tmp/n).write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (tmp/"server.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))


def bound(kind=socket.SOCK_DGRAM):
    s=socket.socket(type=kind);s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,1<<20)
    s.bind((LO,0))
    return s


def group(mode):
    sockets=[bound() for _ in range({"presto":1,"netfront2":3,"netfront3":4}[mode])]
    ports=[s.getsockname()[1] for s in sockets]
    for s in sockets:s.close()
    return ports


@contextmanager
def cli(exe,role,path,conf,marker):
    path.write_text(json.dumps(conf),encoding="utf-8")
    p=subprocess.Popen([str(exe),role,"-c",str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    ready=threading.Event()
    def logs():
        for line in p.stderr:
            if marker in line:ready.set()
    t=threading.Thread(target=logs,daemon=True);t.start()
    try:
        if not ready.wait(5):raise RuntimeError(f"{role} not ready")
        yield
    finally:
        if p.poll() is None:p.terminate()
        try:p.wait(1)
        except subprocess.TimeoutExpired:p.kill();p.wait()
        t.join(1);path.unlink(missing_ok=True)


def server_config(tmp,cfg,tp,up=None):
    target=f'(proto == "tcp" && dst.port == {tp})'
    if up:target+=f' || (proto == "udp" && dst.port == {up})'
    return {"listen":f"{LO}:{cfg['ports'][0]}","auth":{"type":"password","password":cfg["auth"]},
            "tls":{"cert":str(tmp/"server.pem"),"key":str(tmp/"server.key")},"obfs":obfuscation(cfg),
            "ignoreClientBandwidth":True,"congestion":{"type":"bbr","bbrProfile":"standard"},
            "acl":{"rules":[{"outbound":"direct","match":f'dst.host == "127.0.0.1" && ({target})'},{"outbound":"reject","match":"true"}]}}


class Relay:
    def __init__(self,cfg,fault):
        self.dest=cfg["ports"];self.decode=side_decoder(cfg["psk"],3)
        self.front=[bound() for _ in self.dest];self.back=[bound() for _ in self.dest]
        self.peers=[None]*len(self.dest);self.delay=(.065,.012,.115,.035)
        self.fault=fault;self.rebound=False;self.stop=threading.Event();self.error=None
        self.data={};self.session_ids={};self.start=time.monotonic()
        self.thread=threading.Thread(target=self.loop,daemon=True);self.thread.start()

    def phase(self):
        t=time.monotonic()-self.start
        return "warm" if not self.fault or t<6 else "blocked" if t<31 else "restored"

    def bucket(self,p,i,d):
        k=self.data.setdefault(p,{}).setdefault(i,{})
        return k.setdefault(d,dict(forwarded=0,dropped=0,epochs={}))

    def loop(self):
        order=itertools.count();q=[]
        try:
            while not self.stop.is_set():
                now=time.monotonic();phase=self.phase()
                if phase=="restored" and not self.rebound:
                    # Keep old sockets open while allocating the new group, so
                    # that the OS cannot give us the same source endpoints.
                    old=self.back[1:];self.back[1:]=[bound() for _ in old]
                    for s in old:s.close()
                    self.rebound=True
                while q and q[0][0]<=now:
                    _,_,i,d,b,dest=heapq.heappop(q);row=self.bucket(phase,i,d)
                    if i and phase=="blocked":row["dropped"]+=1;continue
                    outgoing=self.back[i] if d=="rx" else self.front[i]
                    if outgoing.sendto(b,dest)!=len(b):raise IOError("short relay write")
                    row["forwarded"]+=1
                    if i:
                        f=self.decode(b,i,d)
                        if f is None:raise ValueError("side frame failed independent authentication")
                        kind,sid,seq=f;k=f"{self.session_ids.setdefault(sid,len(self.session_ids)+1)}:{seq}"
                        ep=row["epochs"].setdefault(k,{});ep[kind]=ep.get(kind,0)+1
                socks=self.front+self.back
                wait=min(.013,max(0,q[0][0]-now)) if q else .013
                for s in select.select(socks,[],[],wait)[0]:
                    try:b,a=s.recvfrom(2048)
                    except ConnectionResetError:continue
                    n=socks.index(s);i=n%len(self.dest);d="rx" if n<len(self.dest) else "tx"
                    if d=="rx":self.peers[i]=a;dest=(LO,self.dest[i])
                    else:
                        if a!=(LO,self.dest[i]) or self.peers[i] is None:raise ValueError("incorrect backend address")
                        dest=self.peers[i]
                    if i and self.phase()=="blocked":self.bucket("blocked",i,d)["dropped"]+=1
                    else:heapq.heappush(q,(time.monotonic()+self.delay[i],next(order),i,d,b,dest))
                    if len(q)>4096:raise ValueError("relay queue exceeded")
        except Exception as e:self.error=str(e)

    def close(self):
        self.stop.set();self.thread.join(1)
        for s in self.front+self.back:s.close()


def controlled(exe,tmp,fault):
    mode="netfront3";load="local-fault" if fault else "renew"
    cfg=dict(auth=secrets.token_urlsafe(32),psk=secrets.token_urlsafe(40),tag=secrets.token_hex(8),
             mode=mode,load=load,host=LO,ports=group(mode))
    echo=Echo(cfg);issues=[];relay=None
    try:
        with cli(exe,"server",tmp/"local-server.json",server_config(tmp,cfg,echo.tp,echo.up),b"server up and running"):
            relay=Relay(cfg,fault)
            local={**cfg,"tcp":echo.tp,"udp":echo.up,"ports":[s.getsockname()[1] for s in relay.front]}
            delta=time.monotonic()-relay.start
            app=exercise(exe,tmp,tmp/"ca.pem",local)
    finally:
        if relay:relay.close()
        echo.close()
    f=reconcile(app,echo.stats,nmessages(load))
    if app["error"] or not app["tcp_ok"] or app["connections"]!=1 or echo.stats["write_errors"] or relay.error:issues.append("transport")
    if f["not_submitted"] or f["bad_payloads"] or any(f["duplicates"]) or f["missing_echo_write"] or any(f["unexpected"]):issues.append("integrity")
    missing=set(f["missing_before_echo"]+f["missing_after_echo"])
    for phase in (["warm","restored"] if fault else ["warm"]):
        for i in range(1,4):
            row=relay.data.get(phase,{}).get(i,{})
            proof=epoch_proofs(row) if set(row)=={"rx","tx"} else []
            if not proof or (not fault and not renewed(proof)):issues.append(f"{phase} lane {i} validation")
    if fault:
        if not relay.rebound or not all(relay.data.get("blocked",{}).get(i,{}).get("rx",{}).get("dropped",0)>0 for i in range(1,4)):
            issues.append("blackout not exercised")
        # Include a time margin for the longest simulated one-way delay and
        # client scheduler jitter near the intentional transition.
        def stable(i):
            t=delta+app.get("udp_start_s",0)+send_at(i,load)
            return t<5.5 or 27<=t<=30 or 39<=t
        good={i for i in range(nmessages(load)) if stable(i)}
        if good & missing:issues.append("unforced missing outside fault transition")
    else:
        good=set(range(nmessages(load)))
        if missing:issues.append("missing with no injected loss")
    return dict(load=load,client=app,server=echo.stats,four=f,issues=issues,relay=relay.data,
                nat_rebound=relay.rebound,stable_sent=len(good),missing_in_stable=sorted(good&missing),relay_error=relay.error)


def bulk(exe,tmp,mode):
    # Two simultaneously authenticated CLI clients, same IP and shared obfs
    # password. Each echoes its own independent 2 MiB over one TCP stream.
    cfg=dict(auth=secrets.token_urlsafe(32),psk=secrets.token_urlsafe(40),mode=mode,ports=group(mode))
    total=2*1024*1024
    listener=bound(socket.SOCK_STREAM);listener.listen(2);listener.settimeout(15)
    tp=listener.getsockname()[1];errors=[]
    def echo(c):
        try:
            with c:
                c.settimeout(12);n=0
                while n<total:
                    b=c.recv(65536)
                    if not b:raise IOError("premature EOF")
                    c.sendall(b);n+=len(b)
        except Exception as e:errors.append(str(e))
    def accept():
        threads=[]
        try:
            for _ in range(2):
                t=threading.Thread(target=echo,args=(listener.accept()[0],),daemon=True)
                t.start();threads.append(t)
        except Exception as e:errors.append(str(e))
        for t in threads:t.join(40)
    at=threading.Thread(target=accept,daemon=True);at.start()
    localsocks=[bound(socket.SOCK_STREAM) for _ in range(2)]
    localports=[s.getsockname()[1] for s in localsocks]
    for s in localsocks:s.close()
    gate=threading.Barrier(2,timeout=8)
    def one(idx):
        conf={"server":f"{LO}:{cfg['ports'][0]}","auth":cfg["auth"],"obfs":obfuscation(cfg),
              "tls":{"sni":"netfront.test.invalid","ca":str(tmp/"ca.pem")},
              "tcpForwarding":[{"listen":f"{LO}:{localports[idx]}","remote":f"{LO}:{tp}"}]}
        with cli(exe,"client",tmp/f"bulk-{idx}.json",conf,b"TCP forwarding listening"):
            with socket.create_connection((LO,localports[idx]),timeout=4) as s:
                s.settimeout(12);gate.wait();n=0;start=time.monotonic()
                while n<total:
                    chunk=os.urandom(32768);s.sendall(chunk);out=bytearray()
                    while len(out)<len(chunk):
                        b=s.recv(len(chunk)-len(out))
                        if not b:raise IOError("unexpected bulk stream EOF")
                        out.extend(b)
                    if out!=chunk:raise ValueError("bulk echo corruption or cross-delivery")
                    n+=len(out)
                return dict(bytes_each_direction=n,wall_s=round(time.monotonic()-start,3))
    try:
        with cli(exe,"server",tmp/"bulk-server.json",server_config(tmp,cfg,tp),b"server up and running"):
            with ThreadPoolExecutor(max_workers=2) as pool:out=list(pool.map(one,(0,1)))
    finally:listener.close();at.join(1)
    return dict(mode=mode,clients=out,echo_errors=errors)


def main():
    p=argparse.ArgumentParser();p.add_argument("--exe",type=Path,required=True);p.add_argument("--output",type=Path,required=True)
    p.add_argument("--temp-parent",type=Path);a=p.parse_args();a.exe=a.exe.resolve()
    if a.output.exists():raise FileExistsError(a.output)
    r={"loopback_only":True,"cases":[],"bulk":[]}
    with tempfile.TemporaryDirectory(prefix="nf-controls-",dir=a.temp_parent) as td:
        tmp=Path(td);certificate(tmp)
        try:
            for fault in (False,True):
                row=controlled(a.exe,tmp,fault);r["cases"].append(row)
                print(row["load"],row["four"]["counts"],row["issues"],flush=True)
            for m in MODES:
                row=bulk(a.exe,tmp,m);r["bulk"].append(row);print("bulk",row,flush=True)
        finally:a.output.write_text(json.dumps(r,indent=2),encoding="utf-8")
    if any(r["issues"] for r in r["cases"]) or any(r["echo_errors"] for r in r["bulk"]):raise SystemExit(1)


if __name__=="__main__":
    main()
