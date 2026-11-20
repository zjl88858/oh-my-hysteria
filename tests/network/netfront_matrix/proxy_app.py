# SPDX-License-Identifier: MIT-0
"""User-facing HTTP, HTTPS CONNECT, SOCKS5 CONNECT and UDP ASSOCIATE checks."""
from concurrent.futures import ThreadPoolExecutor
import hashlib
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time

from common import obfuscation

LO="127.0.0.1"
CERT_NAME="netfront.test.invalid"
ANSWER="192.0.2.7"  # documentation-only address: no external DNS lookup


def digest(b):
    return hashlib.sha256(b).hexdigest()


def dns_messages(tag, txid):
    labels=(tag.encode(),b"netfront",b"test",b"invalid")
    question=b"".join(bytes([len(x)])+x for x in labels)+b"\0"+struct.pack(">HH",1,1)
    q=struct.pack(">HHHHHH",txid,0x0100,1,0,0,0)+question
    a=(struct.pack(">HHHHHH",txid,0x8500,1,1,0,0)+question+
       b"\xc0\x0c"+struct.pack(">HHIH",1,1,30,4)+socket.inet_aton(ANSWER))
    return q,a


class Origins:
    """Only bound to VPS loopback; serve this case's page/file/upload/DNS name."""
    def __init__(self,cfg):
        self.tag=cfg["tag"]; self.page=f"<html><title>OMHY proxy check</title>{secrets.token_hex(16)}</html>".encode()
        self.file=os.urandom(24576)
        self.stats=dict(page=0,file=0,uploads=[],dns_queries=0,dns_answers=0,other=0)
        origin=self
        class Handler(BaseHTTPRequestHandler):
            def log_message(self,*args):pass
            def reply(self,status,kind,b):
                self.send_response(status);self.send_header("Content-Type",kind)
                self.send_header("Content-Length",str(len(b)));self.send_header("Cache-Control","no-store")
                self.end_headers();self.wfile.write(b)
            def do_GET(self):
                if self.path==f"/{origin.tag}/page" and self.server is origin.plain:
                    self.reply(200,"text/html; charset=utf-8",origin.page);origin.stats["page"]+=1
                elif self.path==f"/{origin.tag}/file" and self.server is origin.secure:
                    self.reply(200,"application/octet-stream",origin.file);origin.stats["file"]+=1
                else:origin.stats["other"]+=1;self.reply(404,"text/plain",b"not found")
            def do_POST(self):
                if (self.path!=f"/{origin.tag}/upload" or self.server is not origin.secure or
                        self.headers.get("Content-Length")!="16384"):
                    origin.stats["other"]+=1;self.reply(400,"text/plain",b"bad test request");return
                self.connection.settimeout(5)
                b=self.rfile.read(16384);record={"bytes":len(b),"sha256":digest(b)}
                self.reply(200,"application/json",json.dumps(record).encode());origin.stats["uploads"].append(record)
        self.plain=ThreadingHTTPServer((LO,0),Handler)
        self.secure=ThreadingHTTPServer((LO,0),Handler)
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);ctx.load_cert_chain("server.pem","server.key")
        self.secure.socket=ctx.wrap_socket(self.secure.socket,server_side=True)
        self.udp=socket.socket(type=socket.SOCK_DGRAM);self.udp.bind((LO,0));self.udp.settimeout(.1)
        self.tp=self.plain.server_port;self.up=self.udp.getsockname()[1]
        self.prepared=dict(origin_tls=self.secure.server_port,page_hash=digest(self.page),file_hash=digest(self.file))
        self.stop=threading.Event()
        self.threads=[threading.Thread(target=f,daemon=True) for f in
                      (lambda:self.plain.serve_forever(.05),lambda:self.secure.serve_forever(.05),self.dns)]
        for t in self.threads:t.start()

    def dns(self):
        while not self.stop.is_set():
            try:b,a=self.udp.recvfrom(512)
            except TimeoutError:continue
            if len(b)<2:continue
            q,reply=dns_messages(self.tag,int.from_bytes(b[:2],"big"))
            if b!=q or self.stats["dns_queries"]>=3:self.stats["other"]+=1;continue
            self.stats["dns_queries"]+=1
            if self.udp.sendto(reply,a)==len(reply):self.stats["dns_answers"]+=1

    def close(self):
        self.stop.set()
        for h in (self.plain,self.secure):h.shutdown();h.server_close()
        for t in self.threads:t.join(.5)
        self.udp.close()


def exact(s,n):
    b=bytearray()
    while len(b)<n:
        v=s.recv(n-len(b))
        if not v:raise IOError("early EOF in proxy handshake")
        b.extend(v)
    return bytes(b)


def socks_command(s,cmd,port,host=LO):
    s.sendall(b"\x05\x01\x00")
    if exact(s,2)!=b"\x05\x00":raise IOError("SOCKS5 negotiation")
    s.sendall(bytes((5,cmd,0,1))+socket.inet_aton(host)+struct.pack(">H",port))
    h=exact(s,4)
    if h[:3]!=b"\x05\x00\x00" or h[3]!=1:raise IOError("SOCKS5 command not accepted")
    return socket.inet_ntoa(exact(s,4)),int.from_bytes(exact(s,2),"big")


def http_response(s,method):
    r=http.client.HTTPResponse(s,method=method);r.begin()
    try:
        if r.status!=200:raise IOError(f"{method} HTTP status {r.status}")
        return b"" if method=="CONNECT" else r.read(65537)
    finally:r.close()


def exercise(exe,work,ca,cfg):
    # Distinct loopback ports for ordinary applications. No application test
    # socket has a public destination; only the actual OMHY client does.
    holders=[socket.socket(),socket.socket()]
    try:
        for s in holders:s.bind((LO,0))
        http_port,socks_port=[s.getsockname()[1] for s in holders]
    finally:
        for s in holders:s.close()
    conf=dict(server=f"{cfg['host']}:{cfg['ports'][0]}",auth=cfg["auth"],obfs=obfuscation(cfg),
              tls={"sni":CERT_NAME,"ca":str(ca)},http={"listen":f"{LO}:{http_port}"},
              socks5={"listen":f"{LO}:{socks_port}"},congestion={"type":"bbr","bbrProfile":"standard"})
    path=work/"proxy-app-private.json";path.write_text(json.dumps(conf))
    ctx=ssl.create_default_context(cafile=str(ca));ready=threading.Event()
    res=dict(connections=0,error=None,normal_tls=True);start=time.monotonic()
    proc=None;thread=None
    def page():
        c=http.client.HTTPConnection(LO,http_port,timeout=6)
        try:
            c.request("GET",f"http://{LO}:{cfg['tcp']}/{cfg['tag']}/page",headers={"Connection":"close"})
            r=c.getresponse();b=r.read(4097)
            if r.status!=200 or digest(b)!=cfg["page_hash"]:raise IOError("HTTP proxy page mismatch")
            return dict(status=r.status,sha256=digest(b),bytes=len(b))
        finally:c.close()
    def file():
        with socket.create_connection((LO,http_port),timeout=7) as s:
            target=f"{LO}:{cfg['origin_tls']}"
            s.sendall(f"CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n".encode())
            http_response(s,"CONNECT")
            with ctx.wrap_socket(s,server_hostname=CERT_NAME) as tls:
                tls.sendall(f"GET /{cfg['tag']}/file HTTP/1.1\r\nHost: {CERT_NAME}\r\nConnection: close\r\n\r\n".encode())
                b=http_response(tls,"GET")
                if len(b)!=24576 or digest(b)!=cfg["file_hash"]:raise IOError("HTTPS download mismatch")
                return dict(status=200,bytes=len(b),sha256=digest(b),origin_tls=tls.version())
    def upload():
        b=os.urandom(16384)
        with socket.create_connection((LO,socks_port),timeout=7) as s:
            socks_command(s,1,cfg["origin_tls"])
            with ctx.wrap_socket(s,server_hostname=CERT_NAME) as tls:
                headers=(f"POST /{cfg['tag']}/upload HTTP/1.1\r\nHost: {CERT_NAME}\r\n"
                         f"Content-Length: {len(b)}\r\nConnection: close\r\n\r\n").encode()
                tls.sendall(headers+b);got=json.loads(http_response(tls,"POST"))
                if got!={"bytes":len(b),"sha256":digest(b)}:raise IOError("SOCKS5 HTTPS upload mismatch")
                return dict(status=200,origin_tls=tls.version(),**got)
    def lookup():
        with socket.create_connection((LO,socks_port),timeout=4) as control, socket.socket(type=socket.SOCK_DGRAM) as u:
            u.bind((LO,0));relay=socks_command(control,3,u.getsockname()[1])
            if relay[0]!=LO or not relay[1]:raise IOError("SOCKS5 relay returned a nonlocal bind address")
            u.connect(relay);u.settimeout(1.2)
            q,a=dns_messages(cfg["tag"],secrets.randbits(16))
            header=b"\0\0\0\1"+socket.inet_aton(LO)+struct.pack(">H",cfg["udp"])
            for attempt in range(1,4):
                u.send(header+q)
                try:b=u.recv(512)
                except TimeoutError:continue
                if b!=header+a:raise IOError("incorrect SOCKS5 UDP/DNS answer")
                return dict(answer=ANSWER,transmissions=attempt)
            raise TimeoutError("DNS lookup did not complete in three sends")
    try:
        proc=subprocess.Popen([str(exe),"client","-c",str(path)],stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        def logs():
            seen=set()
            for line in proc.stderr:
                if b"connected to server" in line:res["connections"]+=1
                for marker in (b"SOCKS5 server listening",b"HTTP proxy server listening"):
                    if marker in line:seen.add(marker)
                if len(seen)==2:ready.set()
            ready.set()
        thread=threading.Thread(target=logs,daemon=True);thread.start()
        if not ready.wait(5.5) or proc.poll() is not None:raise IOError("proxy listeners not ready")
        res["http_get"]=page()
        with ThreadPoolExecutor(max_workers=3) as pool:
            tasks={name:pool.submit(f) for name,f in (("https_connect",file),("socks5_https",upload),("socks5_dns",lookup))}
            for name,f in tasks.items():res[name]=f.result()
    except (OSError,ValueError,http.client.HTTPException) as e:res["error"]=str(e)
    finally:
        if proc:
            if proc.poll() is None:proc.terminate()
            try:proc.wait(1)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
        if thread:thread.join(.5)
        path.unlink(missing_ok=True);res["wall_s"]=round(time.monotonic()-start,3)
    return res


def passed(client,meter,prep):
    origin=meter["echo"]
    if client["error"] or meter["error"] or meter["capture_drops"] or client["connections"]!=1:return False
    upload=client["socks5_https"];dns=client["socks5_dns"]
    return (client["http_get"]["sha256"]==prep["page_hash"] and client["https_connect"]["sha256"]==prep["file_hash"]
            and upload["bytes"]==16384 and origin["uploads"]==[{"bytes":16384,"sha256":upload["sha256"]}]
            and origin["page"]==origin["file"]==1 and dns["answer"]==ANSWER
            and 1<=origin["dns_queries"]==origin["dns_answers"]<=dns["transmissions"]<=3 and origin["other"]==0)


if __name__=="__main__":
    os.umask(0o077);root=Path.cwd()
    print(json.dumps(exercise(root/"omhy",root,root/"ca.pem",json.loads(sys.stdin.readline()))),flush=True)
