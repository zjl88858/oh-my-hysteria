# SPDX-License-Identifier: MIT-0
"""Opt-in qualification on one operator-specified, host-key-pinned Linux VPS."""
import argparse
import base64
import getpass
import gzip
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import sys
import tempfile
import time

from client import exercise
from common import EARLY, HARD, MAX_SECONDS, MODES, cases, observations

HERE=Path(__file__).resolve().parent
CA_SCRIPT="""set -eu
umask 077
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=OMHY-QA-CA -days 1 -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign -keyout ca.key -out ca.pem 2>/dev/null
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -subj /CN=netfront.test.invalid -keyout server.key -out req.pem 2>/dev/null
printf '%s\\n' 'basicConstraints=critical,CA:FALSE' 'keyUsage=critical,digitalSignature' 'extendedKeyUsage=serverAuth' 'subjectAltName=DNS:netfront.test.invalid' > server.ext
openssl x509 -req -in req.pem -CA ca.pem -CAkey ca.key -set_serial 2 -days 1 -extfile server.ext -out server.pem 2>/dev/null
rm ca.key req.pem server.ext
openssl verify -verify_hostname netfront.test.invalid -CAfile ca.pem server.pem >/dev/null
cat ca.pem
"""
CLEANUP=r"""
import json, os, pathlib, re, shutil, signal, socket, sys, time
r=pathlib.Path(sys.argv[1])
assert r.parent==pathlib.Path('/tmp') and re.fullmatch(r'omhy-qual\.[A-Za-z0-9]{10}',r.name)
def owned():
    hits=[]
    for p in pathlib.Path('/proc').glob('[0-9]*'):
        try:
            if int(p.name)==os.getpid():continue
            if (p/'exe').resolve() in (r/'omhy',r/'obfs.test') or ((p/'cwd').resolve()==r and any(n in (p/'cmdline').read_bytes() for n in (b'endpoint.py',b'client.py',b'proxy_app.py'))):
                hits.append(int(p.name))
        except (OSError,ValueError):pass
    return hits
before=owned()
for sig in (signal.SIGTERM,signal.SIGKILL):
    group=owned()
    for pid in group:
        try:os.kill(pid,sig)
        except ProcessLookupError:pass
    if group:time.sleep(.3)
assert not owned()
if r.exists():shutil.rmtree(r)
ports={}
for port in (443,31011,31012,31013,31443):
    with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as s:
        try:s.bind(('0.0.0.0',port));ports[str(port)]=True
        except OSError:ports[str(port)]=False
print(json.dumps(dict(temporary_directory_removed=not r.exists(),owned_processes_after=owned(),cleanup_terminated=len(before),ports_free=ports)))
"""


def digest(b):
    return hashlib.sha256(b).hexdigest()


def previous_ledger(old,fingerprint):
    if old["host_key"]!=fingerprint:raise ValueError("seed belongs to a different host")
    if "ledger" in old:
        if old.get("unknown_public_cost"):raise ValueError("a previous public attempt is unaccounted")
        ledger=old["seed"].copy()
        for r in old["records"]:
            if r["public"]:
                m=r["meter"]
                if m["capture_drops"] or m["error"]:raise ValueError("previous public measurement incomplete")
                ledger["bytes"]+=m["ipv4_bytes"];ledger["packets"]+=m["packets"];ledger["ms"]+=m["active_ms"]
        if ledger!=old["ledger"]:raise ValueError("seed ledger disagrees with its receipts")
        return ledger
    m=old["stages"]["public-v4"]["meter"]
    if m["error"] or m["capture_drops"]:raise ValueError("seed is not an accounted receipt")
    return dict(bytes=m["ipv4_bytes"],packets=m["packets"],ms=round(m["active_seconds"]*1000))


class Campaign:
    def __init__(self,args,password,work):
        self.a=args;self.password=password;self.work=work;self.ssh=None;self.root=None
        seed_bytes=args.seed.read_bytes()
        old=json.loads(seed_bytes)
        s=previous_ledger(old,args.fingerprint)
        self.plan=[("app-"+m,i,m,"app") for i,m in enumerate(MODES[1:])] if args.application else list(cases())
        self.data=dict(seed=s.copy(),ledger=s.copy(),seed_sha256=digest(seed_bytes),host_key=args.fingerprint,
                       limits=dict(early_bytes=EARLY,hard_bytes=HARD,ms=MAX_SECONDS*1000),
                       planned=self.plan,records=[],unknown_public_cost=False)
        self.keys=[secrets.token_urlsafe(40) for _ in range(3)]

    def save(self):
        path=self.a.out/"evidence.json";temp=path.with_suffix(".tmp")
        temp.write_text(json.dumps(self.data,indent=2),encoding="utf-8");temp.replace(path)

    def login(self):
        import paramiko  # control workstation only
        if self.ssh:self.ssh.close()
        entry=paramiko.HostKeys(str(Path.home()/".ssh/known_hosts"))[self.a.host]["ssh-ed25519"]
        actual="SHA256:"+base64.b64encode(hashlib.sha256(entry.asbytes()).digest()).decode().rstrip("=")
        if actual!=self.a.fingerprint:raise ValueError("SSH fingerprint mismatch")
        self.ssh=paramiko.SSHClient();self.ssh.get_host_keys().add(self.a.host,"ssh-ed25519",entry)
        self.ssh.connect(self.a.host,username=self.a.user,password=self.password,allow_agent=False,look_for_keys=False,
                         timeout=12,banner_timeout=15,auth_timeout=15)
        self.ssh.get_transport().set_keepalive(6)

    def channel(self,command,timeout=30):
        ch=self.ssh.get_transport().open_session(timeout=timeout);ch.settimeout(timeout)
        ch.exec_command(command)
        return ch

    def cmd(self,command,data=b"",timeout=30):
        ch=self.channel(command,timeout)
        try:
            if data:ch.sendall(data)
            ch.shutdown_write();out=ch.makefile("rb").read();err=ch.makefile_stderr("rb").read()
            if ch.recv_exit_status():raise RuntimeError("remote command failed: "+err.decode(errors="replace")[-400:])
            return out
        finally:ch.close()

    def setup(self):
        self.login()
        self.root=self.cmd("umask 077; mktemp -d /tmp/omhy-qual.XXXXXXXXXX").decode().strip()
        if not re.fullmatch(r"/tmp/omhy-qual\.[A-Za-z0-9]{10}",self.root):raise RuntimeError("bad temporary root")
        result=self.cmd("uname -sm; date +%s; ip -j -4 route show default").decode().splitlines()
        if result[0]!="Linux x86_64" or abs(time.time()-int(result[1]))>25:raise RuntimeError("unexpected platform or clock skew")
        self.iface=json.loads(result[2])[0]["dev"]
        sums={n:h for h,n in (l.split("  ") for l in (self.a.binaries/"SHA256SUMS").read_text().splitlines())}
        for name,h in sums.items():
            if digest((self.a.binaries/name).read_bytes())!=h:raise ValueError("candidate hash mismatch")
        self.data["sha256"]=sums;self.data["platform"]=result[0]
        files=[(self.a.binaries/"oh-my-hysteria-linux-amd64","omhy")]
        if not self.a.application:files.append((self.a.linux_tests,"obfs.test"))
        self.data["ssh_gzip_bytes"]=0
        for p,name in files:
            b=p.read_bytes();packed=gzip.compress(b,compresslevel=4,mtime=0)
            got=self.cmd(f"cd {self.root} && umask 077 && gzip -dc >{name} && chmod 700 {name} && sha256sum {name}",packed,150)
            if got.decode().split()[0]!=digest(b):raise RuntimeError("uploaded hash mismatch")
            self.data["ssh_gzip_bytes"]+=len(packed)
        self.data["linux_version"]=self.cmd(f"{self.root}/omhy version").decode()
        for p in [HERE/name for name in ("common.py","client.py","wire.py","endpoint.py","proxy_app.py")]+[HERE.parents[1]/"servo_reference.py"]:
            self.cmd(f"cd {self.root} && umask 077 && cat >{p.name}",p.read_bytes())
        ca=self.cmd(f"cd {self.root} && sh -s",CA_SCRIPT.encode())
        (self.work/"ca.pem").write_bytes(ca)
        if self.a.application:return
        self.data["linux_test_sha256"]=digest(self.a.linux_tests.read_bytes())
        log=self.cmd(f"cd {self.root} && ./obfs.test -test.v -test.count=3 -test.timeout=2m -test.run '^Test(NetFront|Presto)' ; exitcode=$?; printf '\\nEXITCODE=%d\\n' \"$exitcode\"",timeout=135)
        (self.a.out/"linux-native-tests.log").write_bytes(log)
        if not log.rstrip().endswith(b"EXITCODE=0"):raise RuntimeError("native Linux regression failed")
        self.data["native_linux_tests"]="pass";self.save()

    def stage(self,label,key,mode,load,public):
        ports=([443] if public else [31443])+[31011,31012,31013][:{"presto":0,"netfront2":2,"netfront3":3}[mode]]
        ledger=self.data["ledger"]
        cutoff=min((704 if load=="renew" else 384)*1024,EARLY-ledger["bytes"]-32768) if public else 750*1024
        lifetime={"short":13,"renew":41,"app":19}[load]
        if public and (cutoff<96*1024 or ledger["ms"]+(lifetime+1)*1000>MAX_SECONDS*1000):
            raise RuntimeError("insufficient remaining measured budget for another case")
        cfg=dict(stage=label,tag=secrets.token_hex(8),psk=self.keys[key],auth=secrets.token_urlsafe(32),
                 host=self.a.host if public else "127.0.0.1",iface=self.iface if public else "lo",
                 ports=ports,mode=mode,load=load,byte_cutoff=cutoff,time_cutoff=lifetime)
        row=dict(label=label,key=key,mode=mode,load=load,public=public,key_tag=digest(cfg["psk"].encode())[:12])
        self.data["records"].append(row);self.save()
        self.cmd(f"cd {self.root} && umask 077 && cat >{label}.json",json.dumps(cfg).encode())
        ch=self.channel(f"cd {self.root} && exec python3 -u endpoint.py {label}.json",50)
        reader=ch.makefile("rb");probe=None;started=False
        def get():
            line=reader.readline()
            if not line:raise RuntimeError("endpoint ended: "+ch.makefile_stderr("rb").read().decode(errors="replace")[-400:])
            return json.loads(line)
        try:
            prep=get()
            if not prep.get("prepared"):raise RuntimeError("endpoint preparation failed")
            cfg.update(tcp=prep["tcp"],udp=prep["udp"])
            if load=="app":
                for field in ("origin_tls","page_hash","file_hash"):cfg[field]=prep[field]
                row["origin_expected_sha256"]={"page":prep["page_hash"],"file":prep["file_hash"]}
            if not public:
                script="proxy_app.py" if load=="app" else "client.py"
                probe=self.channel(f"cd {self.root} && exec python3 -u {script}",45)
            ch.sendall(b"START\n");started=True
            event=get()
            if not event.get("ready"):
                if "meter" in event:row["meter"]=event["meter"]
                raise RuntimeError("not all UDP sockets bound")
            if public:
                probe_client=exercise
                if load=="app":
                    from proxy_app import exercise as probe_client
                row["client"]=probe_client(self.a.binaries/"oh-my-hysteria-windows-amd64.exe",self.work,self.work/"ca.pem",cfg)
            else:
                probe.sendall(json.dumps(cfg).encode()+b"\n");probe.shutdown_write()
                row["client"]=json.loads(probe.makefile("rb").readline())
        finally:
            if probe:probe.close()
            if started and "meter" not in row:
                try:
                    if not ch.closed:ch.sendall(b"STOP\n")
                    row["meter"]=get()["meter"]
                except (OSError,RuntimeError,KeyError,EOFError):
                    try:row["meter"]=json.loads(self.cmd(f"cd {self.root} && cat {label}-receipt.json"))
                    except Exception:
                        if public:self.data["unknown_public_cost"]=True
            ch.close()
            if public and "meter" in row:
                m=row["meter"];ledger["bytes"]+=m["ipv4_bytes"];ledger["packets"]+=m["packets"];ledger["ms"]+=m["active_ms"]
            self.save()
        c,m=row["client"],row["meter"]
        if load=="app":
            from proxy_app import passed
            row["functional_pass"]=passed(c,m,prep);self.save()
            print(label,"functional_pass=",row["functional_pass"],"app=",c,"origin=",m["echo"],flush=True)
            if not row["functional_pass"]:raise RuntimeError("proxy application did not complete: "+label)
            if public and (ledger["bytes"]>=EARLY or ledger["ms"]>=MAX_SECONDS*1000):raise RuntimeError("cumulative stop threshold")
            return
        four,issues=observations(cfg,c,m);row.update(four=four,issues=issues)
        self.save()
        print(label,"four=",four["counts"],"issues=",issues,"IP bytes=",m["ipv4_bytes"],flush=True)
        hard=(c["error"] or not c["tcp_ok"] or not c["connections"]==1 or m["error"] or m["capture_drops"]
              or m["echo"]["write_errors"] or four["bad_payloads"] or any(four["duplicates"])
              or any(four["unexpected"]) or four["not_submitted"] or four["missing_echo_write"])
        if hard or (not public and (issues or four["missing_before_echo"] or four["missing_after_echo"])):
            raise RuntimeError("hard measurement/integrity failure: "+label)
        if public and (ledger["bytes"]>=EARLY or ledger["ms"]>=MAX_SECONDS*1000):
            raise RuntimeError("cumulative stop threshold")

    def cleanup(self):
        if not self.root:return
        command="python3 -c "+shlex.quote(CLEANUP)+" "+shlex.quote(self.root)
        try:r=self.cmd(command)
        except Exception:self.login();r=self.cmd(command)
        self.data["cleanup"]=json.loads(r)
        if not all(self.data["cleanup"]["ports_free"].values()):raise RuntimeError("test ports not free")


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument("--host",required=True);p.add_argument("--fingerprint",required=True);p.add_argument("--user",default="root")
    p.add_argument("--binaries",type=Path,required=True);p.add_argument("--linux-tests",type=Path)
    p.add_argument("--out",type=Path,required=True);p.add_argument("--seed",type=Path,required=True)
    p.add_argument("--password-stdin",action="store_true");p.add_argument("--temp-parent",type=Path)
    p.add_argument("--application",action="store_true",help="HTTP/SOCKS5 application acceptance using the latest ledger as seed")
    a=p.parse_args()
    if not a.application and not a.linux_tests:p.error("--linux-tests is required for the transport matrix")
    a.binaries=a.binaries.resolve();a.out.mkdir(parents=True,exist_ok=False)
    password=sys.stdin.readline().rstrip("\r\n") if a.password_stdin else getpass.getpass("SSH password: ")
    with tempfile.TemporaryDirectory(prefix="nf-qualification-",dir=a.temp_parent) as td:
        run=Campaign(a,password,Path(td));run.save()
        try:
            run.setup()
            if a.application:run.stage("lo-application",0,"netfront3","app",False)
            else:
                for i,m in enumerate(MODES):run.stage("lo-"+m,i,m,"short",False)
            for case in run.plan:run.stage(*case,True)
        except BaseException as e:
            run.data["failure"]=str(e);raise
        finally:
            try:run.cleanup()
            finally:
                if run.ssh:run.ssh.close()
                run.save()
                print("accounted ledger:", run.data["ledger"],"cleanup:",run.data.get("cleanup"),flush=True)


if __name__=="__main__":
    main()
