# SPDX-License-Identifier: MIT-0
"""Owned namespace verification; never opens a public listener."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tarfile
import time


def main():
    root = Path(sys.argv[1]);source = root/'source';source.mkdir()
    with tarfile.open(root/'source.tar.gz') as a:a.extractall(source,filter='data')
    bootstrap=json.loads(Path('/opt/omhy-servo-20261106/bootstrap.json').read_text())
    goroot=sys.argv[2] if len(sys.argv)>2 else bootstrap['goroot']
    env=dict(os.environ,PATH=goroot+'/bin:'+os.environ['PATH'],GOTOOLCHAIN='local',GOPATH='/opt/omhy-servo-20261106/go-cache',GOMAXPROCS='2',GOMEMLIMIT='600MiB')
    for name in tuple(env):
        if 'SSH_PASSWORD' in name:env.pop(name)
    result={'source_sha256':hashlib.sha256((root/'source.tar.gz').read_bytes()).hexdigest(),'toolchain':subprocess.check_output(['go','version'],env=env,text=True).strip(),'tests':{},'public_proxy_started':False}
    def save():(root/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    def run(name,args,extra=None,timeout=600):
        start=time.monotonic()
        with (root/(name+'.log')).open('w') as log:
            try:code=subprocess.run(args,cwd=source,env=dict(env,**(extra or {})),stdout=log,stderr=log,timeout=timeout).returncode
            except subprocess.TimeoutExpired:code='timeout'
        result['tests'][name]={'returncode':code,'seconds':time.monotonic()-start};save();print(name,code,flush=True)
        if code:raise RuntimeError(name+' failed; stopped')
    ns='omhy-mariner-20261106';created=False;capture=None
    try:
        run('regression',['go','test','-p=1','-count=1','-timeout=5m','./extras/obfs','./app/cmd','./third_party/quic-go','./third_party/quic-go/internal/ackhandler'])
        run('race',['go','test','-p=1','-race','-count=1','-timeout=5m','./extras/obfs','./app/cmd','-run=Mariner|Servo|Tasman'])
        run('paired',['go','test','-p=1','-count=1','-timeout=5m','-v','./extras/obfs','-run=^TestMarinerTrafficExperiment$'],{'OMHY_MARINER_EXPERIMENT':str(root/'paired')})
        run('bench',['go','test','-p=1','-run=^$','-bench=BenchmarkMariner','-benchmem','-benchtime=1s','./extras/obfs'])
        for target in ('FuzzMarinerWire','FuzzMarinerPlain','FuzzMarinerAuthenticatedTrace'):
            run(target,['go','test','-run=^$','-fuzz=^'+target+'$','-fuzztime=20s','-parallel=2','./extras/obfs'])
        run('build-app-test',['go','test','-c','-o',str(root/'cmd.test'),'./app/cmd'])
        subprocess.run(['ip','netns','add',ns],check=True);created=True
        subprocess.run(['ip','-n',ns,'link','set','lo','up','mtu','1280'],check=True)
        audit=root/'wire-audit';audit.mkdir()
        with (root/'capture.log').open('w') as log:capture=subprocess.Popen(['ip','netns','exec',ns,'tcpdump','-n','-U','-i','lo','-w',str(root/'mariner-loopback.pcap'),'udp'],stdout=subprocess.DEVNULL,stderr=log)
        until=time.monotonic()+5
        while not (root/'mariner-loopback.pcap').exists():
            if capture.poll() is not None or time.monotonic()>until:raise RuntimeError('capture readiness failed')
            time.sleep(.01)
        run('mtu1280',['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestMarinerTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_MARINER_WIRE_AUDIT':str(audit)})
        capture.send_signal(signal.SIGINT);capture.wait(timeout=10);capture=None
        run('pcap-audit',['go','test','-p=1','-count=1','-v','./extras/obfs','-run=^TestMarinerCaptureAudit$'],{'OMHY_MARINER_PCAP':str(root/'mariner-loopback.pcap'),'OMHY_MARINER_WIRE_AUDIT':str(audit)})
        for name,args in [('delay20',['delay','20ms']),('loss5',['delay','20ms','loss','5%']),('burst',['delay','40ms','10ms','25%','loss','5%','75%','reorder','10%','50%'])]:
            subprocess.run(['ip','netns','exec',ns,'tc','qdisc','replace','dev','lo','root','netem',*args],check=True)
            run(name,['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestMarinerTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_MARINER_TCP_ONLY':'1'})
    except Exception as exc:result['error']=str(exc)
    finally:
        if capture is not None:capture.terminate();capture.wait(timeout=10)
        if created:
            for pid in subprocess.check_output(['ip','netns','pids',ns],text=True).split():os.kill(int(pid),signal.SIGTERM)
            subprocess.run(['ip','netns','delete',ns],check=True)
        result['udp443']=subprocess.check_output(['ss','-H','-lunp','sport = :443'],text=True).strip();result['namespace_remaining']=ns in subprocess.check_output(['ip','netns','list'],text=True);save()
        with tarfile.open(root/'evidence.tar.gz','w:gz') as a:
            for p in root.iterdir():
                if p.suffix in ('.json','.log','.pcap') or p.name in ('paired','wire-audit'):a.add(p,arcname=p.name)
    print(json.dumps(result,indent=2),flush=True);raise SystemExit(bool(result.get('error')) or bool(result['udp443']) or result['namespace_remaining'])


if __name__=='__main__':main()
