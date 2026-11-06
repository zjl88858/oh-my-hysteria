# SPDX-License-Identifier: MIT-0
"""Isolated owned VPS validation; no public proxy listener."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tarfile
import time


def main():
    root=Path(sys.argv[1]) if len(sys.argv)>1 else Path('/opt/omhy-tasman-20261106');source=root/'source';source.mkdir()
    with tarfile.open(root/'source.tar.gz') as archive:archive.extractall(source,filter='data')
    bootstrap=json.loads(Path('/opt/omhy-servo-20261106/bootstrap.json').read_text())
    env=dict(os.environ,PATH=bootstrap['goroot']+'/bin:'+os.environ['PATH'],GOTOOLCHAIN='local',GOPATH='/opt/omhy-servo-20261106/go-cache',GOMAXPROCS='2',GOMEMLIMIT='600MiB')
    for name in tuple(env):
        if 'SSH_PASSWORD' in name:env.pop(name)
    result={'source_sha256':hashlib.sha256((root/'source.tar.gz').read_bytes()).hexdigest(),'tests':{},'public_proxy_started':False}
    def save():(root/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    def run(name,argv,extra=None,timeout=600):
        with (root/(name+'.log')).open('w') as log:
            try:status=subprocess.run(argv,cwd=source,env=dict(env,**(extra or {})),stdout=log,stderr=log,timeout=timeout).returncode
            except subprocess.TimeoutExpired:status='timeout'
        result['tests'][name]=status;save();print(name,status,flush=True)
        if status:raise RuntimeError(name+' failed; no automatic retry')
    ns='omhy-tasman-20261106';created=False;capture=None
    try:
        run('tasman',['go','test','-p=1','-count=1','-timeout=5m','-v','./extras/obfs','./app/cmd','./third_party/quic-go','-run=Tasman'])
        run('race',['go','test','-p=1','-race','-count=1','-timeout=5m','./extras/obfs','./app/cmd','./third_party/quic-go/...','-run=Tasman|Servo|OuterRecovery|SendQueue'])
        run('paired',['go','test','-p=1','-count=1','-timeout=5m','-v','./extras/obfs','-run=^TestTasmanTrafficExperiment$'],{'OMHY_TASMAN_EXPERIMENT':str(root/'paired')})
        run('bench',['go','test','-p=1','-run=^$','-bench=BenchmarkTasman','-benchmem','-benchtime=1s','./extras/obfs'])
        for target in ('FuzzTasmanWire','FuzzTasmanPlain','FuzzTasmanAuthenticatedTrace'):
            run(target,['go','test','-run=^$','-fuzz=^'+target+'$','-fuzztime=20s','-parallel=2','./extras/obfs'])
        run('build-app-test',['go','test','-c','-o',str(root/'cmd.test'),'./app/cmd'])
        subprocess.run(['ip','netns','add',ns],check=True);created=True
        subprocess.run(['ip','-n',ns,'link','set','lo','up','mtu','1280'],check=True)
        audit=root/'wire-audit';audit.mkdir()
        capture=subprocess.Popen(['ip','netns','exec',ns,'tcpdump','-n','-U','-i','lo','-w',str(root/'tasman-loopback.pcap'),'udp'],stdout=subprocess.DEVNULL,stderr=(root/'capture.log').open('w'))
        until=time.monotonic()+5
        while not (root/'tasman-loopback.pcap').exists():
            if capture.poll() is not None or time.monotonic()>until:raise RuntimeError('capture readiness failed')
            time.sleep(0.01)
        run('mtu1280',['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestTasmanTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_TASMAN_WIRE_AUDIT':str(audit)})
        capture.send_signal(2);capture.wait(timeout=10);capture=None
        run('pcap-audit',['go','test','-p=1','-count=1','-v','./extras/obfs','-run=^TestTasmanCaptureAudit$'],{'OMHY_TASMAN_PCAP':str(root/'tasman-loopback.pcap'),'OMHY_TASMAN_WIRE_AUDIT':str(audit)})
        for name,args in [('delay20',['delay','20ms']),('loss5',['delay','20ms','loss','5%']),('burst',['delay','40ms','10ms','25%','loss','5%','75%','reorder','10%','50%'])]:
            subprocess.run(['ip','netns','exec',ns,'tc','qdisc','replace','dev','lo','root','netem',*args],check=True)
            run(name,['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestTasmanTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_TASMAN_TCP_ONLY':'1'})
    except Exception as exc:result['error']=str(exc)
    finally:
        if capture is not None:capture.terminate();capture.wait(timeout=10)
        if created:
            for pid in subprocess.check_output(['ip','netns','pids',ns],text=True).split():os.kill(int(pid),15)
            subprocess.run(['ip','netns','delete',ns],check=True)
        result['udp443']=subprocess.check_output(['ss','-H','-lunp','sport = :443'],text=True).strip();result['namespace_remaining']=ns in subprocess.check_output(['ip','netns','list'],text=True);save()
        with tarfile.open(root/'evidence.tar.gz','w:gz') as archive:
            for path in root.iterdir():
                if path.suffix in ('.json','.log','.pcap') or path.name in ('paired','wire-audit'):archive.add(path,arcname=path.name)
    print(json.dumps(result,indent=2),flush=True);raise SystemExit(bool(result.get('error')) or bool(result['udp443']) or result['namespace_remaining'])


if __name__=='__main__':main()
