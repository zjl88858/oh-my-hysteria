# SPDX-License-Identifier: MIT-0
"""Owned VPS-local Servo validation. Never binds a public proxy listener."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile


def main():
    root=Path('/opt/omhy-servo-20261106')
    source=root/'source'
    resume=os.environ.get('OMHY_SERVO_RESUME')=='1'
    if not resume:
        source.mkdir(mode=0o700)
        with tarfile.open(root/'source.tar.gz') as archive:
            archive.extractall(source,filter='data')
    bootstrap=json.loads((root/'bootstrap.json').read_text())
    env=dict(os.environ,PATH=bootstrap['goroot']+'/bin:'+os.environ['PATH'],GOTOOLCHAIN='local',
             GOPATH=str(root/'go-cache'),GOMAXPROCS='2',GOMEMLIMIT='600MiB')
    for name in tuple(env):
        if 'SSH_PASSWORD' in name:env.pop(name)
    result={'source_sha256':hashlib.sha256((root/'source.tar.gz').read_bytes()).hexdigest(),
            'tests':{},'public_proxy_started':False}
    if resume:
        old=json.loads((root/'results.json').read_text())
        assert old['source_sha256']==result['source_sha256']
        assert all(value==0 for value in old['tests'].values()),'failed tests require an explicit correction, not automatic retry'
        result['tests']=old['tests']
        result['prior_controller_error']=old.get('error')

    def save(): (root/'results.json').write_text(json.dumps(result,indent=2)+'\n')
    def run(name,argv,extra=None,timeout=900):
        if name in result['tests']:
            assert result['tests'][name]==0
            print(name,'retained completed pass',flush=True)
            return
        with (root/(name+'.log')).open('w') as log:
            try:status=subprocess.run(argv,cwd=source,env=dict(env,**(extra or {})),stdout=log,stderr=log,timeout=timeout).returncode
            except subprocess.TimeoutExpired:status='timeout'
        result['tests'][name]=status;save();print(name,status,flush=True)
        if status:raise RuntimeError(name+' failed; retained log')

    ns='omhy-servo-20261106'
    created=False
    capture=None
    try:
        run('servo',['go','test','-p=1','-count=1','-timeout=5m','-v','./extras/obfs','./app/cmd','-run=Servo'])
        run('race',['go','test','-p=1','-race','-count=1','-timeout=5m','./extras/obfs','./app/cmd','./third_party/quic-go','-run=Servo|SendQueue|AsyncPacketConn'])
        run('paired',['go','test','-p=1','-count=1','-timeout=4m','-v','./extras/obfs','-run=^TestServoTrafficExperiment$'],{'OMHY_SERVO_EXPERIMENT':str(root/'paired')})
        run('codec-bench',['go','test','-p=1','-run=^$','-bench=BenchmarkServoCodec','-benchmem','-benchtime=1s','./extras/obfs'])
        for target in ('FuzzServoWire','FuzzServoPlain','FuzzServoAuthenticatedTrace','FuzzServoPacker'):
            run(target,['go','test','-run=^$','-fuzz=^'+target+'$','-fuzztime=20s','-parallel=2','./extras/obfs'])
        run('build-app-test',['go','test','-c','-o',str(root/'cmd.test'),'./app/cmd'])
        subprocess.run(['ip','netns','add',ns],check=True);created=True
        subprocess.run(['ip','-n',ns,'link','set','lo','up','mtu','1280'],check=True)
        audit=root/'wire-audit';audit.mkdir(mode=0o700)
        capture=subprocess.Popen(['ip','netns','exec',ns,'tcpdump','-n','-U','-i','lo','-w',str(root/'servo-loopback.pcap'),'udp'],stdout=subprocess.DEVNULL,stderr=(root/'capture.log').open('w'))
        # A readiness barrier avoids starting tests before tcpdump attaches.
        import time
        limit=time.monotonic()+5
        while not (root/'servo-loopback.pcap').exists():
            if capture.poll() is not None or time.monotonic()>limit:raise RuntimeError('capture failed to attach')
            time.sleep(0.01)
        run('mtu1280-pcap',['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestServoTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_SERVO_WIRE_AUDIT':str(audit)})
        capture.send_signal(2);capture.wait(timeout=10);capture=None
        run('pcap-audit',['go','test','-p=1','-count=1','-v','./extras/obfs','-run=^TestServoCaptureAudit$'],{'OMHY_SERVO_PCAP':str(root/'servo-loopback.pcap'),'OMHY_SERVO_WIRE_AUDIT':str(audit)})
        subprocess.run(['ip','netns','exec',ns,'tc','qdisc','add','dev','lo','root','netem','delay','20ms'],check=True)
        run('mtu1280-delay',['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestServoTLSAndTransfer$','-test.timeout=3m','-test.v'])
        subprocess.run(['ip','netns','exec',ns,'tc','qdisc','change','dev','lo','root','netem','delay','20ms','loss','5%'],check=True)
        run('mtu1280-loss-tcp',['ip','netns','exec',ns,str(root/'cmd.test'),'-test.run=^TestServoTLSAndTransfer$','-test.timeout=3m','-test.v'],{'OMHY_SERVO_TCP_ONLY':'1'})
    except Exception as exc:
        result['error']=str(exc)
    finally:
        if capture is not None:
            capture.terminate();capture.wait(timeout=10)
        if created:
            pids=subprocess.check_output(['ip','netns','pids',ns],text=True).split()
            for pid in pids:os.kill(int(pid),15)
            subprocess.run(['ip','netns','delete',ns],check=True)
        result['udp443']=subprocess.check_output(['ss','-H','-lunp','sport = :443'],text=True).strip()
        result['namespace_remaining']=ns in subprocess.check_output(['ip','netns','list'],text=True)
        save()
        with tarfile.open(root/'evidence.tar.gz','w:gz') as archive:
            for path in root.iterdir():
                if path.suffix in ('.json','.log','.pcap') or path.name in ('paired','wire-audit'):
                    archive.add(path,arcname=path.name)
    print(json.dumps(result,indent=2),flush=True)
    raise SystemExit(bool(result.get('error')) or bool(result['udp443']) or result['namespace_remaining'])


if __name__=='__main__':main()
