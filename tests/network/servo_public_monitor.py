# SPDX-License-Identifier: MIT-0
"""Bounded length-only monitor. No payload archive, retries, or counter reset."""
import argparse
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import time

from traffic_budget import TrafficBudget, ipv4_udp_ip_bytes


def main():
    p=argparse.ArgumentParser();p.add_argument('root');p.add_argument('--used',type=int,required=True);p.add_argument('--packets',type=int,required=True);p.add_argument('--seconds',type=int,required=True)
    args=p.parse_args();root=Path(args.root)
    budget=TrafficBudget(6*1024*1024,args.used,args.packets)
    state={'seed_ip_bytes':args.used,'seed_packets':args.packets,'seed_active_seconds':args.seconds,
           'ip_bytes':args.used,'packets':args.packets,'active_seconds':args.seconds,'stages':{},
           'ready':False,'finished':False,'capture_drops':None,'error':None,'payload_contents_recorded':False,
           'stop_threshold_ip_bytes':int(4.5*1024*1024),'limit_ip_bytes':6*1024*1024}
    assert args.used<state['stop_threshold_ip_bytes'] and 0<=args.seconds<297
    stop=False;capture=None;started=time.monotonic();drain=None
    def save():
        state.update(ip_bytes=budget.used_bytes,packets=budget.packets,active_seconds=args.seconds+math.ceil(time.monotonic()-started))
        temp=root/'budget.tmp';temp.write_text(json.dumps(state,indent=2));temp.replace(root/'budget.json')
    def halt(*_):
        nonlocal stop
        stop=True
    def kill_server():
        f=root/'server.pid'
        if f.exists():
            try:
                pid=int(f.read_text());exe=Path('/proc')/str(pid)/'exe'
                if exe.resolve().is_relative_to(root):os.kill(pid,signal.SIGTERM)
            except (FileNotFoundError,ProcessLookupError):pass
    signal.signal(signal.SIGTERM,halt)
    try:
        assert not (root/'budget.json').exists()
        iface=json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True))[0]['dev']
        capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind((iface,0));capture.settimeout(0.1)
        capture.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
        state['ready']=True;state['interface']=iface;save();last=time.monotonic()
        while True:
            now=time.monotonic()
            if stop or (root/'monitor.stop').exists():drain=drain or now+2
            if now-started>300-args.seconds-3:
                state['error']=state['error'] or 'active lifetime exhausted';kill_server();drain=drain or now+2
            if drain is not None and now>=drain:break
            try:frame=capture.recv(65535)
            except socket.timeout:frame=None
            if frame:
                count=ipv4_udp_ip_bytes(frame,443)
                if count:
                    allowed=budget.account(count)
                    stage=(root/'stage').read_text().strip()
                    d=state['stages'].setdefault(stage,{'ip_bytes':0,'packets':0,'payload_max':0})
                    d['ip_bytes']+=count;d['packets']+=1
                    offset=14
                    # The accounting helper accepts VLAN Ethernet as well.
                    kind=int.from_bytes(frame[12:14],'big')
                    while kind in (0x8100,0x88a8):kind=int.from_bytes(frame[offset+2:offset+4],'big');offset+=4
                    header=(frame[offset]&15)*4;u=offset+header
                    size=int.from_bytes(frame[u+4:u+6],'big')-8
                    d['payload_max']=max(d['payload_max'],size)
                    if stage=='servo' and size>1232:raise RuntimeError('Servo wire limit exceeded')
                    if not allowed or budget.used_bytes>=state['stop_threshold_ip_bytes']:
                        state['error']=state['error'] or 'reserved shutdown threshold reached';kill_server()
                        # Keep accounting client shutdown/retransmissions until
                        # the owner stops us; don't hide an uncounted tail.
            if time.monotonic()-last>0.2:save();last=time.monotonic()
    except Exception as exc:
        state['error']=str(exc);kill_server()
    finally:
        if capture is not None:
            try:
                _,drops=struct.unpack('II',capture.getsockopt(263,6,8));state['capture_drops']=drops
                if drops:state['error']=state['error'] or 'capture drops prevent reliable accounting';kill_server()
            except OSError as exc:state['error']=str(exc);kill_server()
            capture.close()
        state['finished']=True;save()


if __name__=='__main__':main()
