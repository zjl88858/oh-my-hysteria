# SPDX-License-Identifier: MIT-0
"""Length-only cumulative UDP443 budget; no payload storage or automatic retries."""
import json
import math
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import time

from traffic_budget import TrafficBudget, ipv4_udp_ip_bytes


def main():
    root=Path(sys.argv[1]);budget=TrafficBudget(6*1024*1024,3628142,3955)
    state={'seed_ip_bytes':3628142,'seed_packets':3955,'seed_active_seconds':223,'ready':False,'finished':False,'error':None,'capture_drops':None,'stages':{},'payload_contents_recorded':False}
    started=time.monotonic();stop=False;drain=None;capture=None
    def save():
        state.update(ip_bytes=budget.used_bytes,packets=budget.packets,active_seconds=223+math.ceil(time.monotonic()-started))
        p=root/'budget.tmp';p.write_text(json.dumps(state,indent=2));p.replace(root/'budget.json')
    def halt(*_):
        nonlocal stop
        stop=True
    def kill_server():
        p=root/'server.pid'
        if p.exists():
            try:
                pid=int(p.read_text())
                if (Path('/proc')/str(pid)/'exe').resolve().is_relative_to(root):os.kill(pid,signal.SIGTERM)
            except (FileNotFoundError,ProcessLookupError):pass
    signal.signal(signal.SIGTERM,halt)
    try:
        assert not (root/'budget.json').exists()
        iface=json.loads(subprocess.check_output(['ip','-j','route','show','default'],text=True))[0]['dev']
        capture=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3));capture.bind((iface,0));capture.settimeout(0.1);capture.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,4*1024*1024)
        state['ready']=True;state['interface']=iface;save();last=time.monotonic()
        while True:
            now=time.monotonic()
            if stop or (root/'monitor.stop').exists():drain=drain or now+2
            if now-started>=72:state['error']=state['error'] or 'active lifetime shutdown';kill_server();drain=drain or now+2
            if drain is not None and now>=drain:break
            try:frame=capture.recv(65535)
            except socket.timeout:frame=None
            if frame:
                count=ipv4_udp_ip_bytes(frame,443)
                if count:
                    allowed=budget.account(count);stage=(root/'stage').read_text().strip();d=state['stages'].setdefault(stage,{'ip_bytes':0,'packets':0,'payload_max':0});d['ip_bytes']+=count;d['packets']+=1
                    offset=14;kind=int.from_bytes(frame[12:14],'big')
                    while kind in (0x8100,0x88a8):kind=int.from_bytes(frame[offset+2:offset+4],'big');offset+=4
                    u=offset+(frame[offset]&15)*4;size=int.from_bytes(frame[u+4:u+6],'big')-8;d['payload_max']=max(d['payload_max'],size)
                    if stage=='tasman' and size>1232:raise RuntimeError('Tasman wire limit exceeded')
                    if not allowed or budget.used_bytes>=int(4.5*1024*1024):state['error']=state['error'] or 'reserved byte threshold';kill_server()
            if time.monotonic()-last>0.2:save();last=time.monotonic()
    except Exception as exc:state['error']=str(exc);kill_server()
    finally:
        if capture is not None:
            try:
                _,drops=struct.unpack('II',capture.getsockopt(263,6,8));state['capture_drops']=drops
                if drops:state['error']=state['error'] or 'capture drops';kill_server()
            except OSError as exc:state['error']=str(exc);kill_server()
            capture.close()
        state['finished']=True;save()


if __name__=='__main__':main()
