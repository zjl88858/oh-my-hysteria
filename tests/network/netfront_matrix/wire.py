# SPDX-License-Identifier: MIT-0
"""Bounded, filtered Linux UDP observation. No packet captures on disk."""
import ctypes as C
import ctypes.util
import hmac
import socket
import struct
import subprocess


def side_decoder(password, lanes):
    prk = hmac.digest(b"oh-my-hysteria/netfront/v1", password.encode(), "sha256")
    keys = {d: hmac.digest(prk, b"side/"+name+b"\x01", "sha256") for d,name in
            (("rx",b"client-to-server"),("tx",b"server-to-client"))}
    sodium = ctypes.util.find_library("sodium")
    if sodium:
        lib = C.CDLL(sodium)
        lib.sodium_init()
        dec = lib.crypto_aead_xchacha20poly1305_ietf_decrypt
        dec.argtypes = [C.c_void_p,C.c_void_p,C.c_void_p,C.c_char_p,C.c_ulonglong,
                        C.c_char_p,C.c_ulonglong,C.c_char_p,C.c_char_p]
        def open_box(key, nonce, box, aad):
            out=C.create_string_buffer(len(box)-16)
            return out.raw if dec(out,None,None,box,len(box),aad,len(aad),nonce,key)==0 else b""
    else:
        from cryptography.exceptions import InvalidTag
        from servo_reference import ChaCha20Poly1305, hchacha
        def open_box(key, nonce, box, aad):
            try:return ChaCha20Poly1305(hchacha(key,nonce[:16])).decrypt(bytes(4)+nonce[16:],box,aad)
            except InvalidTag:return b""

    def decode(data, lane, d):
        if not 83<=len(data)<=384:return None
        p=open_box(keys[d],data[:24],data[24:],bytes((lanes,lane)))
        if len(p)<43 or p[0] not in (1,2,3,4):return None
        sid=p[1:17];seq=int.from_bytes(p[17:25],"big");n=int.from_bytes(p[41:43],"big")
        if not any(sid) or not seq or n>len(p)-43 or ((not any(p[25:41]))!=(p[0]==1)):return None
        if (p[0]==3 and n<84) or (p[0]!=3 and n!=0):return None
        return ("","probe","offer","data","cover")[p[0]],sid,seq
    return decode


def filtered_socket(iface,host,ports):
    dest=" or ".join(f"dst port {p}" for p in ports);src=" or ".join(f"src port {p}" for p in ports)
    expr=f"ip and udp and ((dst host {host} and ({dest})) or (src host {host} and ({src})))"
    lines=subprocess.check_output(["tcpdump","-i",iface,"-y","EN10MB","-ddd",expr],
                                  text=True,stderr=subprocess.DEVNULL).splitlines()
    class Ins(C.Structure):
        _fields_=[("code",C.c_ushort),("jt",C.c_ubyte),("jf",C.c_ubyte),("k",C.c_uint32)]
    class Prog(C.Structure):
        _fields_=[("length",C.c_ushort),("instructions",C.POINTER(Ins))]
    ins=(Ins*int(lines[0]))(*(Ins(*map(int,line.split())) for line in lines[1:]))
    s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,0)  # no traffic until bound below
    try:
        s.setsockopt(socket.SOL_SOCKET,socket.SO_RCVBUF,2<<20)
        s.setsockopt(socket.SOL_SOCKET,26,bytes(Prog(len(ins),ins)))  # SO_ATTACH_FILTER
        s.bind((iface,3));s.setblocking(False)
        return s
    except BaseException:
        s.close();raise


class Meter:
    def __init__(self,cfg):
        ports=cfg["ports"]
        self.local=socket.inet_aton(cfg["host"]);self.ports=ports;self.iface=cfg["iface"]
        self.decode=side_decoder(cfg["psk"],len(ports)-1) if len(ports)>1 else None
        self.sock=filtered_socket(self.iface,cfg["host"],ports)
        self.rows={str(p):{d:dict(packets=0,ip_bytes=0,udp_bytes=0,max_udp=0,kinds={},epochs={}) for d in ("rx","tx")} for p in ports}
        self.ids={};self.total=0;self.packets=0

    def consume(self):
        b,a=self.sock.recvfrom(65535)
        if self.iface=="lo" and a[2]==socket.PACKET_OUTGOING:return
        off=14; et=int.from_bytes(b[12:14],"big")
        for _ in range(2):
            if et not in (0x8100,0x88a8):break
            et=int.from_bytes(b[off+2:off+4],"big");off+=4
        if et!=0x0800 or len(b)<off+28 or b[off]>>4!=4 or b[off+9]!=17:raise ValueError("unexpected captured frame")
        ihl=(b[off]&15)*4;iplen=int.from_bytes(b[off+2:off+4],"big");u=off+ihl
        if ihl<20 or iplen<ihl+8 or len(b)<off+iplen or int.from_bytes(b[off+6:off+8],"big")&0x3fff:
            raise ValueError("malformed/fragmented captured UDP")
        src,dst,ulen=struct.unpack_from(">HHH",b,u)
        if dst in self.ports and b[off+16:off+20]==self.local:p,d=dst,"rx"
        elif src in self.ports and b[off+12:off+16]==self.local:p,d=src,"tx"
        else:raise ValueError("packet outside BPF filter")
        if ulen<8 or ulen+ihl!=iplen:raise ValueError("inconsistent UDP length")
        n=ulen-8;r=self.rows[str(p)][d]
        self.total+=iplen;self.packets+=1;r["ip_bytes"]+=iplen;r["udp_bytes"]+=n
        r["packets"]+=1;r["max_udp"]=max(r["max_udp"],n)
        if n>(1232 if p==self.ports[0] else 384):raise ValueError("wire limit exceeded")
        if p==self.ports[0]:return
        decoded=self.decode(b[u+8:u+ulen],self.ports.index(p),d)
        kind="other"
        if decoded:
            kind,sid,seq=decoded
            if sid not in self.ids and len(self.ids)>=8:raise ValueError("unexpected number of sessions")
            label=self.ids.setdefault(sid,len(self.ids)+1)
            key=f"{label}:{seq}"
            if key not in r["epochs"] and len(r["epochs"])>=128:raise ValueError("unexpected number of leases")
            epoch=r["epochs"].setdefault(key,{})
            epoch[kind]=epoch.get(kind,0)+1
        r["kinds"][kind]=r["kinds"].get(kind,0)+1

    def finish(self):
        try:kernel,drops=struct.unpack("=II",self.sock.getsockopt(263,6,8))
        finally:self.sock.close()
        return dict(ports=self.rows,ipv4_bytes=self.total,packets=self.packets,capture_drops=drops,kernel_frames=kernel)
