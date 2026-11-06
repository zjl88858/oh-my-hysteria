# SPDX-License-Identifier: MIT-0
"""Independent Tasman profile/GF/AEAD vectors; no network access."""
import hashlib
import json
import struct

from servo_reference import Stream, derive, seal

DOMAIN = b"oh-my-hysteria/tasman/v1"
PASSWORD = b"tasman-independent-vector-password-32+"


def profile(direction):
    stream = Stream(derive(PASSWORD, b"profile/" + (b"c2s" if direction == 0 else b"s2c"), DOMAIN))
    pairs = [(416 + stream.below(85), 616 + stream.below(85)) for _ in range(4)]
    collect, carrier = 2000 + stream.below(2001), 2000 + stream.below(4001)
    repair, tails, padding = 1 + stream.below(2), stream.below(3), stream.below(33)
    return b"".join(struct.pack(">HH", *pair) for pair in pairs) + struct.pack(">HHBBB", collect, carrier, repair, tails, padding)


def mul(a, b):
    out = 0
    for _ in range(8):
        if b & 1:
            out ^= a
        a <<= 1
        if a & 256:
            a ^= 0x11D
        b >>= 1
    return out


def inverse(a):
    return next(x for x in range(1, 256) if mul(a, x) == 1)


def repair(sources, row):
    out = bytearray(len(sources[0]))
    for col, source in enumerate(sources):
        coefficient = inverse(row ^ (16 + col))
        for i, x in enumerate(source):
            out[i] ^= mul(coefficient, x)
    return bytes(out)


def symbol(message, data, width=500, offset=0, total=None):
    record = struct.pack(">IHHH", message, len(data) if total is None else total, offset, len(data)) + data
    return struct.pack(">H", len(record)) + record + bytes(width - 2 - len(record))


def vectors():
    sources = [symbol(i + 1, bytes((i + j) % 256 for j in range(488))) for i in range(8)]
    fec = [{"k": k, "repair_sha256": [hashlib.sha256(repair(sources[:k], row)).hexdigest() for row in (0, 1)]} for k in range(2, 9)]
    frames = []
    for direction in (0, 1):
        for kind in range(4):
            session = bytes(range(16)) if direction == 0 else bytes(range(255, 239, -1))
            counter = ((1 << 64) - 1) if kind == 1 else kind
            pad = bytes(12) if kind != 3 else b""
            if kind == 3:
                body = struct.pack(">IHHH", 99, 1, 0, 1) + b"\xa5"
            elif kind == 2:
                body = bytes(8)
            else:
                desc = struct.pack(">IBBH", 0x10203040, 0 if kind == 0 else 0x80, 0 if kind == 0 else 8, 500)
                body = desc + (sources[0] if kind == 0 else repair(sources, 0))
            plain = struct.pack(">QHH", 1700000000, len(pad), kind) + body + pad
            wire, mask, ad = seal(PASSWORD, direction, session, counter, plain, DOMAIN)
            frames.append({"dir": direction, "kind": kind, "wire_hex": wire.hex(), "mask_hex": mask.hex(), "ad_hex": ad.hex()})
    return {"domain": DOMAIN.decode(), "password_hex": PASSWORD.hex(), "profiles": [profile(d).hex() for d in (0, 1)], "fec": fec, "frames": frames}


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2))
