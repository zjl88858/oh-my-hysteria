# SPDX-License-Identifier: MIT-0
"""Mariner v1 independent wire compiler and AEAD vectors (offline)."""
import hashlib
import hmac
import json
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from servo_reference import derive, hchacha

DOMAIN = b"oh-my-hysteria/mariner/v1"
PASSWORD = b"mariner-independent-vector-password-32+"


class Stream:
    def __init__(self, key, label):
        self.key, self.label = key, label
        self.counter, self.offset, self.block = 0, 32, b""

    def below(self, n):
        if not 1 <= n <= 65536:
            raise ValueError("range")
        for _ in range(128):
            if self.offset == 32:
                self.block = hmac.digest(self.key, b"compile\0" + self.label + struct.pack(">Q", self.counter), "sha256")
                self.counter += 1
                self.offset = 0
            x = int.from_bytes(self.block[self.offset:self.offset + 4], "big")
            self.offset += 4
            if x < (1 << 32) // n * n:
                return x % n
        raise ValueError("rejection exhaustion")


def weighted(stream, weights):
    x = stream.below(sum(weights))
    for i, w in enumerate(weights):
        x -= w
        if x < 0:
            return i
    raise AssertionError("positive weights")


def shuffle(s, xs):
    for i in range(len(xs) - 1, 0, -1):
        j = s.below(i + 1)
        xs[i], xs[j] = xs[j], xs[i]


def affine(table):
    for x in range(256):
        y = table[0]
        for bit in range(8):
            if x & (1 << bit):
                y ^= table[1 << bit] ^ table[0]
        if y != table[x]:
            return False
    return True


def profile(password=PASSWORD, direction=0):
    key = derive(password, b"profile/" + (b"c2s" if direction == 0 else b"s2c"), DOMAIN)
    s = Stream(key, b"profile")
    r = 16 + s.below(5)
    orders = [1 + s.below(16) for _ in range(3)]
    pool = [16, 32, 64, 128, 0][s.below(5)]
    deltas = [1 + s.below(16) for _ in range(4)]
    tables, s = [], Stream(key, b"tables")
    for _ in range(16):
        for _ in range(16):
            table = list(range(256))
            shuffle(s, table)
            if not affine(table):
                tables.append(table)
                break
        else:
            raise ValueError("affine exhaustion")
    return dict(key=key, density=r, orders=orders, pool=pool, deltas=deltas, tables=tables)


def profile_bytes(p):
    return bytes([p['density'], p['pool'], *p['orders'], *p['deltas']]) + b"".join(bytes(t) for t in p['tables'])


def graph(p, length):
    k = 64 * length // (64 + p['density'])
    r = length - k
    if not (k >= 63 and 0 < r < k and k - r >= 4 and length <= 1232):
        raise ValueError("dimensions")
    s = Stream(p['key'], b"graph" + struct.pack(">H", length))
    source = list(range(k))
    shuffle(s, source)
    pool = source[r:r + (min(p['pool'], k - r) if p['pool'] else k - r)]
    relations = []
    for j in range(r):
        m = 3 + weighted(s, p['orders'])
        parents, swaps = [source[j]], []
        for i in range(m - 1):
            x = i + s.below(len(pool) - i)
            swaps.append(x)
            pool[i], pool[x] = pool[x], pool[i]
            parents.append(pool[i])
        for i in range(m - 2, -1, -1):
            pool[i], pool[swaps[i]] = pool[swaps[i]], pool[i]
        tables = [s.below(16) for _ in range(m + 1)]
        relations.append((parents, tables))
    positions = list(range(length))
    shuffle(s, positions)
    return dict(k=k, r=r, length=length, relations=relations, positions=positions)


def graph_bytes(g):
    out = bytearray(struct.pack(">HHH", g['k'], g['r'], g['length']))
    for parents, tables in g['relations']:
        out.append(len(parents))
        for parent, table in zip(parents, tables):
            out.extend(struct.pack(">HB", parent, table))
        out.append(tables[-1])
    for position in g['positions']:
        out.extend(struct.pack(">H", position))
    return bytes(out)


def encode(p, g, raw):
    assert len(raw) == g['k']
    logical = bytearray(raw)
    for parents, tables in g['relations']:
        x = 0
        for parent, table in zip(parents, tables):
            x ^= p['tables'][table][raw[parent]]
        logical.append(p['tables'][tables[-1]][x])
    out = bytearray(g['length'])
    for pos, x in zip(g['positions'], logical):
        out[pos] = x
    return bytes(out)


def decode(p, g, wire):
    raw = bytes(wire[i] for i in g['positions'][:g['k']])
    if encode(p, g, raw) != wire:
        raise ValueError("relations")
    return raw


def base(p, n):
    return ((64 + p['density']) * n + 63) // 64


def seal(password, direction, session, counter, plain, length):
    suffix = b"c2s" if direction == 0 else b"s2c"
    nonce = session + struct.pack(">Q", counter)
    ad = DOMAIN + b"\0frame\0" + bytes([direction]) + struct.pack(">H", length)
    key = derive(password, b"aead/" + suffix, DOMAIN)
    cipher = ChaCha20Poly1305(hchacha(key, nonce[:16])).encrypt(bytes(4) + nonce[16:], plain, ad)
    hp = derive(password, b"nonce-mask/" + suffix, DOMAIN)
    mask = hmac.digest(hp, DOMAIN + b"\0nonce-mask\0" + bytes([direction]) + struct.pack(">H", length) + cipher[-16:], "sha256")[:24]
    return bytes(a ^ b for a, b in zip(nonce, mask)) + cipher


def vectors():
    result = dict(domain=DOMAIN.decode(), password_hex=PASSWORD.hex(), profiles=[], frames=[])
    for direction in (0, 1):
        p = profile(PASSWORD, direction)
        result['profiles'].append(dict(direction=direction, density=p['density'], pool=p['pool'], orders=p['orders'], deltas=p['deltas'], sha256=hashlib.sha256(profile_bytes(p)).hexdigest(), graphs=[]))
        for length in (base(p, 63), 512, 900, 1232):
            g = graph(p, length)
            result['profiles'][-1]['graphs'].append(dict(length=length, sha256=hashlib.sha256(graph_bytes(g)).hexdigest()))
        for f, delta, counter in [(1, 0, 0), (1, 3, 1 << 63), (600, 2, (1 << 64) - 1)]:
            data = bytes((i * 31 + 7) % 256 for i in range(f))
            length = base(p, 62 + f) + delta
            g = graph(p, length)
            session = bytes(range(16)) if direction == 0 else bytes(range(255, 239, -1))
            plain = struct.pack(">QBBH", 1700000000, 1, 0, 10 + f) + struct.pack(">IHHH", 0x10203040, 1 if f == 1 else 1200, 0, f) + data + bytes(g['k'] - 62 - f)
            raw = seal(PASSWORD, direction, session, counter, plain, length)
            wire = encode(p, g, raw)
            result['frames'].append(dict(direction=direction, fragment=f, delta=delta, counter=str(counter), length=length, raw_hex=raw.hex(), wire_hex=wire.hex()))
    return result


if __name__ == '__main__':
    print(json.dumps(vectors(), indent=2))
