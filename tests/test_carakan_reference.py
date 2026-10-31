# SPDX-License-Identifier: MIT-0
"""Independent integer/bit-list tANS reference. Not for network protection."""
import collections
import hashlib
import hmac
import itertools
import math
import struct
import unittest

from test_trident_reference import chacha_block

L = 16384
R = 14
PASSWORD = b"carakan-test-only-32-byte-secret!!"


def compile_table(password, code):
    m = code // 100
    unit = L // (1 << m)

    def entropy(n):
        if n == 0:
            return m
        q = n / unit
        return m - q * math.log2(q) - (1 - q) * math.log2(1 - q)

    minor = min(range(unit // 2 + 1), key=lambda n: abs(entropy(n) - code / 100))
    prk = hmac.digest(b"oh-my-hysteria/carakan/v3", password, "sha256")
    rotation_key = hmac.digest(prk, f"interleave/{code}".encode() + b"\x01", "sha256")
    key = hmac.digest(prk, f"spectrum/{code}".encode() + b"\x01", "sha256")
    stream = iter(itertools.chain.from_iterable(chacha_block(key, i) for i in itertools.count()))
    symbols = list(range(256))
    for i in range(255, 0, -1):
        while True:
            v = next(stream) | next(stream) << 8
            if v < 65536 // (i + 1) * (i + 1):
                break
        j = v % (i + 1)
        symbols[i], symbols[j] = symbols[j], symbols[i]
    freq = [0] * 256
    for i in range(1 << m):
        freq[symbols[i]] = unit - minor
        if minor:
            freq[symbols[(1 << m) + i]] = minor
    for _ in range(16):
        spread = [(s, R - (j.bit_length() - 1),
                   (j << (R - (j.bit_length() - 1))) - L)
                  for s, count in enumerate(freq) for j in range(count, 2 * count)]
        for i in range(L - 1, 0, -1):
            while True:
                v = next(stream) | next(stream) << 8
                if v < 65536 // (i + 1) * (i + 1):
                    break
            j = v % (i + 1)
            spread[i], spread[j] = spread[j], spread[i]
        table = finish_table(freq, spread)
        if min(table[3]) >= 0 and max(table[3]) <= 32:
            return (*table, rotation_key)
    raise ValueError("bounded graph compilation exhausted")


def finish_table(freq, spread):
    rows = spread
    inverse = [[] for _ in freq]
    for x, (s, n, base) in enumerate(rows):
        inverse[s].append((x, n, base))

    def enc(s, y):
        # Independent range search rather than Go's normalized-index formula.
        for x, n, base in inverse[s]:
            if base <= y < base + (1 << n):
                return x, y - base, n
        raise ValueError("unreachable encoder state")

    # Build reverse adjacency directly from decoder ranges (not enc()).
    parents = [[] for _ in range(L)]
    for x, (_, n, base) in enumerate(rows):
        for y in range(base, base + (1 << n)):
            parents[y].append(x)
    finish = [0] * L
    distance = [-1] * L
    distance[0] = 0
    queue = collections.deque([0])
    while queue:
        y = queue.popleft()
        # Go BFS considers predecessor symbols in ascending byte order.
        for x in sorted(parents[y], key=lambda x: rows[x][0]):
            if distance[x] < 0:
                distance[x] = distance[y] + 1
                finish[x] = y
                queue.append(x)
    return freq, rows, finish, distance, enc


def pack(table, raw):
    _, rows, finish, _, _, rotation_key = table
    mask = hashlib.sha256(raw[24:]).digest()
    whitened = bytes(a ^ b for a, b in zip(raw[:24], mask[:24]))
    data = whitened + struct.pack(">H", len(raw)) + raw[24:]
    value = int.from_bytes(data, "little")
    state = value & (L - 1)
    pos = R
    out = bytearray()
    while pos < len(data) * 8:
        s, n, base = rows[state]
        out.append(s)
        state = base + ((value >> pos) & ((1 << n) - 1))
        pos += n
    while state:
        out.append(rows[state][0])
        state = finish[state]
    wire = bytes(out)
    counts = collections.Counter(wire)
    spec = struct.pack(">H256H", len(wire), *(counts[s] for s in range(256)))
    shift = int.from_bytes(hmac.digest(rotation_key, spec, "sha256")[:8], "big") % len(wire)
    return wire[shift:] + wire[:shift]


def unpack(table, wire):
    enc = table[4]
    counts = collections.Counter(wire)
    spec = struct.pack(">H256H", len(wire), *(counts[s] for s in range(256)))
    shift = int.from_bytes(hmac.digest(table[5], spec, "sha256")[:8], "big") % len(wire)
    original = wire
    wire = wire[-shift:] + wire[:-shift] if shift else wire
    state = 0
    chunks = []
    for s in reversed(wire):
        state, value, width = enc(s, state)
        chunks.append((value, width))
    value, pos = state, R
    for chunk, width in reversed(chunks):
        value |= chunk << pos
        pos += width
    source = value.to_bytes((pos + 7) // 8, "little")
    size = int.from_bytes(source[24:26], "big")
    ciphertext = source[26:size + 2]
    mask = hashlib.sha256(ciphertext).digest()
    raw = bytes(a ^ b for a, b in zip(source[:24], mask[:24])) + ciphertext
    if len(raw) != size or pack(table, raw) != original:
        raise ValueError("noncanonical")
    return raw


class CarakanReferenceTests(unittest.TestCase):
    def test_golden(self):
        vectors = [
            (100, 149, 1206, "7f19fb34904440526b046570b256663348a86f112212cb734a2962784db33642",
             "56d28b0fa3d719b25fc4123ac9732e22e7cc5858434d3bebc37e88d16abb1806"),
            (450, 612, 1102, "5253cfa9b64fab2930804d61f8d913eb78a19d7731758d64a58bedbbe3736cf3",
             "d6e9db75c57a7f95566892f0c3063982997159c8e9948663f0dd2283bd643c2c"),
            (750, 684, 737, "2eea1638a72e89bc32f11debbc2cf8f96c38da6e3a9b95994ad21ff6322dbc64",
             "e7e32eef391179566bf2db96f370c87072c8a2f2a5bef4e58ca54ab49804c2b3"),
        ]
        for code, size, length, spectrum, digest in vectors:
            table = compile_table(PASSWORD, code)
            freq, rows, finish, _, _, _ = table
            spec = b"".join(struct.pack("<H", n) for n in freq)
            spec += b"".join(struct.pack("<HBB", base, s, n) for s, n, base in rows)
            spec += b"".join(struct.pack("<H", n) for n in finish)
            self.assertEqual(hashlib.sha256(spec).hexdigest(), spectrum)
            wire = pack(table, bytes(i % 256 for i in range(size)))
            self.assertEqual(len(wire), length)
            self.assertEqual(hashlib.sha256(wire).hexdigest(), digest)

    def test_roundtrip_and_bounds(self):
        for code in (100, 250, 400, 450, 750):
            with self.subTest(code=code):
                table = compile_table(PASSWORD, code)
                maximum = min(684, (1232 - max(table[3])) * (code // 100) // 8 - 2)
                for fill in (bytes(maximum), bytes([255]) * maximum,
                             bytes(i % 256 for i in range(maximum))):
                    wire = pack(table, fill)
                    self.assertLessEqual(len(wire), 1232)
                    self.assertEqual(unpack(table, wire), fill)
                self.assertEqual(sum(table[0]), L)
                self.assertGreaterEqual(min(n for _, n, _ in table[1]), code // 100)


if __name__ == "__main__":
    unittest.main()
