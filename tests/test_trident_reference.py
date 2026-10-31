# SPDX-License-Identifier: MIT-0
"""Slow, independent protocol vectors; never used to protect network traffic."""

import hashlib
import hmac
import itertools
import struct
import unittest


PASSWORD = b"trident-test-only-32-byte-secret!!"


def chacha_block(key, counter=0, nonce=bytes(12)):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + [counter]
    state += list(struct.unpack("<3I", nonce))
    words = state.copy()

    def rotate(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def quarter(a, b, c, d):
        words[a] = (words[a] + words[b]) & 0xFFFFFFFF
        words[d] = rotate(words[d] ^ words[a], 16)
        words[c] = (words[c] + words[d]) & 0xFFFFFFFF
        words[b] = rotate(words[b] ^ words[c], 12)
        words[a] = (words[a] + words[b]) & 0xFFFFFFFF
        words[d] = rotate(words[d] ^ words[a], 8)
        words[c] = (words[c] + words[d]) & 0xFFFFFFFF
        words[b] = rotate(words[b] ^ words[c], 7)

    for _ in range(10):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            quarter(*indices)
    return struct.pack("<16I", *((a + b) & 0xFFFFFFFF for a, b in zip(words, state)))


def compile_isa(password):
    # HKDF-SHA256: only one expand block is needed for the 32-byte stream key.
    prk = hmac.digest(b"oh-my-hysteria/trident/v1", password, "sha256")
    key = hmac.digest(prk, b"isa\x01", "sha256")
    stream = iter(itertools.chain.from_iterable(chacha_block(key, i) for i in itertools.count()))

    def below(n):
        while True:
            value = next(stream) | (next(stream) << 8)
            if value < 65536 // n * n:
                return value % n

    opcodes = list(range(256))
    lengths = [0] * 8 + [1] * 8 + [2] * 8 + [4] * 16 + [8] * 24
    for i in range(64):
        j = i + below(256 - i)
        opcodes[i], opcodes[j] = opcodes[j], opcodes[i]
    for i in range(63, 0, -1):
        j = below(i + 1)
        lengths[i], lengths[j] = lengths[j], lengths[i]
    return [(opcodes[i], n, 1 << below(1 if n < 2 else 2 if n < 4 else 3))
            for i, n in enumerate(lengths)]


def reference_pack(isa, raw):
    source = raw[:24] + len(raw).to_bytes(2, "big") + raw[24:]
    # Deliberately use one giant integer and per-bit indexing rather than Go's
    # rolling reservoirs. This reference is for vectors, not performance.
    value = int.from_bytes(source, "little")
    total_bits = len(source) * 8
    consumed = 0
    out = bytearray()
    while consumed < total_bits:
        opcode, operands, alignment = isa[(value >> consumed) & 63]
        consumed += 6
        out.append(opcode)
        out.extend(bytes((-len(out)) % alignment))
        for _ in range(operands):
            out.append((value >> consumed) & 255)
            consumed += 8
    return bytes(out)


class TridentReferenceTests(unittest.TestCase):
    def test_chacha20_rfc8439(self):
        block = chacha_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
        self.assertEqual(block.hex(),
                         "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
                         "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")

    def test_compiler_golden(self):
        isa = compile_isa(PASSWORD)
        digest = hashlib.sha256(bytes(itertools.chain.from_iterable(isa))).hexdigest()
        self.assertEqual(digest, "91d61a59bac85019a01973d9b78e85d4574ba0f8e37b248e634ef661a2c6561b")

    def test_packing_vector(self):
        isa = compile_isa(PASSWORD)
        raw = bytes(i % 256 for i in range(500))
        wire = reference_pack(isa, raw)
        self.assertLessEqual(len(wire), 1222)
        # Exact cross-language vector is also checked by TestTridentGolden.
        self.assertEqual(hashlib.sha256(wire).hexdigest(),
                         "06533375d6426d191d7e7e0df7157236b909a47328bc7a935a46be6aeb63a5ba")


if __name__ == "__main__":
    unittest.main()
