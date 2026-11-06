# SPDX-License-Identifier: MIT-0
"""Independent Servo v1 vectors, for offline tests only, never network traffic.

HChaCha20 and profile stream are specified with integers, independent of Go's
library / packing code. The IETF AEAD uses the locked cryptography dependency.
"""

import hashlib
import hmac
import itertools
import json
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


DOMAIN = b"oh-my-hysteria/servo/v1"
PASSWORD = b"servo-test-only-32-byte-secret!!"
SEED = bytes(range(32))


def derive(password, label, domain=DOMAIN):
    if not 32 <= len(password) <= 1024:
        raise ValueError("password length")
    prk = hmac.digest(domain, password, "sha256")
    return hmac.digest(prk, label + b"\x01", "sha256")


def rounds(state):
    w = state.copy()

    def rol(x, n):
        return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF

    def qr(a, b, c, d):
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF
        w[d] = rol(w[d] ^ w[a], 16)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF
        w[b] = rol(w[b] ^ w[c], 12)
        w[a] = (w[a] + w[b]) & 0xFFFFFFFF
        w[d] = rol(w[d] ^ w[a], 8)
        w[c] = (w[c] + w[d]) & 0xFFFFFFFF
        w[b] = rol(w[b] ^ w[c], 7)

    for _ in range(10):
        for indices in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                        (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            qr(*indices)
    return w


def chacha_block(key, counter=0):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + [counter, 0, 0, 0]
    return struct.pack("<16I", *((a + b) & 0xFFFFFFFF for a, b in zip(state, rounds(state))))


def hchacha(key, nonce16):
    state = list(struct.unpack("<4I", b"expand 32-byte k"))
    state += list(struct.unpack("<8I", key)) + list(struct.unpack("<4I", nonce16))
    w = rounds(state)
    return struct.pack("<8I", *(w[i] for i in (0, 1, 2, 3, 12, 13, 14, 15)))


class Stream:
    def __init__(self, key):
        self.stream = iter(itertools.chain.from_iterable(chacha_block(key, i) for i in itertools.count()))

    def below(self, n):
        for _ in range(128):
            x = (next(self.stream) << 8) | next(self.stream)
            if x < 65536 // n * n:
                return x % n
        raise ValueError("bounded random mapping exhausted")


def profile(password, direction):
    s = Stream(derive(password, b"profile/" + (b"c2s" if direction == 0 else b"s2c")))
    count, jitter, wait = 6 + s.below(7), s.below(17), 200 + s.below(301)
    centers = [(640 + s.below(461), 1 + s.below(32)) for _ in range(count)]
    return jitter, wait, centers


def profile_bytes(p):
    jitter, wait, centers = p
    return struct.pack(">BBH", len(centers), jitter, wait) + b"".join(struct.pack(">HH", *x) for x in centers)


def sample(p, stream):
    jitter, _, centers = p
    x = stream.below(sum(weight for _, weight in centers))
    for center, weight in centers:
        x -= weight
        if x < 0:
            return max(640, min(1100, center + stream.below(2 * jitter + 1) - jitter))
    raise AssertionError("positive weights")


def fixture(name, direction):
    session = bytes(range(16)) if direction == 0 else bytes(255 - i for i in range(16))
    if name == "tiny":
        counter, records = (0 if direction == 0 else 1 << 63), [(1, 1, 0, b"\xa5")]
    else:
        counter = (1 << 64) - 1
        records = []
        for i in range(8):
            n = 137 if i < 7 else 141
            records.append((0x10203040 + i, n + 3, 3, bytes((i * 31 + j) % 256 for j in range(n))))
    return session, counter, 1700000000, records


def encode_plain(born, records):
    data = b"".join(struct.pack(">IHHH", message, total, offset, len(fragment)) + fragment
                    for message, total, offset, fragment in records)
    return struct.pack(">QBBH", born, len(records), 0, len(data)) + data


def seal(password, direction, session, counter, plain, domain=DOMAIN):
    suffix = b"c2s" if direction == 0 else b"s2c"
    nonce = session + struct.pack(">Q", counter)
    w = 24 + len(plain) + 16
    ad = domain + b"\0frame\0" + bytes([direction]) + struct.pack(">H", w)
    key = derive(password, b"aead/" + suffix, domain)
    subkey = hchacha(key, nonce[:16])
    ciphertext = ChaCha20Poly1305(subkey).encrypt(bytes(4) + nonce[16:], plain, ad)
    hp = derive(password, b"nonce-mask/" + suffix, domain)
    mask = hmac.digest(hp, domain + b"\0nonce-mask\0" + bytes([direction]) + struct.pack(">H", w) + ciphertext[-16:], "sha256")[:24]
    protected = bytes(a ^ b for a, b in zip(nonce, mask))
    return protected + ciphertext, mask, ad


def vectors():
    result = {"domain": DOMAIN.decode(), "password_hex": PASSWORD.hex(), "shape_seed_hex": SEED.hex(),
              "profiles": [], "frames": []}
    for direction in (0, 1):
        p, s = profile(PASSWORD, direction), Stream(SEED)
        result["profiles"].append({"direction": direction, "serialized_hex": profile_bytes(p).hex(),
                                   "capacities": [sample(p, s) for _ in range(32)]})
        for name in ("tiny", "max"):
            session, counter, born, records = fixture(name, direction)
            plain = encode_plain(born, records)
            wire, mask, ad = seal(PASSWORD, direction, session, counter, plain)
            v = {"fixture": name, "direction": direction, "session_hex": session.hex(), "counter": str(counter),
                 "born": born, "wire_length": len(wire), "wire_sha256": hashlib.sha256(wire).hexdigest(),
                 "plain_sha256": hashlib.sha256(plain).hexdigest(), "ad_hex": ad.hex(),
                 "mask_hex": mask.hex(), "protected_nonce_hex": wire[:24].hex(), "tag_hex": wire[-16:].hex()}
            if name == "tiny":
                v["wire_hex"] = wire.hex()
            result["frames"].append(v)
    return result


if __name__ == "__main__":
    print(json.dumps(vectors(), indent=2))
