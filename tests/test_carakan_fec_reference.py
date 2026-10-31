# SPDX-License-Identifier: MIT-0
"""Independent bit-polynomial Cauchy erasure reference; public test data only."""
import hashlib
import itertools
import unittest


def mul(a, b):
    value = 0
    while b:
        if b & 1:
            value ^= a
        b >>= 1
        a <<= 1
        if a & 256:
            a ^= 0x11D
    return value


def inverse(a):
    if not a:
        raise ValueError("zero inverse")
    result = 1
    for _ in range(254):
        result = mul(result, a)
    return result


def repairs(data, k, width, count):
    result = []
    for row in range(count):
        parity = bytearray(width)
        for col in range(k):
            coefficient = inverse(row ^ (32 + col))
            for offset, value in enumerate(data[col * width:(col + 1) * width]):
                parity[offset] ^= mul(coefficient, value)
        result.append(bytes(parity))
    return result


def recover(shards, k, width, total):
    # Independent full k-by-k inversion, unlike Go's <=4-erasure solve.
    chosen = sorted(shards)[:k]
    if len(chosen) < k:
        raise ValueError("not enough shards")
    matrix = []
    for index in chosen:
        row = [int(index == col) for col in range(k)] if index < k else [inverse((index - k) ^ (32 + col)) for col in range(k)]
        matrix.append(row + list(shards[index].ljust(width, b"\x00")))
    for col in range(k):
        pivot = next(row for row in range(col, k) if matrix[row][col])
        matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
        scale = inverse(matrix[col][col])
        matrix[col] = [mul(value, scale) for value in matrix[col]]
        for row in range(k):
            if row != col:
                factor = matrix[row][col]
                matrix[row] = [a ^ mul(factor, b) for a, b in zip(matrix[row], matrix[col])]
    decoded = b"".join(bytes(row[k:]) for row in matrix)
    if any(decoded[total:]):
        raise ValueError("nonzero recovered tail padding")
    return decoded[:total]


class CarakanFECReferenceTests(unittest.TestCase):
    def test_field(self):
        for value in range(1, 256):
            self.assertEqual(mul(value, inverse(value)), 1)
            self.assertEqual(mul(value, 0), 0)

    def test_small_all_erasures(self):
        data = bytes(range(37))
        k, width, r = 5, 8, 2
        shards = {i: data[i * width:(i + 1) * width] for i in range(k)}
        shards.update({k + i: row for i, row in enumerate(repairs(data, k, width, r))})
        for dropped in itertools.combinations(range(k + r), r):
            available = {i: row for i, row in shards.items() if i not in dropped}
            self.assertEqual(recover(available, k, width, len(data)), data)

    def test_vectors(self):
        data = bytes(i % 256 for i in range(1200))
        parity = repairs(data, 13, 96, 4)
        # Printed by the offline vector generator and checked by Go as well.
        self.assertEqual(len(parity), 4)
        for dropped in ((0, 1, 2, 12), (3, 7, 13, 16), (13, 14, 15, 16)):
            shards = {i: data[i * 96:(i + 1) * 96] for i in range(13)}
            shards.update({13 + i: row for i, row in enumerate(parity)})
            self.assertEqual(recover({i: row for i, row in shards.items() if i not in dropped}, 13, 96, 1200), data)
        self.assertEqual(hashlib.sha256(b"".join(parity)).hexdigest(), "bee022adeeba3056ed3b33383feee515bc1a56aa6ee3f9373e270a4b1c667c22")


if __name__ == "__main__":
    unittest.main()
