// SPDX-License-Identifier: MIT-0

package obfs

// Deliberately independent of Carakan's wire code. GF(256), polynomial 0x11d.
func tasmanMul(a, b byte) byte {
	var r byte
	for b != 0 {
		if b&1 != 0 {
			r ^= a
		}
		hi := a & 128
		a <<= 1
		if hi != 0 {
			a ^= 0x1d
		}
		b >>= 1
	}
	return r
}

func tasmanInv(a byte) byte {
	if a == 0 {
		return 0
	}
	r := byte(1)
	for n := 254; n > 0; n >>= 1 {
		if n&1 != 0 {
			r = tasmanMul(r, a)
		}
		a = tasmanMul(a, a)
	}
	return r
}
func tasmanCoefficient(row, col int) byte { return tasmanInv(byte(row) ^ byte(16+col)) }
func tasmanEncode(sources [][]byte, row int) []byte {
	out := make([]byte, len(sources[0]))
	for i, s := range sources {
		c := tasmanCoefficient(row, i)
		for b, x := range s {
			out[b] ^= tasmanMul(c, x)
		}
	}
	return out
}

// Only 1x1 / 2x2 systems, with bounded widths and immutable input shards.
func tasmanRecover(src [8][]byte, rep [2][]byte, k, width int) ([8][]byte, error) {
	var out [8][]byte
	if k < 2 || k > 8 || !tasmanWidth(width) {
		return out, errTasmanFrame
	}
	var missing, rows []int
	for i := range k {
		if src[i] == nil {
			missing = append(missing, i)
		} else if len(src[i]) != width {
			return out, errTasmanFrame
		}
	}
	for j := range 2 {
		if rep[j] != nil {
			if len(rep[j]) != width {
				return out, errTasmanFrame
			}
			rows = append(rows, j)
		}
	}
	if len(missing) == 0 {
		return out, nil
	}
	if len(missing) > 2 || len(missing) > len(rows) {
		return out, errTasmanResource
	}
	var rhs [2][]byte
	for r := range len(missing) {
		row := rows[r]
		rhs[r] = append([]byte(nil), rep[row]...)
		for i := range k {
			if src[i] != nil {
				c := tasmanCoefficient(row, i)
				for b, x := range src[i] {
					rhs[r][b] ^= tasmanMul(c, x)
				}
			}
		}
	}
	if len(missing) == 1 {
		c := tasmanInv(tasmanCoefficient(rows[0], missing[0]))
		for b := range width {
			rhs[0][b] = tasmanMul(c, rhs[0][b])
		}
		out[missing[0]] = rhs[0]
		return out, nil
	}
	a, b := tasmanCoefficient(rows[0], missing[0]), tasmanCoefficient(rows[0], missing[1])
	c, d := tasmanCoefficient(rows[1], missing[0]), tasmanCoefficient(rows[1], missing[1])
	det := tasmanInv(tasmanMul(a, d) ^ tasmanMul(b, c))
	if det == 0 {
		return out, errTasmanConflict
	}
	x, y := make([]byte, width), make([]byte, width)
	for i := range width {
		x[i] = tasmanMul(det, tasmanMul(d, rhs[0][i])^tasmanMul(b, rhs[1][i]))
		y[i] = tasmanMul(det, tasmanMul(c, rhs[0][i])^tasmanMul(a, rhs[1][i]))
	}
	out[missing[0]], out[missing[1]] = x, y
	return out, nil
}
