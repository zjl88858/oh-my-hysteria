// SPDX-License-Identifier: MIT-0

package obfs

import "math/bits"

const (
	carakanMaxRepair        = 4
	carakanMaxData          = carakanMaxParts - carakanMaxRepair
	carakanReassemblyBudget = 600 * 1024
)

// A systematic Cauchy code over GF(256), polynomial x^8+x^4+x^3+x^2+1.
// The repair row j / data column i coefficient is 1/(j XOR (32+i)).
// Disjoint distinct row/column labels make every square Cauchy minor invertible.
// No third-party codec, unauthenticated parity, or cross-message state is used.
var carakanField = func() struct {
	mul [256][256]byte
	inv [256]byte
} {
	var field struct {
		mul [256][256]byte
		inv [256]byte
	}
	for a := range 256 {
		for b := range 256 {
			x, y, product := a, b, 0
			for y != 0 {
				if y&1 != 0 {
					product ^= x
				}
				y >>= 1
				x <<= 1
				if x&256 != 0 {
					x ^= 0x11d
				}
			}
			field.mul[a][b] = byte(product)
			if product == 1 {
				field.inv[a] = byte(b)
			}
		}
	}
	return field
}()

func carakanRepairCount(data int) int {
	if data <= 1 {
		return 0
	}
	return min(carakanMaxRepair, (data+3)/4)
}

func carakanRepair(dst, data []byte, width, count, row int) {
	clear(dst[:width])
	for col := range count {
		coefficient := carakanField.inv[byte(row)^byte(32+col)]
		products := &carakanField.mul[coefficient]
		start := col * width
		for j, value := range data[start:min(start+width, len(data))] {
			dst[j] ^= products[value]
		}
	}
}

// recover reconstructs only missing data shards (at most four), rather than
// inverting a full k-by-k matrix. It is called once enough authenticated shards
// are present; scratch and CPU are bounded, and padding must reconstruct to zero.
func (a *carakanAssembly) recover() (int, bool) {
	k, width := int(a.count), int(a.width)
	var missing, rows [carakanMaxRepair]int
	m := 0
	for i := range k {
		if a.mask&(uint32(1)<<i) == 0 {
			if m == carakanMaxRepair {
				return 0, false
			}
			missing[m] = i
			m++
		}
	}
	if m == 0 {
		return 0, true
	}
	if bits.OnesCount32(a.mask) < k {
		return 0, false
	}
	n := 0
	for row := range carakanRepairCount(k) {
		if a.mask&(uint32(1)<<(k+row)) != 0 && n < m {
			rows[n] = row
			n++
		}
	}
	if n != m {
		return 0, false
	}
	var matrix [carakanMaxRepair][2 * carakanMaxRepair]byte
	for row := range m {
		for col := range m {
			matrix[row][col] = carakanField.inv[byte(rows[row])^byte(32+missing[col])]
		}
		matrix[row][m+row] = 1
	}
	for col := range m {
		pivot := col
		for pivot < m && matrix[pivot][col] == 0 {
			pivot++
		}
		if pivot == m {
			return 0, false
		}
		matrix[col], matrix[pivot] = matrix[pivot], matrix[col]
		products := &carakanField.mul[carakanField.inv[matrix[col][col]]]
		for j := range 2 * m {
			matrix[col][j] = products[matrix[col][j]]
		}
		for row := range m {
			if row == col {
				continue
			}
			products := &carakanField.mul[matrix[row][col]]
			for j := range 2 * m {
				matrix[row][j] ^= products[matrix[col][j]]
			}
		}
	}
	// Subtract known data from the selected parity equations in place. This
	// assembly is immediately delivered or abandoned, never reused afterward.
	for row := range m {
		residual := a.parity[rows[row]*width : (rows[row]+1)*width]
		for col := range k {
			if a.mask&(uint32(1)<<col) == 0 {
				continue
			}
			products := &carakanField.mul[carakanField.inv[byte(rows[row])^byte(32+col)]]
			start := col * width
			for j, value := range a.data[start:min(start+width, len(a.data))] {
				residual[j] ^= products[value]
			}
		}
	}
	for col := range m {
		for j := range width {
			var value byte
			for row := range m {
				value ^= carakanField.mul[matrix[col][m+row]][a.parity[rows[row]*width+j]]
			}
			index := missing[col]*width + j
			if index < len(a.data) {
				a.data[index] = value
			} else if value != 0 {
				return 0, false
			}
		}
	}
	return m, true
}
