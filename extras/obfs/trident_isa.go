// SPDX-License-Identifier: MIT-0

package obfs

import (
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	"golang.org/x/crypto/chacha20"
)

type tridentInstruction struct {
	opcode, operands, alignment byte
}

type tridentISA struct {
	code    [64]tridentInstruction
	reverse [256]int16
}

func tridentDerive(password []byte, domain string, size int) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("trident: password must contain 32..1024 bytes; use a random secret")
	}
	return hkdf.Key(sha256.New, password, []byte("oh-my-hysteria/trident/v1"), domain, size)
}

// The deterministic compiler uses a domain-separated ChaCha20 stream, not the
// runtime fragment sampler. Rejection sampling avoids biased opcode subsets.
type tridentCompiler struct{ stream *chacha20.Cipher }

func (r tridentCompiler) below(n int) int {
	limit := 65536 / n * n
	for {
		var b [2]byte
		r.stream.XORKeyStream(b[:], b[:])
		v := int(binary.LittleEndian.Uint16(b[:]))
		if v < limit {
			return v % n
		}
	}
}

func compileTridentISA(password []byte) (tridentISA, error) {
	var isa tridentISA
	seed, err := tridentDerive(password, "isa", 32)
	if err != nil {
		return isa, err
	}
	stream, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, chacha20.NonceSize))
	if err != nil {
		return isa, err
	}
	r := tridentCompiler{stream}
	var opcodes [256]byte
	for i := range opcodes {
		opcodes[i] = byte(i)
		isa.reverse[i] = -1
	}
	var lengths [64]byte
	for i := range lengths {
		switch {
		case i < 8:
			lengths[i] = 0
		case i < 16:
			lengths[i] = 1
		case i < 24:
			lengths[i] = 2
		case i < 40:
			lengths[i] = 4
		default:
			lengths[i] = 8
		}
	}
	// Partial Fisher-Yates for opcodes, full Fisher-Yates for operand classes.
	for i := range isa.code {
		j := i + r.below(256-i)
		opcodes[i], opcodes[j] = opcodes[j], opcodes[i]
	}
	for i := len(lengths) - 1; i > 0; i-- {
		j := r.below(i + 1)
		lengths[i], lengths[j] = lengths[j], lengths[i]
	}
	for i := range isa.code {
		choices := 1
		if lengths[i] >= 2 {
			choices = 2
		}
		if lengths[i] >= 4 {
			choices = 3
		}
		isa.code[i] = tridentInstruction{opcodes[i], lengths[i], 1 << r.below(choices)}
		isa.reverse[opcodes[i]] = int16(i)
	}
	return isa, nil
}

// Byte-Split Packing consumes six bits per opcode and eight per operand byte.
// Small reservoirs cover all four possible source byte phases without search,
// backtracking, dictionaries, heap allocation, or a bit-at-a-time loop.
type tridentBitsIn struct {
	data []byte
	pos  int
	word uint16
	bits uint
}

func (r *tridentBitsIn) take(n uint) byte {
	if r.bits < n && r.pos < len(r.data) {
		r.word |= uint16(r.data[r.pos]) << r.bits
		r.pos++
		r.bits += 8
	}
	v := byte(r.word & ((1 << n) - 1))
	r.word >>= n
	if r.bits >= n {
		r.bits -= n
	} else {
		r.bits = 0 // Canonical zero extension in the final instruction only.
	}
	return v
}

func (isa *tridentISA) pack(dst, raw []byte) ([]byte, error) {
	if len(raw) < tridentOverhead+1 || len(raw) > tridentRawMax || len(dst) < tridentWireMax {
		return nil, errTridentProgram
	}
	var source [tridentRawMax + 2]byte
	// Keep the random nonce first: a fixed length prefix at stream offset zero
	// would unnecessarily restrict every program's first opcode to 0, 1 or 2.
	copy(source[:tridentNonce], raw[:tridentNonce])
	binary.BigEndian.PutUint16(source[tridentNonce:tridentNonce+2], uint16(len(raw)))
	copy(source[tridentNonce+2:], raw[tridentNonce:])
	r := tridentBitsIn{data: source[:2+len(raw)]}
	pos := 0
	for r.pos < len(r.data) || r.bits > 0 {
		ins := isa.code[r.take(6)]
		dst[pos] = ins.opcode
		pos++
		pad := (-pos) & (int(ins.alignment) - 1)
		clear(dst[pos : pos+pad])
		pos += pad
		for range ins.operands {
			dst[pos] = r.take(8)
			pos++
		}
	}
	return dst[:pos], nil
}

type tridentBitsOut struct {
	data []byte
	pos  int
	word uint16
	bits uint
}

func (w *tridentBitsOut) put(v byte, n uint) {
	w.word |= uint16(v) << w.bits
	w.bits += n
	if w.bits >= 8 {
		w.data[w.pos] = byte(w.word)
		w.pos++
		w.word >>= 8
		w.bits -= 8
	}
}

// Parsing is bounded, allocation-free and happens AFTER the per-source decode
// budget, but BEFORE AEAD. No receiver state is allocated on syntax alone.
func (isa *tridentISA) unpack(dst, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > tridentWireMax || len(dst) < tridentRawMax+12 {
		return nil, errTridentProgram
	}
	w := tridentBitsOut{data: dst}
	expected := 0
	for pos := 0; pos < len(wire); {
		idx := isa.reverse[wire[pos]]
		if idx < 0 {
			return nil, errTridentProgram
		}
		ins := isa.code[idx]
		pos++
		pad := (-pos) & (int(ins.alignment) - 1)
		end := pos + pad + int(ins.operands)
		if end > len(wire) || w.pos > tridentRawMax+2 {
			return nil, errTridentProgram
		}
		for _, b := range wire[pos : pos+pad] {
			if b != 0 {
				return nil, errTridentProgram
			}
		}
		w.put(byte(idx), 6)
		for _, b := range wire[pos+pad : end] {
			w.put(b, 8)
		}
		pos = end
		if expected == 0 && w.pos >= tridentNonce+2 {
			size := int(binary.BigEndian.Uint16(dst[tridentNonce : tridentNonce+2]))
			if size < tridentOverhead+1 || size > tridentRawMax {
				return nil, errTridentProgram
			}
			expected = size + 2
		}
		if expected != 0 && w.pos >= expected {
			if pos != len(wire) || w.word != 0 {
				return nil, errTridentProgram
			}
			for _, b := range dst[expected:w.pos] {
				if b != 0 {
					return nil, errTridentProgram
				}
			}
			copy(dst[2:tridentNonce+2], dst[:tridentNonce])
			return dst[2:expected], nil
		}
	}
	return nil, errTridentProgram
}
