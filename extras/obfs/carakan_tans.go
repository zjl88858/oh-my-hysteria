// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"

	"golang.org/x/crypto/chacha20"
)

const (
	carakanTableLog = 14
	carakanStates   = 1 << carakanTableLog
	carakanWireMax  = 1232
	carakanRawMax   = 684
	carakanTailMax  = 32
)

var errCarakanShape = errors.New("carakan: invalid or noncanonical shaped stream")

type carakanRow struct {
	base         uint16
	symbol, bits uint8
}

// Each symbol's encoder rows are concatenated in increasing j order. There
// are L decoder rows and L encoder entries, not a 256*L search table.
type carakanTANS struct {
	rows                                    [carakanStates]carakanRow
	encode                                  [carakanStates]uint16
	freq                                    [256]uint16
	start                                   [256]int
	finish                                  [carakanStates]uint16
	distance                                [carakanStates]uint16
	target, entropy                         float64
	code, minBits, maxTail, rawMax, partMax int
	interleaveInner, interleaveOuter        [64]byte
}

func carakanEntropyCode(target *float64) (int, error) {
	h := 4.0
	if target != nil {
		h = *target
	}
	if math.IsNaN(h) || math.IsInf(h, 0) || h < 1 || h > 7.5 || math.Abs(h*100-math.Round(h*100)) > 1e-8 {
		return 0, errors.New("carakan: targetEntropy must be 1.00..7.50 bits/byte in steps of 0.01")
	}
	return int(math.Round(h * 100)), nil
}

func carakanDerive(password []byte, domain string, size int) ([]byte, error) {
	if len(password) < 32 || len(password) > 1024 {
		return nil, errors.New("carakan: password must contain 32..1024 bytes; use a random secret")
	}
	return hkdf.Key(sha256.New, password, []byte("oh-my-hysteria/carakan/v3"), domain, size)
}

// Frozen v2 compiler primitive; changing another obfuscator cannot change this
// wire dialect. Rejection sampling is unbiased for every n<=16384.
type carakanCompiler struct{ stream *chacha20.Cipher }

func (r carakanCompiler) below(n int) int {
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

// H = m + h2(q): split each of 2^m equiprobable classes into two
// homophones. Quantize q to an integer frequency, choosing the nearest H.
// This is a target marginal spectrum, NOT an exact finite-packet histogram.
func compileCarakanTANS(password []byte, target *float64) (*carakanTANS, error) {
	code, err := carakanEntropyCode(target)
	if err != nil {
		return nil, err
	}
	seed, err := carakanDerive(password, fmt.Sprintf("spectrum/%d", code), 32)
	if err != nil {
		return nil, err
	}
	t := &carakanTANS{code: code, target: float64(code) / 100, minBits: code / 100}
	interleave, err := carakanDerive(password, fmt.Sprintf("interleave/%d", code), 32)
	if err != nil {
		return nil, err
	}
	for i := range t.interleaveInner {
		t.interleaveInner[i], t.interleaveOuter[i] = 0x36, 0x5c
		if i < len(interleave) {
			t.interleaveInner[i] ^= interleave[i]
			t.interleaveOuter[i] ^= interleave[i]
		}
	}
	classes := 1 << t.minBits
	unit := carakanStates / classes
	binaryEntropy := func(n int) float64 {
		if n == 0 {
			return 0
		}
		q := float64(n) / float64(unit)
		return -q*math.Log2(q) - (1-q)*math.Log2(1-q)
	}
	minor, difference := 0, math.Inf(1)
	for n := 0; n <= unit/2; n++ {
		d := math.Abs(float64(t.minBits) + binaryEntropy(n) - t.target)
		if d < difference {
			minor, difference = n, d
		}
	}
	stream, err := chacha20.NewUnauthenticatedCipher(seed, make([]byte, chacha20.NonceSize))
	if err != nil {
		return nil, err
	}
	r := carakanCompiler{stream: stream}
	var symbols [256]byte
	for i := range symbols {
		symbols[i] = byte(i)
	}
	for i := 255; i > 0; i-- {
		j := r.below(i + 1)
		symbols[i], symbols[j] = symbols[j], symbols[i]
	}
	for i := 0; i < classes; i++ {
		t.freq[symbols[i]] = uint16(unit - minor)
		if minor != 0 {
			t.freq[symbols[classes+i]] = uint16(minor)
		}
	}
	// max(p)<=2^-m guarantees bits>=m>=1, including all termination paths.
	cumulative := 0
	for s, f := range t.freq {
		t.start[s] = cumulative
		cumulative += int(f)
		if f != 0 {
			p := float64(f) / carakanStates
			t.entropy -= p * math.Log2(p)
		}
	}
	// A contiguous spread badly biases the stationary spectrum; a conventional
	// odd-step spread can have disconnected components even for binary uniform
	// input. Keyed unbiased spreads are admitted ONLY after full reachability
	// validation. This is bounded deterministic table construction, not payload
	// rejection sampling, password selection, or a network fallback.
	for attempt := 0; attempt < 16; attempt++ {
		position := 0
		for s, f := range t.freq {
			for j := int(f); j < 2*int(f); j++ {
				n := uint8(carakanTableLog - (bits.Len(uint(j)) - 1))
				t.rows[position] = carakanRow{symbol: byte(s), bits: n, base: uint16((j << n) - carakanStates)}
				position++
			}
		}
		for i := carakanStates - 1; i > 0; i-- {
			j := r.below(i + 1)
			t.rows[i], t.rows[j] = t.rows[j], t.rows[i]
		}
		for i := range t.rows {
			row := &t.rows[i]
			s := row.symbol
			j := (int(row.base) + carakanStates) >> row.bits
			t.encode[t.start[s]+j-int(t.freq[s])] = uint16(i)
			if int(row.bits) < t.minBits {
				return nil, errors.New("carakan: invalid tANS normalization")
			}
		}
		// Reverse BFS constructs a canonical shortest path from EVERY state to
		// terminal state 0. The path is shaped symbols, never a raw state trailer.
		for i := range t.distance {
			t.distance[i] = math.MaxUint16
		}
		t.maxTail = 0
		t.distance[0] = 0
		queue := make([]uint16, 1, carakanStates)
		for head := 0; head < len(queue); head++ {
			y := queue[head]
			for s, f := range t.freq {
				if f == 0 {
					continue
				}
				x, _, _ := t.inverse(byte(s), y)
				if t.distance[x] == math.MaxUint16 {
					t.distance[x] = t.distance[y] + 1
					t.finish[x] = y
					t.maxTail = max(t.maxTail, int(t.distance[x]))
					queue = append(queue, x)
				}
			}
		}
		if len(queue) == carakanStates && t.maxTail <= carakanTailMax {
			break
		}
		if attempt == 15 {
			return nil, errors.New("carakan: bounded tANS graph compilation exhausted")
		}
	}
	// Conservative, data-independent bound; never attempt/retry a fit based
	// on ciphertext. Initial-state bits only make this bound more conservative.
	t.rawMax = min(carakanRawMax, (carakanWireMax-t.maxTail)*t.minBits/8-2)
	t.partMax = t.rawMax - carakanOverhead
	if t.partMax < 40 {
		return nil, errors.New("carakan: insufficient bounded fragment capacity")
	}
	return t, nil
}

func (t *carakanTANS) inverse(symbol byte, state uint16) (uint16, uint16, uint8) {
	f := int(t.freq[symbol])
	n := carakanTableLog - (bits.Len(uint(f)) - 1)
	x := int(state) + carakanStates
	if x>>n < f {
		n--
	}
	j := x >> n
	return t.encode[t.start[symbol]+j-f], uint16(x & ((1 << n) - 1)), uint8(n)
}

// Source is whitened_nonce || uint16_be(raw length) || ciphertext, LSB-first.
// Public reversible whitening avoids repeating the structured session/counter
// nonce at the start of every shaped stream. It adds NO encryption strength.
// The receiver runs the tANS ENCODER backwards from state 0 after derotation.
func (t *carakanTANS) pack(dst, raw []byte) ([]byte, error) {
	if len(raw) < carakanOverhead+1 || len(raw) > t.rawMax || len(dst) < carakanWireMax {
		return nil, errCarakanShape
	}
	var source [carakanRawMax + 2]byte
	mask := sha256.Sum256(raw[carakanNonce:])
	for i := range carakanNonce {
		source[i] = raw[i] ^ mask[i]
	}
	binary.BigEndian.PutUint16(source[carakanNonce:carakanNonce+2], uint16(len(raw)))
	copy(source[carakanNonce+2:], raw[carakanNonce:])
	r := carakanBits{data: source[:len(raw)+2]}
	state := uint16(r.take(carakanTableLog))
	pos := 0
	for r.consumed < len(r.data)*8 {
		row := t.rows[state]
		dst[pos] = row.symbol
		pos++
		state = row.base + uint16(r.take(uint(row.bits)))
	}
	for state != 0 {
		dst[pos] = t.rows[state].symbol
		pos++
		state = t.finish[state]
	}
	out := dst[:pos]
	shift := t.rotation(out)
	var rotated [carakanWireMax]byte
	copy(rotated[:], out[shift:])
	copy(rotated[pos-shift:], out[:shift])
	copy(out, rotated[:pos])
	return out, nil
}

// A keyed histogram determines a cyclic rotation and is itself rotation
// invariant. Receiver inversion is unique, linear and needs no transmitted
// offset or AEAD trials. This scatters, rather than removes, the terminal seam.
func (t *carakanTANS) rotation(wire []byte) int {
	var histogram [256]uint16
	for _, b := range wire {
		histogram[b]++
	}
	// Allocation-free HMAC-SHA256 with the precomputed 32-byte-key pads.
	var inner [64 + 2 + 512]byte
	copy(inner[:64], t.interleaveInner[:])
	binary.BigEndian.PutUint16(inner[64:66], uint16(len(wire)))
	for i, n := range histogram {
		binary.BigEndian.PutUint16(inner[66+i*2:68+i*2], n)
	}
	digest := sha256.Sum256(inner[:])
	var outer [96]byte
	copy(outer[:64], t.interleaveOuter[:])
	copy(outer[64:], digest[:])
	mac := sha256.Sum256(outer[:])
	// At most 1232/2^64 modulo bias; not claimed to be exact uniform sampling.
	return int(binary.BigEndian.Uint64(mac[:8]) % uint64(len(wire)))
}

type carakanBits struct {
	data     []byte
	consumed int
}

func (r *carakanBits) take(n uint) uint32 {
	// At most 14 bits, at most three source bytes. Final transition zero extends.
	pos, shift := r.consumed/8, uint(r.consumed%8)
	var word uint32
	for i := 0; i < 3 && pos+i < len(r.data); i++ {
		word |= uint32(r.data[pos+i]) << (8 * i)
	}
	r.consumed += int(n)
	return (word >> shift) & ((1 << n) - 1)
}

func (t *carakanTANS) unpack(dst, wire []byte) ([]byte, error) {
	if len(wire) == 0 || len(wire) > carakanWireMax || len(dst) < carakanRawMax+2 {
		return nil, errCarakanShape
	}
	var chunks [carakanWireMax]uint16
	var widths [carakanWireMax]uint8
	var ordered [carakanWireMax]byte
	shift := t.rotation(wire)
	copy(ordered[:shift], wire[len(wire)-shift:])
	copy(ordered[shift:], wire[:len(wire)-shift])
	state, total := uint16(0), carakanTableLog
	for i := len(wire) - 1; i >= 0; i-- {
		if t.freq[ordered[i]] == 0 {
			return nil, errCarakanShape
		}
		var n uint8
		state, chunks[i], n = t.inverse(ordered[i], state)
		widths[i] = n
		total += int(n)
		if total > (t.rawMax+2)*8+carakanTableLog*(t.maxTail+1) {
			return nil, errCarakanShape
		}
	}
	// Reassemble in source order using an integer reservoir, not reverse bits.
	var source [carakanRawMax + 2 + (carakanTailMax+1)*carakanTableLog/8 + 1]byte
	word, available, pos := uint32(state), uint(carakanTableLog), 0
	flush := func() bool {
		for available >= 8 {
			if pos >= len(source) {
				return false
			}
			source[pos] = byte(word)
			pos++
			word >>= 8
			available -= 8
		}
		return true
	}
	if !flush() {
		return nil, errCarakanShape
	}
	for i := range wire {
		word |= uint32(chunks[i]) << available
		available += uint(widths[i])
		if !flush() {
			return nil, errCarakanShape
		}
	}
	if pos < carakanNonce+2 {
		return nil, errCarakanShape
	}
	size := int(binary.BigEndian.Uint16(source[carakanNonce : carakanNonce+2]))
	if size < carakanOverhead+1 || size > t.rawMax || pos < size+2 {
		return nil, errCarakanShape
	}
	copy(dst[carakanNonce:size], source[carakanNonce+2:size+2])
	mask := sha256.Sum256(dst[carakanNonce:size])
	for i := range carakanNonce {
		dst[i] = source[i] ^ mask[i]
	}
	// Reject noncanonical endings/padding before AEAD or state allocation.
	// An edit/truncation that is another canonical stream must still pass AEAD.
	var canonical [carakanWireMax]byte
	encoded, err := t.pack(canonical[:], dst[:size])
	if err != nil || !bytes.Equal(encoded, wire) {
		return nil, errCarakanShape
	}
	return dst[:size], nil
}
