// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/chacha20poly1305"
)

var servoTestPassword = []byte("servo-test-only-32-byte-secret!!")

func servoTestCipher(t testing.TB, direction byte) *servoCipher {
	t.Helper()
	c, err := newServoCipher(servoTestPassword, direction)
	require.NoError(t, err)
	return c
}

func servoTestFixture(name string, direction byte) servoFrame {
	f := servoFrame{born: 1700000000, count: 1}
	for i := range f.session {
		f.session[i] = byte(i)
		if direction == 1 {
			f.session[i] = byte(255 - i)
		}
	}
	f.records[0] = servoRecord{message: 1, total: 1, data: []byte{0xa5}}
	if direction == 1 {
		f.counter = 1 << 63
	}
	if name == "max" {
		f.count, f.counter = 8, math.MaxUint64
		for i := range f.count {
			n := 137
			if i == 7 {
				n = 141
			}
			data := make([]byte, n)
			for j := range data {
				data[j] = byte(i*31 + j)
			}
			f.records[i] = servoRecord{message: 0x10203040 + uint32(i), total: uint16(n + 3), offset: 3, data: data}
		}
	}
	return f
}

// Deliberately independent plaintext serializer for authenticated-invalid tests.
func servoTestPlain(f servoFrame) []byte {
	var body, out bytes.Buffer
	for i := range f.count {
		r := f.records[i]
		_ = binary.Write(&body, binary.BigEndian, r.message)
		_ = binary.Write(&body, binary.BigEndian, r.total)
		_ = binary.Write(&body, binary.BigEndian, r.offset)
		_ = binary.Write(&body, binary.BigEndian, uint16(len(r.data)))
		body.Write(r.data)
	}
	_ = binary.Write(&out, binary.BigEndian, f.born)
	out.WriteByte(byte(f.count))
	out.WriteByte(0)
	_ = binary.Write(&out, binary.BigEndian, uint16(body.Len()))
	out.Write(body.Bytes())
	return out.Bytes()
}

func servoTestSealPlain(c *servoCipher, f servoFrame, plain []byte) []byte {
	nonce := append(bytes.Clone(f.session[:]), make([]byte, 8)...)
	binary.BigEndian.PutUint64(nonce[16:], f.counter)
	w := 40 + len(plain)
	ct := c.aead.Seal(nil, nonce, plain, servoContext("frame", c.direction, w))
	mask := c.mask(w, ct[len(ct)-16:])
	for i := range nonce {
		nonce[i] ^= mask[i]
	}
	return append(nonce, ct...)
}

func TestServoIndependentGolden(t *testing.T) {
	var vectors struct {
		Domain   string `json:"domain"`
		Password string `json:"password_hex"`
		Seed     string `json:"shape_seed_hex"`
		Profiles []struct {
			Direction  byte   `json:"direction"`
			Serialized string `json:"serialized_hex"`
			Capacities []int  `json:"capacities"`
		} `json:"profiles"`
		Frames []struct {
			Fixture   string `json:"fixture"`
			Direction byte   `json:"direction"`
			Session   string `json:"session_hex"`
			Counter   string `json:"counter"`
			Born      uint64 `json:"born"`
			WireSize  int    `json:"wire_length"`
			WireHash  string `json:"wire_sha256"`
			PlainHash string `json:"plain_sha256"`
			AD        string `json:"ad_hex"`
			Mask      string `json:"mask_hex"`
			Protected string `json:"protected_nonce_hex"`
			Tag       string `json:"tag_hex"`
			Wire      string `json:"wire_hex"`
		} `json:"frames"`
	}
	data, err := os.ReadFile("../../tests/vectors/servo-v1.json")
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, &vectors))
	require.Equal(t, servoDomain, vectors.Domain)
	require.Equal(t, hex.EncodeToString(servoTestPassword), vectors.Password)
	seed, err := hex.DecodeString(vectors.Seed)
	require.NoError(t, err)
	for _, v := range vectors.Profiles {
		p, err := compileServoProfile(servoTestPassword, v.Direction)
		require.NoError(t, err)
		require.Equal(t, v.Serialized, hex.EncodeToString(p.bytes()))
		s, err := newServoStream(seed)
		require.NoError(t, err)
		for _, want := range v.Capacities {
			got, err := p.sample(s)
			require.NoError(t, err)
			require.Equal(t, want, got)
		}
	}
	for _, v := range vectors.Frames {
		t.Run(fmt.Sprintf("%s/%d", v.Fixture, v.Direction), func(t *testing.T) {
			c := servoTestCipher(t, v.Direction)
			f := servoTestFixture(v.Fixture, v.Direction)
			require.Equal(t, v.Session, hex.EncodeToString(f.session[:]))
			require.Equal(t, v.Counter, strconv.FormatUint(f.counter, 10))
			require.Equal(t, v.Born, f.born)
			plainHash := sha256.Sum256(servoTestPlain(f))
			require.Equal(t, v.PlainHash, hex.EncodeToString(plainHash[:]))
			wire, err := c.seal(&f)
			require.NoError(t, err)
			require.Len(t, wire, v.WireSize)
			hash := sha256.Sum256(wire)
			require.Equal(t, v.WireHash, hex.EncodeToString(hash[:]))
			require.Equal(t, v.AD, hex.EncodeToString(servoContext("frame", v.Direction, len(wire))))
			require.Equal(t, v.Mask, hex.EncodeToString(c.mask(len(wire), wire[len(wire)-16:])))
			require.Equal(t, v.Protected, hex.EncodeToString(wire[:24]))
			require.Equal(t, v.Tag, hex.EncodeToString(wire[len(wire)-16:]))
			if v.Wire != "" {
				require.Equal(t, v.Wire, hex.EncodeToString(wire))
			}
			var scratch [servoWireMax]byte
			got, err := c.open(wire, &scratch)
			require.NoError(t, err)
			require.Equal(t, f, got)
		})
	}
}

func TestServoProfileBoundsAndIndependentTracks(t *testing.T) {
	for i := range 64 {
		password := []byte(fmt.Sprintf("servo-profile-public-test-%032d", i))
		for direction := range byte(2) {
			p, err := compileServoProfile(password, direction)
			require.NoError(t, err)
			again, err := compileServoProfile(password, direction)
			require.NoError(t, err)
			require.Equal(t, p, again)
			require.GreaterOrEqual(t, p.count, 6)
			require.LessOrEqual(t, p.count, 12)
			require.GreaterOrEqual(t, p.wait, 200*time.Microsecond)
			require.LessOrEqual(t, p.wait, 500*time.Microsecond)
			for j := range p.count {
				require.GreaterOrEqual(t, p.centers[j], 640)
				require.LessOrEqual(t, p.centers[j], 1100)
				require.Positive(t, p.weights[j])
			}
			s1, err := newServoStream(bytes.Repeat([]byte{1}, 32))
			require.NoError(t, err)
			s2, err := newServoStream(bytes.Repeat([]byte{2}, 32))
			require.NoError(t, err)
			var first, second []int
			for range 64 {
				for _, s := range []*servoStream{s1, s2} {
					x, err := p.sample(s)
					require.NoError(t, err)
					require.GreaterOrEqual(t, x, 640)
					require.LessOrEqual(t, x, 1100)
					if s == s1 {
						first = append(first, x)
					} else {
						second = append(second, x)
					}
				}
			}
			require.NotEqual(t, first, second)
		}
	}
	for _, size := range []int{0, 31, 1025} {
		_, err := newServoCipher(make([]byte, size), 0)
		require.Error(t, err)
		_, err = compileServoProfile(make([]byte, size), 0)
		require.Error(t, err)
	}
	for _, size := range []int{32, 1024} {
		_, err := newServoCipher(make([]byte, size), 0)
		require.NoError(t, err)
	}
	_, err := newServoCipher(servoTestPassword, 2)
	require.Error(t, err)
	_, err = compileServoProfile(servoTestPassword, 2)
	require.Error(t, err)
	_, err = newServoStream([]byte{1})
	require.Error(t, err)
	s, err := newServoStream(make([]byte, 32))
	require.NoError(t, err)
	_, err = s.below(0)
	require.Error(t, err)
	_, err = s.below(65537)
	require.Error(t, err)
}

func TestServoCodecRoundTripLengths(t *testing.T) {
	for direction := range byte(2) {
		c := servoTestCipher(t, direction)
		for n := 1; n <= servoDataMax; n++ {
			f := servoTestFixture("tiny", direction)
			f.counter = uint64(n)
			f.records[0] = servoRecord{message: uint32(n), total: 1200, offset: uint16((1200 - n) / 2), data: bytes.Repeat([]byte{byte(n)}, n)}
			wire, err := c.seal(&f)
			require.NoError(t, err)
			require.Len(t, wire, servoOverhead+servoDescriptor+n)
			var scratch [servoWireMax]byte
			got, err := c.open(wire, &scratch)
			require.NoError(t, err)
			require.Equal(t, f, got)
		}
	}
}

func TestServoAuthenticatedInvalidPlaintexts(t *testing.T) {
	c := servoTestCipher(t, 0)
	f := servoTestFixture("tiny", 0)
	base := servoTestPlain(f)
	cases := map[string]func([]byte) []byte{
		"born-zero":       func(b []byte) []byte { clear(b[:8]); return b },
		"born-overflow":   func(b []byte) []byte { binary.BigEndian.PutUint64(b[:8], math.MaxUint64); return b },
		"flags":           func(b []byte) []byte { b[9] = 1; return b },
		"count-zero":      func(b []byte) []byte { b[8] = 0; return b },
		"count-nine":      func(b []byte) []byte { b[8] = 9; return b },
		"count-extra":     func(b []byte) []byte { b[8] = 2; return b },
		"used-short":      func(b []byte) []byte { b[11]--; return b },
		"used-long":       func(b []byte) []byte { b[11]++; return b },
		"message-zero":    func(b []byte) []byte { clear(b[12:16]); return b },
		"total-zero":      func(b []byte) []byte { clear(b[16:18]); return b },
		"total-large":     func(b []byte) []byte { binary.BigEndian.PutUint16(b[16:18], 1201); return b },
		"offset-total":    func(b []byte) []byte { b[19] = 1; return b },
		"offset-overflow": func(b []byte) []byte { binary.BigEndian.PutUint16(b[18:20], 65535); return b },
		"length-zero":     func(b []byte) []byte { b[21] = 0; return b },
		"length-large":    func(b []byte) []byte { binary.BigEndian.PutUint16(b[20:22], 65535); return b },
		"trailing": func(b []byte) []byte {
			b = append(b, 0)
			binary.BigEndian.PutUint16(b[10:12], uint16(len(b)-12))
			return b
		},
		"duplicate-message": func(b []byte) []byte {
			b = append(b, b[12:]...)
			b[8] = 2
			binary.BigEndian.PutUint16(b[10:12], uint16(len(b)-12))
			return b
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			plain := mutate(bytes.Clone(base))
			_, err := decodeServoPlain(plain)
			require.ErrorIs(t, err, errServoFrame)
			wire := servoTestSealPlain(c, f, plain)
			var scratch [servoWireMax]byte
			_, err = c.open(wire, &scratch)
			require.ErrorIs(t, err, errServoFrame)
		})
	}
	for n := range len(base) {
		_, err := decodeServoPlain(base[:n])
		require.Error(t, err)
	}
	f.records[0] = servoRecord{message: 1, total: 1200, data: make([]byte, 1101)}
	_, err := c.seal(&f)
	require.ErrorIs(t, err, errServoFrame)
	var scratch [servoWireMax]byte
	_, err = c.open(servoTestSealPlain(c, f, servoTestPlain(f)), &scratch)
	require.ErrorIs(t, err, errServoFrame)
}

func TestServoAuthenticationDomainsAndTamper(t *testing.T) {
	c := servoTestCipher(t, 0)
	f := servoTestFixture("tiny", 0)
	wire, err := c.seal(&f)
	require.NoError(t, err)
	var scratch [servoWireMax]byte
	for i := range wire {
		for bit := range 8 {
			bad := bytes.Clone(wire)
			bad[i] ^= 1 << bit
			_, err := c.open(bad, &scratch)
			require.Error(t, err, "byte=%d bit=%d", i, bit)
		}
	}
	for n := range len(wire) {
		_, err := c.open(wire[:n], &scratch)
		require.Error(t, err)
	}
	_, err = c.open(append(bytes.Clone(wire), 0), &scratch)
	require.Error(t, err)
	_, err = c.open(make([]byte, servoWireMax+1), &scratch)
	require.Error(t, err)
	wrongDir := servoTestCipher(t, 1)
	_, err = wrongDir.open(wire, &scratch)
	require.ErrorIs(t, err, errServoAuth)
	wrongPassword, err := newServoCipher(bytes.Repeat([]byte("!"), 32), 0)
	require.NoError(t, err)
	_, err = wrongPassword.open(wire, &scratch)
	require.ErrorIs(t, err, errServoAuth)
	wrongHP := *c
	wrongHP.hp[0] ^= 1
	_, err = wrongHP.open(wire, &scratch)
	require.ErrorIs(t, err, errServoAuth)
	for _, domain := range []string{"oh-my-hysteria/servo/v2", "oh-my-hysteria/tasman/v1"} {
		key, err := hkdf.Key(sha256.New, servoTestPassword, []byte(domain), "aead/c2s", 32)
		require.NoError(t, err)
		wrong := *c
		wrong.aead, err = chacha20poly1305.NewX(key)
		require.NoError(t, err)
		_, err = wrong.open(wire, &scratch)
		require.ErrorIs(t, err, errServoAuth)
	}
}

func TestServoRawPasswordAndProfileClamping(t *testing.T) {
	// Accept byte length, not rune count; never silently base64-decode input.
	unicode := bytes.Repeat([]byte("密"), 11)
	_, err := compileServoProfile(unicode, 0)
	require.NoError(t, err)
	a, err := servoDerive([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), "profile/c2s")
	require.NoError(t, err)
	b, err := servoDerive(make([]byte, 32), "profile/c2s")
	require.NoError(t, err)
	require.NotEqual(t, a, b)
	for _, center := range []int{640, 1100} {
		p := servoProfile{count: 1, jitter: 16}
		p.centers[0], p.weights[0] = center, 1
		s, err := newServoStream(make([]byte, 32))
		require.NoError(t, err)
		hits := 0
		for range 100 {
			x, err := p.sample(s)
			require.NoError(t, err)
			require.GreaterOrEqual(t, x, 640)
			require.LessOrEqual(t, x, 1100)
			if x == center {
				hits++
			}
		}
		require.Positive(t, hits)
	}
}

func FuzzServoWire(f *testing.F) {
	c := servoTestCipher(f, 0)
	for _, name := range []string{"tiny", "max"} {
		frame := servoTestFixture(name, 0)
		wire, err := c.seal(&frame)
		require.NoError(f, err)
		f.Add(wire)
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		var scratch [servoWireMax]byte
		frame, err := c.open(wire, &scratch)
		if err != nil {
			return
		}
		canonical, err := c.seal(&frame)
		require.NoError(t, err)
		require.Equal(t, wire, canonical)
	})
}

func FuzzServoPlain(f *testing.F) {
	for _, name := range []string{"tiny", "max"} {
		f.Add(servoTestPlain(servoTestFixture(name, 0)))
	}
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, plain []byte) {
		frame, err := decodeServoPlain(plain)
		if err == nil {
			require.Equal(t, plain, servoTestPlain(frame))
		}
	})
}
