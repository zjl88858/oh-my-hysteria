// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/hex"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestPrestoLitePacingTransitions(t *testing.T) {
	var s prestoLitePacing
	now := time.Unix(10, 0)
	full := bytes.Repeat([]byte{0x40}, 1024)
	long := bytes.Repeat([]byte{0xc0}, 1200)
	for range 40 {
		require.False(t, s.enter(long, now))
	}
	for range 32 {
		require.False(t, s.enter(full, now))
		now = now.Add(time.Millisecond)
	}
	require.True(t, s.enter(full, now))
	require.False(t, s.keep(81*time.Microsecond))
	require.False(t, s.enter(full[:48], now))
	require.True(t, s.keep(80*time.Microsecond))
	require.False(t, s.keep(time.Microsecond))
	for range 100 {
		require.True(t, s.enter(full, now))
	}
	require.True(t, s.keep(2500*time.Microsecond))
	require.False(t, s.keep(time.Microsecond))
	now = now.Add(41 * time.Millisecond)
	require.False(t, s.enter(full, now))
	require.False(t, s.enter(long, now))
	for range 32 {
		require.False(t, s.enter(full, now))
	}
}

func TestPrestoLiteFullStreamGrammar(t *testing.T) {
	type sample struct {
		lengths []int
		stats   PrestoStats
	}
	run := func(v prestoVariant) sample {
		raw := new(blinkTestConn)
		c, err := v.newPrestoConn(raw, PrestoOptions{Password: prestoTestPassword})
		require.NoError(t, err)
		defer c.Close()
		ap, _, _ := blinkAddress(blinkServerAddr)
		s, err := c.sender(ap, time.Now())
		require.NoError(t, err)
		s.grammar = newPrestoGrammar(c.genome, [32]byte{71, 8, 23})
		full := bytes.Repeat([]byte{0x40}, 1200)
		long := bytes.Repeat([]byte{0xc0}, 1200)
		write := func(b []byte) {
			n, err := c.WriteTo(b, blinkServerAddr)
			require.NoError(t, err)
			require.Equal(t, len(b), n)
		}
		for range 50 {
			write(long)
			write(full[:64])
		}
		require.Zero(t, c.PrestoStats().LiteSkippedPauses)
		for i := range 400 {
			write(full)
			if i%17 == 0 {
				write(full[:64])
			}
		}
		r := sample{stats: c.PrestoStats()}
		for _, w := range raw.output {
			r.lengths = append(r.lengths, len(w))
		}
		return r
	}
	a, b := run(prestoStandard), run(prestoLite)
	require.Equal(t, a.lengths, b.lengths)
	require.Equal(t, a.stats.PaddingBytes, b.stats.PaddingBytes)
	require.Positive(t, b.stats.FragmentedMessages)
	require.Positive(t, b.stats.BurstPauses)
	require.Positive(t, b.stats.LiteSkippedPauses)
	require.Equal(t, a.stats.BurstPauses, b.stats.BurstPauses+b.stats.LiteSkippedPauses)
	require.Zero(t, a.stats.LiteSkippedPauses)
}

func TestPrestoLiteCreditOnlyAfterCompleteDelivery(t *testing.T) {
	raw := new(blinkTestConn)
	c, err := prestoLite.newPrestoConn(raw, PrestoOptions{Password: prestoTestPassword, Server: true})
	require.NoError(t, err)
	defer c.Close()
	tx, _, err := prestoLite.prestoCiphers(prestoTestPassword, false)
	require.NoError(t, err)
	full := bytes.Repeat([]byte{0x40}, 1200)
	born := uint64(time.Now().Unix())
	frames := func(id uint64, data []byte) [][]byte {
		h := prestoTestHeader()
		h.born = born
		h.message, h.total, h.size = id, uint16(len(data)), uint16(len(data)/2)
		first := prestoTestFrame(tx, h, data[:h.size], 0)
		h.index, h.offset = 1, h.size
		return [][]byte{first, prestoTestFrame(tx, h, data[h.offset:], 0)}
	}
	add := func(addr net.Addr, wire ...[]byte) {
		for _, w := range wire {
			raw.input = append(raw.input, blinkTestPacket{w, addr})
		}
	}
	read := func(want []byte) {
		var out [1200]byte
		n, _, err := c.ReadFrom(out[:])
		if want == nil {
			require.ErrorIs(t, err, io.EOF)
		} else {
			require.NoError(t, err)
			require.Equal(t, want, out[:n])
		}
	}
	add(blinkClientAddr, frames(0, full)...)
	read(full)
	ap, _, _ := blinkAddress(blinkClientAddr)
	credit := &c.routes[ap].credit
	require.Zero(t, credit.left, "first route")
	w := frames(1, full)
	add(blinkClientAddr, w[1], w[1])
	read(nil)
	require.Zero(t, credit.left, "incomplete/duplicate")
	add(blinkClientAddr, w[0])
	read(full)
	require.Equal(t, 2, credit.left)
	add(&net.UDPAddr{IP: blinkClientAddr.IP, Port: blinkClientAddr.Port + 1}, w...)
	read(nil)
	require.Equal(t, 2, credit.left, "same IP, other port")
	bad := bytes.Clone(w[0])
	bad[len(bad)-1] ^= 1
	add(blinkClientAddr, bad)
	read(nil)
	require.Equal(t, 1, credit.left, "debit is not authentication")
	add(blinkClientAddr, w...)
	read(nil)
	require.Zero(t, credit.left, "replay cannot earn credit")
	add(blinkClientAddr, frames(2, full[:64])...)
	read(full[:64])
	long := bytes.Repeat([]byte{0xc0}, 1200)
	add(blinkClientAddr, frames(3, long)...)
	read(long)
	add(blinkClientAddr, frames(4, full)...)
	_, _, err = c.ReadFrom(make([]byte, 8))
	require.ErrorIs(t, err, io.ErrShortBuffer)
	require.Zero(t, credit.left)
	require.EqualValues(t, 2, c.PrestoStats().LiteCreditUses)
}

func TestPrestoLiteBudgetIsolation(t *testing.T) {
	c, err := prestoLite.newPrestoConn(new(blinkTestConn), PrestoOptions{Password: prestoTestPassword, Server: true})
	require.NoError(t, err)
	defer c.Close()
	ap, src, _ := blinkAddress(blinkClientAddr)
	other := netip.AddrPortFrom(ap.Addr(), ap.Port()+1)
	now := time.Unix(500, 0)
	p := &prestoPeer{addr: ap, source: src, used: now}
	c.routes[ap] = p
	p.credit.earn(now, 1000)
	for range 2048 {
		require.True(t, c.verifyBudget(other, src, now))
	}
	require.False(t, c.verifyBudget(other, src, now))
	require.Equal(t, 256, p.credit.left)
	before := c.verify.tokens
	for range 256 {
		require.True(t, c.verifyBudget(ap, src, now))
	}
	require.Equal(t, before-256, c.verify.tokens)
	p.credit.earn(now, 4)
	require.False(t, c.verifyBudget(ap, src, now), "extra shard capped even with earned credit")
	now = now.Add(time.Millisecond)
	require.True(t, c.verifyBudget(ap, src, now))
	require.Equal(t, 3, p.credit.left)
	now = now.Add(250 * time.Millisecond)
	uses := c.stats.LiteCreditUses
	require.True(t, c.verifyBudget(ap, src, now), "ordinary bucket refilled")
	require.Equal(t, uses, c.stats.LiteCreditUses, "expired private credit was not used")
	p.credit.earn(now, 2)
	require.Equal(t, 2, p.credit.left)
	for c.verify.allow(now, 32768, 4096) {
	}
	require.False(t, c.verifyBudget(ap, src, now), "global ceiling")
	require.Equal(t, 2, p.credit.left)
}

func TestLiteModeAuthentication(t *testing.T) {
	type mode struct {
		name string
		v    prestoVariant
		nf   bool
	}
	modes := []mode{{"presto", prestoStandard, false}, {"prestolite", prestoLite, false},
		{"netfront", prestoStandard, true}, {"netfrontlite", prestoLite, true}}
	opts := NetFrontOptions{prestoTestPassword, []int{31011, 31012}}
	key := func(m mode, server bool) []byte {
		if !m.nf {
			return prestoTestPassword
		}
		profile, err := m.v.compileNetfront(opts, server)
		require.NoError(t, err)
		return profile.prestoKey
	}
	for _, server := range []bool{false, true} {
		for _, from := range modes {
			tx, _, err := from.v.prestoCiphers(key(from, server), server)
			require.NoError(t, err)
			h := prestoTestHeader()
			h.count, h.size, h.total = 1, 1, 1
			wire := prestoTestFrame(tx, h, []byte{7}, 9)
			for _, to := range modes {
				raw := &blinkTestConn{input: []blinkTestPacket{{bytes.Clone(wire), blinkClientAddr}}}
				c, err := to.v.newPrestoConn(raw, PrestoOptions{Password: key(to, !server), Server: !server})
				require.NoError(t, err)
				c.remote, _, _ = blinkAddress(blinkClientAddr)
				var out [1]byte
				_, _, err = c.ReadFrom(out[:])
				if from == to {
					require.NoError(t, err)
					require.Equal(t, byte(7), out[0])
				} else {
					require.ErrorIs(t, err, io.EOF, "%s → %s", from.name, to.name)
					require.EqualValues(t, 1, c.PrestoStats().AuthDrops)
					require.Empty(t, c.peers)
				}
				require.NoError(t, c.Close())
			}
		}
		base, e := prestoStandard.compileNetfront(opts, server)
		require.NoError(t, e)
		lite, e := prestoLite.compileNetfront(opts, server)
		require.NoError(t, e)
		require.Equal(t, base.lanes, lite.lanes)
		require.Equal(t, base.seed, lite.seed)
		for _, v := range []prestoVariant{prestoStandard, prestoLite} {
			p, e := v.compileNetfront(opts, !server)
			require.NoError(t, e)
			a := netfrontAction{lane: 2, wire: 120, frame: netfrontFrame{kind: nfProbe, session: [16]byte{1}, seq: 1}}
			for other, rx := range map[prestoVariant]netfrontProfile{prestoStandard: base, prestoLite: lite} {
				_, ok := openNetfront(a.seal(make([]byte, 384), p.tx, 2), rx.rx, 2, 2)
				require.Equal(t, v == other, ok, "side-lane mode must also match")
			}
		}
	}
}

// Independent vectors: tests/servo_reference.py's HKDF and HChaCha20 with
// IETF ChaCha20-Poly1305; nonce and SID count upwards from zero. These pin the
// new wire key labels even if both Go endpoints change in the same build.
func TestLiteWireVectors(t *testing.T) {
	nonce := make([]byte, 24)
	for i := range nonce {
		nonce[i] = byte(i)
	}
	opts := NetFrontOptions{prestoTestPassword, []int{31011, 31012, 31013}}
	nf, err := prestoLite.compileNetfront(opts, true)
	require.NoError(t, err)
	for _, tc := range []struct {
		key    []byte
		server bool
		box    string
	}{
		{prestoTestPassword, true, "f9a9a94e7056e3d1bf8569e9efdbaec8e20f425259e064ee1d8b6fcd2e8123a494a7db730e0a94430cabc53f6ae738c2681b1bbb36f6a6261becc6ccf2"},
		{nf.prestoKey, false, "95d6c590b716c58b8774d242485498396e35ef29945d34fd46d0178548b67c903c564036d7cb61f42d330adac0c930977ce378e00f3ff76a5e6da9d52d"},
	} {
		_, rx, err := prestoLite.prestoCiphers(tc.key, tc.server)
		require.NoError(t, err)
		box, err := hex.DecodeString(tc.box)
		require.NoError(t, err)
		plain, err := rx.Open(nil, nonce, box, nil)
		require.NoError(t, err)
		h, body, err := decodePrestoHeader(plain)
		require.NoError(t, err)
		require.EqualValues(t, 42, h.message)
		require.Equal(t, []byte("X"), body)
	}
	side, err := hex.DecodeString("ad9c496d28a608d483ba323cf5f6252b7f4753c21400261045a26c21b4839c1c4df8754b52a4983c1d6ed777ee56aff7fe3871c6b3fbfbfb9ce6e4")
	require.NoError(t, err)
	f, ok := openNetfront(append(nonce, side...), nf.rx, 3, 2)
	require.True(t, ok)
	require.Equal(t, nfProbe, f.kind)
	require.EqualValues(t, 3, f.seq)
}
