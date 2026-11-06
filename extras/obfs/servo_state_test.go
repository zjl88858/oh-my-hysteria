// SPDX-License-Identifier: MIT-0

package obfs

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var (
	servoTestNow  = time.Unix(1700000000, 0)
	servoTestAddr = netip.MustParseAddrPort("192.0.2.1:12345")
)

func servoTestReceiver(t testing.TB) *servoReceiver {
	t.Helper()
	r, err := newServoReceiver(servoTestPassword, 0)
	require.NoError(t, err)
	return r
}

func servoStateFrame(session, counter uint64, records ...servoRecord) servoFrame {
	f := servoFrame{born: uint64(servoTestNow.Unix()), counter: counter, count: len(records)}
	binary.BigEndian.PutUint64(f.session[8:], session)
	copy(f.records[:], records)
	return f
}

func servoFullRecord(id uint32, n int) servoRecord {
	return servoRecord{message: id, total: uint16(n), data: bytes.Repeat([]byte{byte(id)}, n)}
}

func servoTestReceive(t testing.TB, r *servoReceiver, f servoFrame, addr netip.AddrPort, now time.Time) error {
	t.Helper()
	wire, err := r.cipher.seal(&f)
	require.NoError(t, err)
	return r.receive(wire, addr, now)
}

func TestServoPacketAndCompletionWindows(t *testing.T) {
	r := servoTestReceiver(t)
	first := servoRecord{message: 1, total: 1200, data: bytes.Repeat([]byte{1}, 700)}
	last := servoRecord{message: 1, total: 1200, offset: 700, data: bytes.Repeat([]byte{2}, 500)}
	f := servoStateFrame(1, 10, first)
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	p := r.peers[f.session]
	require.True(t, p.packets.seen(10))
	require.False(t, p.done.seen(1), "a first fragment isn't a completed message")
	require.False(t, p.routeReady)
	require.Zero(t, r.queue.Len())
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoReplay)
	// A later complete datagram is delivered without waiting for message 1.
	f = servoStateFrame(1, 12, servoFullRecord(2, 64))
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	require.True(t, p.routeReady)
	var out [1200]byte
	n, addr, err := r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, servoTestAddr, addr)
	require.Equal(t, bytes.Repeat([]byte{2}, 64), out[:n])
	// Same fragment in a fresh packet is harmless, but doesn't refresh TTL.
	f = servoStateFrame(1, 13, first)
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(time.Second)))
	require.Equal(t, uint64(1), r.stats.DuplicateFragments)
	require.Equal(t, servoTestNow.Add(3*time.Second), p.assemblies[1].deadline)
	// Packet and message order are independent, as are their replay windows.
	f = servoStateFrame(1, 11, last)
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(time.Second)))
	n, _, err = r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, append(bytes.Repeat([]byte{1}, 700), bytes.Repeat([]byte{2}, 500)...), out[:n])
	require.True(t, p.done.seen(1))
	require.Empty(t, p.assemblies)
	require.Zero(t, r.assemblyBytes)
	f.counter = 14
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(time.Second)))
	require.Zero(t, r.queue.Len())
	require.Equal(t, uint64(1), r.stats.MessageReplayDrops)
}

func TestServoWholeContainerConflictAtomicity(t *testing.T) {
	for _, kind := range []string{"bytes", "total", "overlap", "third"} {
		t.Run(kind, func(t *testing.T) {
			r := servoTestReceiver(t)
			initial := servoRecord{message: 1, total: 20, data: []byte{1, 2, 3, 4, 5}}
			f := servoStateFrame(1, 0, initial)
			require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
			bad := initial
			switch kind {
			case "bytes":
				bad.data = []byte{5, 4, 3, 2, 1}
			case "total":
				bad.total = 21
			case "overlap":
				bad.offset = 4
			case "third":
				second := initial
				second.offset = 10 // deliberate gap; never complete
				require.NoError(t, servoTestReceive(t, r, servoStateFrame(1, 1, second), servoTestAddr, servoTestNow))
				bad.offset = 15
			}
			valid := servoFullRecord(2, 3)
			f = servoStateFrame(1, 2, valid, bad)
			require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoConflict)
			p := r.peers[f.session]
			require.Zero(t, r.queue.Len(), "earlier valid record must not be delivered")
			require.False(t, p.done.seen(2))
			require.False(t, p.packets.seen(2), "conflict must not consume packet state")
			require.False(t, p.routeReady)
			// Correcting the same counter proves the rejected container didn't commit.
			f = servoStateFrame(1, 2, valid)
			require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
			require.Equal(t, 1, r.queue.Len())
		})
	}
}

func TestServoReverseFragmentsAndScratchOwnership(t *testing.T) {
	r := servoTestReceiver(t)
	last := servoRecord{message: 1, total: 1200, offset: 640, data: bytes.Repeat([]byte{8}, 560)}
	require.NoError(t, servoTestReceive(t, r, servoStateFrame(1, 1, last), servoTestAddr, servoTestNow))
	// Overwrite scratch and input between fragments. Receiver must own its copy.
	clear(last.data)
	clear(r.scratch[:])
	first := servoRecord{message: 1, total: 1200, data: bytes.Repeat([]byte{7}, 640)}
	require.NoError(t, servoTestReceive(t, r, servoStateFrame(1, 0, first), servoTestAddr, servoTestNow))
	clear(first.data)
	clear(r.scratch[:])
	var out [1200]byte
	n, _, err := r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, append(bytes.Repeat([]byte{7}, 640), bytes.Repeat([]byte{8}, 560)...), out[:n])
	// Completed single-record data also cannot alias decoder scratch.
	f := servoStateFrame(1, 2, servoFullRecord(2, 10), servoFullRecord(3, 20))
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	clear(r.scratch[:])
	n, _, err = r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{2}, 10), out[:n])
	n, _, err = r.pop(out[:])
	require.NoError(t, err)
	require.Equal(t, bytes.Repeat([]byte{3}, 20), out[:n])
}

func TestServoSessionBindingFreshnessAndTombstones(t *testing.T) {
	for _, addr := range []netip.AddrPort{
		servoTestAddr, netip.MustParseAddrPort("[2001:db8::1]:12345"),
	} {
		t.Run(addr.String(), func(t *testing.T) {
			r := servoTestReceiver(t)
			f := servoStateFrame(1, 0, servoFullRecord(1, 1))
			require.NoError(t, servoTestReceive(t, r, f, addr, servoTestNow))
			p := r.peers[f.session]
			changed := netip.AddrPortFrom(addr.Addr(), addr.Port()+1)
			f.counter = 1
			require.ErrorIs(t, servoTestReceive(t, r, f, changed, servoTestNow), errServoFresh)
			f.born++
			require.ErrorIs(t, servoTestReceive(t, r, f, addr, servoTestNow), errServoFresh)
			f.born--
			// An active session outlives the initial freshness window.
			require.NoError(t, servoTestReceive(t, r, f, addr, servoTestNow.Add(40*time.Second)))
			r.retire(p, servoTestNow.Add(41*time.Second))
			require.NotNil(t, r.tombstones[f.session])
			require.Zero(t, r.endpoints[addr])
			require.Empty(t, r.peers)
			require.ErrorIs(t, servoTestReceive(t, r, f, addr, servoTestNow.Add(41*time.Second)), errServoFresh)
		})
	}
	r := servoTestReceiver(t)
	f := servoStateFrame(1, 0, servoFullRecord(1, 1))
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	r.retire(r.peers[f.session], servoTestNow.Add(time.Second))
	f.counter++
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(2*time.Second)), errServoReplay)
	r.maintain(servoTestNow.Add(31 * time.Second))
	require.Empty(t, r.tombstones)
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(31*time.Second)), errServoFresh)
	for _, delta := range []int64{-31, 31} {
		f = servoStateFrame(uint64(delta+100), 0, servoFullRecord(1, 1))
		f.born = uint64(servoTestNow.Unix() + delta)
		require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoFresh)
	}
	for _, delta := range []int64{-30, 30} {
		f = servoStateFrame(uint64(delta+100), 0, servoFullRecord(1, 1))
		f.born = uint64(servoTestNow.Unix() + delta)
		require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	}
	r.maintain(servoTestNow.Add(servoSessionTTL))
	require.Empty(t, r.peers)
	require.Empty(t, r.sources)
	require.Empty(t, r.endpoints)
}

func TestServoIndependentExpiryAndOwnQuotaEviction(t *testing.T) {
	r := servoTestReceiver(t)
	partial := servoRecord{message: 1, total: 1200, data: make([]byte, 600)}
	f := servoStateFrame(1, 0, partial)
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	f.counter++
	f.records[0].message = 2
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(time.Second)))
	r.maintain(servoTestNow.Add(3 * time.Second))
	p := r.peers[f.session]
	require.Nil(t, p.assemblies[1])
	require.NotNil(t, p.assemblies[2])
	require.True(t, p.done.seen(1))
	require.False(t, p.done.seen(2))
	require.False(t, p.routeReady)
	f.counter++
	f.records[0].message, f.records[0].offset = 1, 600
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(3*time.Second)))
	require.Nil(t, p.assemblies[1], "expired message must not reopen")
	for i := 3; i <= 131; i++ {
		f.counter++
		f.records[0].message, f.records[0].offset = uint32(i), 0
		require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(3*time.Second)))
	}
	require.Len(t, p.assemblies, servoPerSession)
	require.Nil(t, p.assemblies[2])
	require.Equal(t, uint64(2), r.stats.EvictedAssemblies)
	require.Equal(t, servoPerSession*1200, r.assemblyBytes)
}

func TestServoGlobalAssemblyLimitDoesNotEvictOthers(t *testing.T) {
	r := servoTestReceiver(t)
	for session := 1; session <= 16; session++ {
		addr := netip.MustParseAddrPort(fmt.Sprintf("192.0.2.%d:12345", session))
		for message := 1; message <= servoPerSession; message++ {
			part := servoRecord{message: uint32(message), total: 1200, data: make([]byte, 600)}
			f := servoStateFrame(uint64(session), uint64(message), part)
			require.NoError(t, servoTestReceive(t, r, f, addr, servoTestNow))
		}
	}
	require.Equal(t, servoMaxAssemblies, r.assemblyOrder.Len())
	require.Equal(t, servoMaxAssemblyBytes, r.assemblyBytes)
	f := servoStateFrame(17, 0, servoRecord{message: 1, total: 1200, data: make([]byte, 600)})
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	require.Empty(t, r.peers[f.session].assemblies)
	require.Equal(t, uint64(1), r.stats.ResourceDrops)
	require.Equal(t, servoMaxAssemblies, r.assemblyOrder.Len())
	require.Zero(t, r.stats.EvictedAssemblies)
}

func TestServoQueueLimitsAndShortBuffer(t *testing.T) {
	for _, n := range []int{1, 1100} {
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			r := servoTestReceiver(t)
			for message := 1; message <= 65; message++ {
				f := servoStateFrame(1, uint64(message), servoFullRecord(uint32(message), n))
				require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
			}
			want := min(servoPeerQueueItems, servoPeerQueueBytes/n)
			require.Equal(t, want, r.queue.Len())
			require.Equal(t, want*n, r.queueBytes)
			require.Equal(t, uint64(65-want), r.stats.QueueDrops)
			f := servoStateFrame(1, 66, servoFullRecord(65, n))
			require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
			require.Equal(t, want, r.queue.Len(), "queue drops keep completion dedup")
			for range want {
				_, _, err := r.pop(nil)
				require.ErrorIs(t, err, io.ErrShortBuffer)
			}
			require.Zero(t, r.queueBytes)
			require.Empty(t, r.queued)
			_, _, err := r.pop(nil)
			require.ErrorIs(t, err, errServoEmpty)
		})
	}
	for _, n := range []int{1, 1100} {
		t.Run("global-"+fmt.Sprint(n), func(t *testing.T) {
			r := servoTestReceiver(t)
			for session := 1; session <= 18; session++ {
				for message := 1; message <= 59; message++ {
					f := servoStateFrame(uint64(session), uint64(message), servoFullRecord(uint32(message), n))
					require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
				}
			}
			require.Equal(t, min(servoQueueItems, servoQueueBytes/n), r.queue.Len())
			require.LessOrEqual(t, r.queueBytes, servoQueueBytes)
			require.Positive(t, r.stats.QueueDrops)
		})
	}
}

func TestServoAuthenticationBeforeAllocationAndSourceQuota(t *testing.T) {
	r := servoTestReceiver(t)
	f := servoStateFrame(1, 0, servoFullRecord(1, 1))
	wire, err := r.cipher.seal(&f)
	require.NoError(t, err)
	for i := range wire {
		bad := bytes.Clone(wire)
		bad[i] ^= 1
		require.Error(t, r.receive(bad, servoTestAddr, servoTestNow))
	}
	require.Empty(t, r.peers)
	require.Empty(t, r.sources)
	require.Empty(t, r.tombstones)
	require.Empty(t, r.endpoints)
	require.Zero(t, r.assemblyBytes)
	for i := range 32 {
		f := servoStateFrame(uint64(i), 0, servoFullRecord(1, 1))
		addr := netip.AddrPortFrom(servoTestAddr.Addr(), uint16(1000+i))
		require.NoError(t, servoTestReceive(t, r, f, addr, servoTestNow))
	}
	f = servoStateFrame(33, 0, servoFullRecord(1, 1))
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoResource)
	_, prefix, _ := servoEndpoint(servoTestAddr)
	require.Equal(t, 32, r.sources[prefix])
	// Mapped IPv4 and scope-free IPv6 /64 quotas are normalized.
	_, a, ok := servoEndpoint(netip.MustParseAddrPort("[::ffff:192.0.2.1]:12"))
	require.True(t, ok)
	require.Equal(t, prefix, a)
	_, a, ok = servoEndpoint(netip.MustParseAddrPort("[2001:db8::1]:12"))
	require.True(t, ok)
	_, b, _ := servoEndpoint(netip.MustParseAddrPort("[2001:db8::ffff]:13"))
	require.Equal(t, a, b)
	for _, addr := range []netip.AddrPort{
		{}, netip.MustParseAddrPort("0.0.0.0:123"), netip.MustParseAddrPort("224.0.0.1:123"), netip.MustParseAddrPort("192.0.2.1:0"),
	} {
		require.ErrorIs(t, r.receive(wire, addr, servoTestNow), errServoFrame)
	}
}

func TestServoBoundedRetirementAdmission(t *testing.T) {
	r := servoTestReceiver(t)
	for i := range servoSessionSlots {
		now := servoTestNow.Add(time.Duration(i) * 8 * time.Millisecond)
		f := servoStateFrame(uint64(i), 0, servoFullRecord(1, 1))
		require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, now))
		r.retire(r.peers[f.session], now)
	}
	require.Len(t, r.tombstones, servoSessionSlots)
	require.Empty(t, r.peers)
	f := servoStateFrame(servoSessionSlots, 0, servoFullRecord(1, 1))
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(17*time.Second)), errServoResource)
	// Capacity cannot be reclaimed by reopening a fresh tombstoned session.
	f = servoStateFrame(1, 1, servoFullRecord(2, 1))
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(17*time.Second)), errServoReplay)
}

func TestServoSeparateUnknownAndActiveBudgets(t *testing.T) {
	r := servoTestReceiver(t)
	f := servoStateFrame(1, 0, servoFullRecord(1, 1))
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	// Exhaust the unknown pool. A known authenticated endpoint is not capped
	// by this pool, although the overall CPU ceiling still applies.
	r.unknown = blinkBucket{at: servoTestNow}
	f.counter++
	f.records[0].message++
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	unknown := netip.MustParseAddrPort("192.0.2.99:12345")
	require.ErrorIs(t, servoTestReceive(t, r, servoStateFrame(2, 0, servoFullRecord(1, 1)), unknown, servoTestNow), errServoRate)
	r.verify = blinkBucket{at: servoTestNow}
	f.counter++
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoRate)
	// Per-session packet and record ceilings are additional, not replacements.
	r.verify = blinkBucket{}
	p := r.peers[f.session]
	p.verify = blinkBucket{at: servoTestNow}
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoRate)
	p.verify, p.records = blinkBucket{}, blinkBucket{at: servoTestNow}
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoRate)
	require.False(t, p.packets.seen(f.counter))
}

func TestServoActiveSessionCeilingAndAdmissionRate(t *testing.T) {
	r := servoTestReceiver(t)
	for i := range servoMaxSessions {
		now := servoTestNow.Add(time.Duration(i) * 8 * time.Millisecond)
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, byte(i >> 8), byte(i)}), 12345)
		f := servoStateFrame(uint64(i), 0, servoFullRecord(1, 1))
		require.NoError(t, servoTestReceive(t, r, f, addr, now))
	}
	require.Len(t, r.peers, servoMaxSessions)
	f := servoStateFrame(servoMaxSessions, 0, servoFullRecord(1, 1))
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(9*time.Second)), errServoResource)
	r = servoTestReceiver(t)
	r.admit = blinkBucket{at: servoTestNow}
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoRate)
	require.Empty(t, r.peers)
}

func TestServoWindowDisplacementCannotReopenOldMessage(t *testing.T) {
	r := servoTestReceiver(t)
	first := servoRecord{message: 1, total: 1200, data: make([]byte, 640)}
	f := servoStateFrame(1, 0, first)
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	f = servoStateFrame(1, servoWindowSize, servoFullRecord(servoWindowSize+1, 1))
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	f = servoStateFrame(1, 0, servoFullRecord(servoWindowSize+2, 1))
	require.ErrorIs(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow), errServoReplay)
	f = servoStateFrame(1, servoWindowSize+1, servoRecord{message: 1, total: 1200, offset: 640, data: make([]byte, 560)})
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	require.Equal(t, uint64(1), r.stats.Completed)
	require.Equal(t, uint64(1), r.stats.MessageReplayDrops)
	r.maintain(servoTestNow.Add(3 * time.Second))
	require.Zero(t, r.assemblyBytes)
}

func TestServoAuthenticatedInvalidFrameDoesNotAllocate(t *testing.T) {
	r := servoTestReceiver(t)
	f := servoStateFrame(1, 0, servoFullRecord(1, 1))
	plain := servoTestPlain(f)
	plain[9] = 1
	require.ErrorIs(t, r.receive(servoTestSealPlain(r.cipher, f, plain), servoTestAddr, servoTestNow), errServoFrame)
	require.Empty(t, r.peers)
	require.Equal(t, uint64(1), r.stats.MalformedDrops)
	_, err := newServoReceiver(nil, 0)
	require.Error(t, err)
}

func TestServoExpiryBeyondMaintenanceBatch(t *testing.T) {
	r := servoTestReceiver(t)
	for i := range 33 {
		part := servoRecord{message: uint32(i + 1), total: 1200, data: make([]byte, 600)}
		f := servoStateFrame(1, uint64(i), part)
		require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow))
	}
	f := servoStateFrame(1, 33, servoRecord{message: 33, total: 1200, offset: 600, data: make([]byte, 600)})
	require.NoError(t, servoTestReceive(t, r, f, servoTestAddr, servoTestNow.Add(3*time.Second)))
	require.Equal(t, uint64(33), r.stats.ExpiredAssemblies)
	require.Zero(t, r.stats.Completed)
	require.Zero(t, r.assemblyBytes)
	r = servoTestReceiver(t)
	for i := range 33 {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 18, 0, byte(i + 1)}), 12345)
		f = servoStateFrame(uint64(i), 0, servoFullRecord(1, 1))
		require.NoError(t, servoTestReceive(t, r, f, addr, servoTestNow))
	}
	addr := netip.MustParseAddrPort("198.18.0.33:12345")
	f.counter++
	require.ErrorIs(t, servoTestReceive(t, r, f, addr, servoTestNow.Add(servoSessionTTL)), errServoFresh)
	require.Empty(t, r.peers)
	require.Len(t, r.tombstones, 33)
}

func TestServoReplayWindowAgainstSetOracle(t *testing.T) {
	var window servoWindow
	seen := make(map[uint64]bool)
	rng := rand.New(rand.NewPCG(1, 2))
	high := uint64(0)
	for i := range 10000 {
		delta := rng.Uint64N(1000)
		id := high + delta
		if i%7 == 0 {
			id = high + servoWindowSize + delta
		} else if i%3 == 0 && high >= delta {
			id = high - delta
		}
		want := seen[id] || (window.hasHigh && id <= high && high-id >= servoWindowSize)
		require.Equal(t, want, window.seen(id), "iteration %d, id %d", i, id)
		if !want {
			window.mark(id)
			seen[id] = true
			high = max(high, id)
		}
		require.True(t, window.seen(id))
		for range 5 {
			probe := rng.Uint64N(high + 100)
			want := seen[probe] || (probe <= high && high-probe >= servoWindowSize)
			require.Equal(t, want, window.seen(probe))
		}
	}
	window.mark(math.MaxUint64)
	require.True(t, window.seen(math.MaxUint64))
	require.True(t, window.seen(0))
	require.False(t, window.seen(math.MaxUint64-1))
	window.mark(math.MaxUint64 - 1)
	require.True(t, window.seen(math.MaxUint64-1))
	window.mark(0) // too old: must not accidentally clear the top bit
	require.True(t, window.seen(math.MaxUint64))
}

func FuzzServoReceiver(f *testing.F) {
	c := servoTestCipher(f, 0)
	frame := servoStateFrame(1, 0, servoFullRecord(1, 10))
	wire, err := c.seal(&frame)
	require.NoError(f, err)
	f.Add(wire)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, wire []byte) {
		r := servoTestReceiver(t)
		_ = r.receive(wire, servoTestAddr, servoTestNow)
		require.LessOrEqual(t, len(r.peers), 1)
		require.LessOrEqual(t, r.assemblyBytes, 8*servoInnerMax)
		require.LessOrEqual(t, r.queue.Len(), 8)
	})
}

func FuzzServoAuthenticatedTrace(f *testing.F) {
	f.Add([]byte{0, 0, 0, 8, 1, 0, 4, 8, 0, 4, 0, 8})
	f.Add(bytes.Repeat([]byte{255, 0, 1, 0}, 16))
	f.Fuzz(func(t *testing.T, trace []byte) {
		r := servoTestReceiver(t)
		// More than unauthenticated-noise fuzzing: every step is authenticated
		// and syntactically valid, including hostile overlap / total changes.
		trace = trace[:min(len(trace), 256)]
		delivered := make(map[[2]uint64]bool)
		var out [servoInnerMax]byte
		for i := 0; i+3 < len(trace); i += 4 {
			session := uint64(1 + trace[i]%2)
			id := uint32(1 + trace[i+1]%8)
			total := 1 + int(trace[i+2])*4
			offset := int(trace[i+3]) % total
			n := min(1+int(trace[i+1])*4, total-offset)
			record := servoRecord{message: id, total: uint16(total), offset: uint16(offset), data: bytes.Repeat([]byte{byte(id)}, n)}
			frame := servoStateFrame(session, uint64(i/4), record)
			now := servoTestNow.Add(time.Duration(i) * 20 * time.Millisecond)
			_ = servoTestReceive(t, r, frame, servoTestAddr, now)
			for r.queue.Len() > 0 {
				d := r.queue.Front().Value.(servoCompleted)
				key := [2]uint64{binary.BigEndian.Uint64(d.session[8:]), uint64(d.data[0])}
				require.False(t, delivered[key], "completed message delivered twice")
				delivered[key] = true
				_, _, err := r.pop(out[:])
				require.NoError(t, err)
			}
			require.LessOrEqual(t, r.assemblyBytes, 16*servoInnerMax)
			require.LessOrEqual(t, len(r.peers), 2)
		}
	})
}
