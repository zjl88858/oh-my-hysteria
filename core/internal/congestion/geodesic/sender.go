// SPDX-License-Identifier: MIT-0

package geodesic

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"sync"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

type mode uint8

const (
	startup mode = iota
	drain
	probeBW
)

func (m mode) String() string { return [...]string{"Startup", "Drain", "ProbeBW"}[m] }

const historyCapacity = 131072

type undoState struct {
	valid bool
	cwnd  uint64
	lost  map[congestion.PacketNumber]struct{}
}
type senderState struct {
	rtt                                           congestion.RTTStatsProvider
	sampler                                       *deliverySampler
	size, initial, cwnd, inFlight, rate, seedRate uint64
	state                                         mode
	phase                                         uint8
	geo                                           estimator
	round, nextRound, roundRTTMin                 uint64
	allowG2                                       bool
	lastRTTTime                                   monotime.Time
	hasRTTTime                                    bool
	bwSlots                                       [10]bandwidthSlot
	lastBandwidth                                 uint64
	bwRound, bwDeliveryRound, rejectedBW          uint64
	roundQualified, lastSampleLimited             bool
	fullBW, plateau                               uint64
	fullReached                                   bool
	inRecovery                                    bool
	recoveryEnd                                   congestion.PacketNumber
	priorCwnd                                     uint64
	undo                                          undoState
	ceEnd                                         congestion.PacketNumber
	ceCount                                       uint64
	lossSinceACK                                  bool
	ltUse, ltSampling                             bool
	ltRate, ltRounds, ltDelivered, ltLost         uint64
	ltStamp                                       monotime.Time
	aggStamp                                      monotime.Time
	aggSet                                        bool
	aggAcked, aggRounds                           uint64
	aggIndex                                      uint8
	extra                                         [2]uint64
	now, cycleStamp                               monotime.Time
	clockSet, idle                                bool
	pacer                                         pacer
	rng                                           *rand.Rand
	faults, unknown, resets, undoCount            uint64
}

type Snapshot struct {
	Algorithm                                                     string `json:"algorithm"`
	State                                                         string `json:"state"`
	Phase                                                         uint8
	Cwnd, InFlight, Bandwidth, PacingRate                         uint64
	MinRTT, EstimateRTT, QueueDelay, Jitter                       time.Duration
	Round, RTTSamples, Confidence, G1, G2, G3, LockReleases       uint64
	Locked, FullBandwidth, Recovery, Policer                      bool
	SamplingErrors, UnknownACKs, PathResets, ECNEvents, UndoCount uint64
	History                                                       int
	BandwidthRound, RejectedBandwidthSamples                      uint64
	RoundQualified, LastSampleAppLimited                          bool
}

// Sender is connection-local. No kernel module, FEC, global KF bandwidth floor,
// or UCP transport is installed. Only the estimation/model policy is adapted.
type Sender struct {
	mu                  sync.Mutex
	debug, debugStarted bool
	debugStamp          monotime.Time
	debugState          mode
	debugPhase          uint8
	senderState
}

var _ congestion.AdvancedControl = (*Sender)(nil)

func NewSender(size congestion.ByteCount) *Sender {
	s := &Sender{debug: os.Getenv("OH_MY_HYSTERIA_GEODESIC_DEBUG") == "1"}
	s.reset(size, nil)
	return s
}

func (s *Sender) reset(size congestion.ByteCount, r congestion.RTTStatsProvider) {
	if size <= 0 {
		size = congestion.InitialPacketSize
	}
	size = min(size, 65527)
	sampler, _ := newDeliverySampler(historyCapacity)
	s.senderState = senderState{
		rtt: r, sampler: sampler, size: uint64(size), initial: 32 * uint64(size), cwnd: 32 * uint64(size),
		recoveryEnd: -1, ceEnd: -1, rng: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}
	s.seedRate = bytesPerSecond(s.initial, s.initialRTT())
	s.rate = max(1, mulDiv(s.seedRate, startupGain*99, 25600))
}

func (s *Sender) initialRTT() time.Duration {
	if s.rtt != nil && s.rtt.SmoothedRTT() > 0 {
		return min(time.Minute, max(time.Microsecond, s.rtt.SmoothedRTT()))
	}
	return 100 * time.Millisecond
}
func (s *Sender) floor() uint64   { return 4 * s.size }
func (s *Sender) maximum() uint64 { return uint64(congestion.MaxCongestionWindowPackets) * s.size }
func (s *Sender) setClock(now monotime.Time) {
	if !s.clockSet || now > s.now {
		s.now = now
	}
	s.clockSet = true
}

func (s *Sender) SetRTTStatsProvider(r congestion.RTTStatsProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rtt = r
	if s.geo.samples == 0 {
		s.seedRate = bytesPerSecond(s.initial, s.initialRTT())
		s.rate = max(1, mulDiv(s.seedRate, startupGain*99, 25600))
	}
}

func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.cwnd)
}
func (s *Sender) InSlowStart() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.state == startup }
func (s *Sender) InRecovery() bool  { s.mu.Lock(); defer s.mu.Unlock(); return s.inRecovery }
func (s *Sender) CanSend(flight congestion.ByteCount) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return flight >= 0 && uint64(flight) < s.cwnd
}

func (s *Sender) TimeUntilSend(congestion.ByteCount) monotime.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.deadline(s.size, s.rate)
}

func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.budget(now, s.rate, s.burst()) >= int64(s.size)
}

func (s *Sender) SendQuantum() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.quantum())
}

// The AdvancedControl contract owns all bookkeeping, not these legacy hooks.
func (*Sender) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}

func (*Sender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (*Sender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (*Sender) MaybeExitSlowStart()          {}
func (*Sender) OnRetransmissionTimeout(bool) {} // QUIC PTO is not TCP RTO.

func (s *Sender) samplingFault(err error) {
	faults, resets, size, r := s.faults+1, s.resets, s.size, s.rtt
	if faults == 1 {
		fmt.Fprintf(os.Stderr, "geodesic: resetting sampling state: %v\n", err)
	}
	s.reset(congestion.ByteCount(size), r)
	s.faults, s.resets = faults, resets
}

func (s *Sender) OnPacketSentContext(e congestion.SentPacketContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(e.Time)
	s.pacer.sent(s.now, uint64(max(0, e.Bytes)), s.rate, s.burst())
	if e.Space != congestion.SpaceApplication {
		return
	}
	s.inFlight = uint64(max(0, e.ApplicationBytesInFlight))
	if s.idle && e.AckEliciting && e.ApplicationBytesInFlight == e.Bytes {
		s.cycleStamp = s.now
		s.aggSet = false
		s.aggAcked = 0
		if s.state == probeBW {
			s.rate = max(1, mulDiv(s.bandwidth(), 99, 100))
		}
	}
	// PMTU probes maintain packet-number ordering, but are not data samples.
	if err := s.sampler.sent(e.Time, e.PacketNumber, e.Bytes, e.ApplicationBytesInFlight, e.AckEliciting && !e.MTUProbe, false); err != nil {
		s.samplingFault(err)
	}
}

func (s *Sender) OnApplicationLimited(now monotime.Time, flight congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(now)
	if err := s.sampler.markAppLimited(flight); err != nil {
		s.samplingFault(err)
		return
	}
	s.idle = true
	s.geo.fast, s.geo.slow, s.geo.fall, s.geo.unlock, s.geo.srttGuard = 0, 0, 0, 0, 0
	s.roundRTTMin = 0
	s.roundQualified = false
	s.allowG2 = false
	s.resetLT()
}

func (s *Sender) OnPacketRemoved(space congestion.PacketSpace, pn congestion.PacketNumber, _ congestion.RemovalReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if space != congestion.SpaceApplication {
		return
	}
	if _, ok := s.undo.lost[pn]; ok {
		s.undo.valid = false
		clear(s.undo.lost)
	}
	s.sampler.discard(pn)
}

func (s *Sender) OnPathReset(now monotime.Time, size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	faults, resets, r := s.faults, s.resets+1, s.rtt
	s.reset(size, r)
	s.faults, s.resets = faults, resets
	s.setClock(now)
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size <= 0 || uint64(size) < s.size || size > 65527 {
		panic("geodesic: invalid datagram size")
	}
	initial := s.cwnd == s.initial && s.state == startup
	s.size = uint64(size)
	s.initial = 32 * s.size
	if initial {
		s.cwnd = s.initial
	}
	s.cwnd = min(s.maximum(), max(s.floor(), s.cwnd))
}

func (s *Sender) noteLoss(pn congestion.PacketNumber, bytes uint64) {
	if !s.inRecovery || pn > s.recoveryEnd {
		s.inRecovery = true
		s.recoveryEnd = s.sampler.lastSent
		s.priorCwnd = s.cwnd
		s.undo = undoState{valid: true, cwnd: s.cwnd, lost: make(map[congestion.PacketNumber]struct{})}
	}
	if s.undo.valid {
		if len(s.undo.lost) >= 64 {
			s.undo.valid = false
			clear(s.undo.lost)
		} else {
			s.undo.lost[pn] = struct{}{}
		}
	}
	s.cwnd = max(s.floor(), s.cwnd-min(s.cwnd, bytes))
	s.lossSinceACK = true
}

func (s *Sender) OnSpuriousPacket(pn congestion.PacketNumber, at monotime.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(at)
	if _, ok := s.sampler.packets[pn]; ok {
		if _, err := s.sampler.ack(at, []congestion.PacketNumber{pn}, 0); err != nil {
			s.samplingFault(err)
			return
		}
	}
	if _, ok := s.undo.lost[pn]; !ok {
		return
	}
	delete(s.undo.lost, pn)
	if s.undo.valid && len(s.undo.lost) == 0 {
		s.cwnd = min(s.maximum(), max(s.cwnd, s.undo.cwnd))
		s.inRecovery = false
		s.undo.valid = false
		s.undoCount++
	}
}

func (s *Sender) OnCongestionEventContext(e congestion.CongestionEventContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if e.Space != congestion.SpaceApplication {
		return
	}
	s.setClock(e.Time)
	s.inFlight = uint64(max(0, e.ApplicationBytesInFlight))
	for _, p := range e.Lost {
		if p.MTUProbe {
			continue
		}
		l, err := s.sampler.lost(p.PacketNumber)
		if err != nil {
			s.samplingFault(err)
			return
		}
		if l.newlyLost && l.congestion {
			s.noteLoss(p.PacketNumber, uint64(l.bytes))
		}
	}
	numbers := make([]congestion.PacketNumber, 0, len(e.Acked))
	mtuACK, unknown := false, false
	for _, p := range e.Acked {
		if p.MTUProbe {
			mtuACK = true
			continue
		}
		if _, ok := s.sampler.packets[p.PacketNumber]; ok {
			numbers = append(numbers, p.PacketNumber)
		} else {
			s.unknown++
			unknown = true
		}
	}
	minRTT := time.Duration(0)
	if s.rtt != nil {
		minRTT = max(0, s.rtt.MinRTT())
	}
	rs, err := s.sampler.ack(e.Time, numbers, minRTT)
	if err != nil {
		s.samplingFault(err)
		return
	}
	if unknown {
		rs.valid = false
	}
	newRound := rs.hasData && rs.priorDelivered >= s.nextRound
	if newRound {
		s.round++
		s.nextRound = s.sampler.totals.delivered
		s.geo.completeRoundWithPolicy(s.round, s.roundRTTMin, rttMicros(s.initialRTT()), s.state == probeBW && s.roundQualified)
		s.roundRTTMin = 0
		s.roundQualified = false
		s.allowG2 = true
	}
	if rs.hasData && !mtuACK && !unknown && e.RTTUpdated && e.RTT > 0 && (!s.hasRTTTime || e.Time >= s.lastRTTTime) {
		us := rttMicros(e.RTT)
		if s.roundRTTMin == 0 || us < s.roundRTTMin {
			s.roundRTTMin = us
		}
		s.geo.observe(us, s.round, s.allowG2)
		s.allowG2 = false
		s.lastRTTTime, s.hasRTTTime = e.Time, true
	}
	s.noteBandwidth(rs)
	if rs.hasData {
		s.lastSampleLimited = rs.appLimited
	}
	loss := s.lossSinceACK
	s.longTerm(rs, newRound, loss)
	s.aggregation(rs.newlyAcked, newRound)
	if s.inRecovery && rs.hasData && rs.packet > s.recoveryEnd {
		s.inRecovery = false
		s.cwnd = max(s.cwnd, s.priorCwnd)
	}
	ce := e.ECNCongestion && s.sampler.hasSent && (s.ceEnd < 0 || (rs.hasData && rs.packet > s.ceEnd))
	if ce {
		s.ceEnd = s.sampler.lastSent
		s.ceCount++
		s.undo.valid = false
		clear(s.undo.lost)
		s.cwnd = max(s.floor(), mulDiv(s.cwnd, 7, 10))
		s.priorCwnd = min(s.priorCwnd, s.cwnd)
		s.fullReached = true
		if s.state == startup {
			s.state = drain
		} else if s.state == probeBW {
			s.phase = 1
		}
		s.cycleStamp = s.now
	}
	s.advance(rs, newRound, loss)
	s.updateControls(rs.newlyAcked, rs.appLimited, ce)
	if rs.hasData {
		s.lossSinceACK = false
		s.idle = false
	}
	s.trace()
}

func (s *Sender) snapshot() Snapshot {
	return Snapshot{
		Algorithm: "geodesic", State: s.state.String(), Phase: s.phase, Cwnd: s.cwnd, InFlight: s.inFlight,
		Bandwidth: s.bandwidth(), PacingRate: s.rate, MinRTT: time.Duration(s.geo.minimum) * time.Microsecond,
		EstimateRTT: time.Duration(s.geo.x>>10) * time.Microsecond, QueueDelay: time.Duration(s.geo.queue) * time.Microsecond, Jitter: time.Duration(s.geo.jitter) * time.Microsecond,
		Round: s.round, RTTSamples: s.geo.samples, Confidence: s.geo.confidence, G1: s.geo.g1, G2: s.geo.g2, G3: s.geo.g3, LockReleases: s.geo.lockReleases,
		Locked: s.geo.locked, FullBandwidth: s.fullReached, Recovery: s.inRecovery, Policer: s.ltUse,
		SamplingErrors: s.faults, UnknownACKs: s.unknown, PathResets: s.resets, ECNEvents: s.ceCount, UndoCount: s.undoCount, History: len(s.sampler.packets),
		BandwidthRound: s.bwRound, RejectedBandwidthSamples: s.rejectedBW, RoundQualified: s.roundQualified, LastSampleAppLimited: s.lastSampleLimited,
	}
}
func (s *Sender) Snapshot() Snapshot { s.mu.Lock(); defer s.mu.Unlock(); return s.snapshot() }
func (s *Sender) trace() {
	if !s.debug {
		return
	}
	elapsed, _ := sampleElapsed(s.now, s.debugStamp)
	if s.debugStarted && s.state == s.debugState && s.phase == s.debugPhase && elapsed < time.Second {
		return
	}
	data, err := json.Marshal(s.snapshot())
	if err == nil {
		fmt.Fprintf(os.Stderr, "geodesic snapshot %s\n", data)
	}
	s.debugStarted, s.debugStamp, s.debugState, s.debugPhase = true, s.now, s.state, s.phase
}
