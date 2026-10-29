// SPDX-License-Identifier: MIT-0

package bbr3

import (
	"encoding/json"
	"fmt"
	"math"
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
	probeDown
	probeCruise
	probeRefill
	probeUp
	probeRTT
)

func (m mode) String() string {
	return [...]string{"Startup", "Drain", "ProbeBW_DOWN", "ProbeBW_CRUISE", "ProbeBW_REFILL", "ProbeBW_UP", "ProbeRTT"}[m]
}

type ackPhase uint8

const (
	acksInit ackPhase = iota
	acksRefill
	acksStarting
	acksFeedback
	acksStopping
)

const (
	unlimited       = uint64(math.MaxUint64)
	historyCapacity = 131072
)

type undoState struct {
	valid                                  bool
	restoreState                           bool
	state                                  mode
	bwShort, flightShort, flightLong, cwnd uint64
	lost                                   map[congestion.PacketNumber]struct{}
}

type aggregateSlot struct {
	round, value uint64
	valid        bool
}

// Snapshot is an immutable diagnostic view. Byte rates are bytes/second.
// It does not expose authentication, addresses or packet contents.
type Snapshot struct {
	Profile                                                                      Profile `json:"profile"`
	State                                                                        string  `json:"state"`
	Round                                                                        uint64  `json:"round"`
	Bandwidth, PacingRate, Cwnd, InFlight, InflightLongterm, InflightShortterm   uint64
	MinRTT                                                                       time.Duration
	FullBandwidth                                                                bool
	ProbeRTTCount, SamplingErrors, UnknownACKs, ECNEvents, UndoCount, PathResets uint64
}

type senderState struct {
	sampler                                                 *deliverySampler
	rtt                                                     congestion.RTTStatsProvider
	size, initial, cwnd, priorCwnd, inFlight                uint64
	state                                                   mode
	phase                                                   ackPhase
	bwCurrent, bwPrevious, bwShort, flightShort, flightLong uint64
	rate, quantum                                           uint64
	pacer                                                   pacer
	now                                                     monotime.Time
	clockSet                                                bool
	round, nextRound, roundsSinceProbe, drainRound          uint64
	limitedCurrent, limitedPrevious                         bool
	fullBW, plateauRounds                                   uint64
	fullNow, fullReached                                    bool
	minRTT, probeMin                                        time.Duration
	minStamp, probeStamp                                    monotime.Time
	hasMin, hasProbeStamp                                   bool
	probeDone                                               monotime.Time
	probeTimer                                              bool
	probeRound                                              uint64
	idleRestart                                             bool
	cycleStamp                                              monotime.Time
	probeWait                                               time.Duration
	probeSamples, prevHigh, prevPrecaution                  bool
	upRounds                                                uint
	upAcked, upPerIncrease                                  uint64
	bwLatest, flightLatest, lossBoundary                    uint64
	lossInRound                                             bool
	roundLossBytes, roundMaxFlight                          uint64
	roundLost                                               map[congestion.PacketNumber]struct{}
	lossGroups                                              int
	inRecovery                                              bool
	recoveryEnd                                             congestion.PacketNumber
	recoveryRound                                           uint64
	undo                                                    undoState
	aggStamp                                                monotime.Time
	aggValid                                                bool
	aggDelivered                                            uint64
	aggSlots                                                [10]aggregateSlot
	extraAcked                                              uint64
	lastCERound                                             uint64
	seenCE                                                  bool
	rng                                                     *rand.Rand
	probeCount, faults, unknown, ceCount, undoCount, resets uint64
}

// Sender implements an independent BBRv3 controller based on draft -06. It
// requires the local QUIC AdvancedControl contract, not upstream's legacy API.
// A mutex also protects diagnostics read by a different goroutine.
type Sender struct {
	mu           sync.Mutex
	profile      Profile
	tuning       profileConfig
	debug        bool
	debugStamp   monotime.Time
	debugState   mode
	debugStarted bool
	senderState
}

var _ congestion.AdvancedControl = (*Sender)(nil)

func NewSender(size congestion.ByteCount) *Sender {
	return NewSenderWithProfile(size, ProfileStandard)
}

// NewSenderWithProfile requires a valid profile. Configuration entry points
// must call ParseProfile and return its error to users before installation.
// The immutable profile survives path resets and sampling-fault recovery.
func NewSenderWithProfile(size congestion.ByteCount, profile Profile) *Sender {
	normalized, err := ParseProfile(string(profile))
	if err != nil {
		panic(err)
	}
	s := &Sender{profile: normalized, tuning: configForProfile(normalized), debug: os.Getenv("OH_MY_HYSTERIA_BBR3_DEBUG") == "1"}
	s.reset(size, nil)
	return s
}

func (s *Sender) reset(size congestion.ByteCount, provider congestion.RTTStatsProvider) {
	if size <= 0 {
		size = congestion.InitialPacketSize
	}
	sampler, _ := newDeliverySampler(historyCapacity)
	s.senderState = senderState{
		sampler: sampler, rtt: provider, size: uint64(size), initial: 32 * uint64(size), cwnd: 32 * uint64(size),
		bwShort: unlimited, flightShort: unlimited, flightLong: unlimited,
		upPerIncrease: unlimited, roundLost: make(map[congestion.PacketNumber]struct{}),
		rng: rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64())),
	}
	s.initializeRate()
}

func (s *Sender) initializeRate() {
	rtt := 100 * time.Millisecond
	if s.rtt != nil && s.rtt.SmoothedRTT() > 0 {
		rtt = s.rtt.SmoothedRTT()
	}
	s.rate = max(1, mulDiv(bytesPerSecond(s.initial, rtt), s.tuning.startupPacingGain, 100))
	s.updateQuantum()
}

func (s *Sender) SetRTTStatsProvider(r congestion.RTTStatsProvider) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rtt = r
	s.initializeRate()
}

func (s *Sender) GetCongestionWindow() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.cwnd)
}
func (s *Sender) InSlowStart() bool { s.mu.Lock(); defer s.mu.Unlock(); return s.state == startup }
func (s *Sender) InRecovery() bool  { s.mu.Lock(); defer s.mu.Unlock(); return s.inRecovery }
func (s *Sender) TimeUntilSend(_ congestion.ByteCount) monotime.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.deadline(s.size, s.rate)
}

func (s *Sender) HasPacingBudget(now monotime.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pacer.budget(now, s.rate, s.burst()) >= int64(s.size)
}

func (s *Sender) CanSend(flight congestion.ByteCount) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if flight >= 0 && uint64(flight) >= s.cwnd {
		s.limitedCurrent = true
	}
	return flight >= 0 && uint64(flight) < s.cwnd
}

func (s *Sender) SendQuantum() congestion.ByteCount {
	s.mu.Lock()
	defer s.mu.Unlock()
	return congestion.ByteCount(s.quantum)
}

// Legacy per-packet notifications deliberately do not bookkeep: the rich event
// follows them once and has the packet-space / PMTU information we require.
func (*Sender) OnPacketSent(monotime.Time, congestion.ByteCount, congestion.PacketNumber, congestion.ByteCount, bool) {
}

func (*Sender) OnPacketAcked(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount, monotime.Time) {
}

func (*Sender) OnCongestionEvent(congestion.PacketNumber, congestion.ByteCount, congestion.ByteCount) {
}
func (*Sender) MaybeExitSlowStart() {}

// QUIC PTO never calls or substitutes for a TCP RTO. Kept for interface compatibility.
func (*Sender) OnRetransmissionTimeout(bool) {}

func (s *Sender) setClock(now monotime.Time) {
	if !s.clockSet {
		s.now = now
		s.clockSet = true
		s.minStamp = now
		s.probeStamp = now
		s.hasProbeStamp = true
	}
	if now > s.now {
		s.now = now
	}
}

func (s *Sender) samplingFault(err error) {
	faults, resets, provider, size := s.faults+1, s.resets, s.rtt, s.size
	if faults == 1 {
		fmt.Fprintf(os.Stderr, "bbr3: resetting sampling state: %v\n", err)
	}
	s.reset(congestion.ByteCount(size), provider)
	s.faults, s.resets = faults, resets
}

func (s *Sender) OnPacketSentContext(e congestion.SentPacketContext) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(e.Time)
	s.pacer.sent(e.Time, uint64(max(0, e.Bytes)), s.rate, s.burst())
	if e.Space != congestion.SpaceApplication {
		return
	}
	if e.AckEliciting && e.ApplicationBytesInFlight == e.Bytes && s.sampler.appLimitedEnd != 0 {
		s.idleRestart = true
		s.aggStamp = s.now
		s.aggDelivered = 0
		s.aggValid = true
		if s.probingState() {
			s.rate = max(1, s.bandwidth())
			s.updateQuantum()
		}
		if s.state == probeRTT && s.probeTimer && s.now >= s.probeDone && s.round >= s.probeRound {
			s.exitProbeRTT()
		}
	}
	s.inFlight = uint64(max(0, e.ApplicationBytesInFlight))
	if uint64(max(0, e.BytesInFlight)) >= s.cwnd {
		s.limitedCurrent = true
	}
	if err := s.sampler.sent(e.Time, e.PacketNumber, e.Bytes, e.ApplicationBytesInFlight, e.AckEliciting, e.MTUProbe); err != nil {
		s.samplingFault(err)
	}
}

func (s *Sender) OnApplicationLimited(now monotime.Time, flight congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.setClock(now)
	if err := s.sampler.markAppLimited(flight); err != nil {
		s.samplingFault(err)
	}
}

func (s *Sender) OnPacketRemoved(space congestion.PacketSpace, pn congestion.PacketNumber, _ congestion.RemovalReason) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if space != congestion.SpaceApplication {
		return
	}
	if _, affected := s.undo.lost[pn]; affected {
		s.undo.valid = false
		clear(s.undo.lost)
	}
	s.sampler.discard(pn)
}

func (s *Sender) OnPathReset(now monotime.Time, size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	resets, faults, r := s.resets+1, s.faults, s.rtt
	s.reset(size, r)
	s.resets = resets
	s.faults = faults
	s.setClock(now)
}

func (s *Sender) SetMaxDatagramSize(size congestion.ByteCount) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if size <= 0 || uint64(size) < s.size {
		panic("bbr3: invalid decreasing datagram size")
	}
	s.size = uint64(size)
	s.initial = 32 * s.size
	s.cwnd = max(s.cwnd, s.floor())
	s.updateQuantum()
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
	if !s.undo.valid || len(s.undo.lost) != 0 {
		return
	}
	u := s.undo
	s.undo.valid = false
	s.cwnd = max(s.cwnd, u.cwnd)
	s.bwShort = max(s.bwShort, u.bwShort)
	s.flightShort = max(s.flightShort, u.flightShort)
	s.flightLong = max(s.flightLong, u.flightLong)
	s.lossInRound = false
	s.roundLossBytes = 0
	s.roundMaxFlight = 0
	clear(s.roundLost)
	s.lossGroups = 0
	s.fullNow = false
	s.fullBW = 0
	s.plateauRounds = 0
	if s.state != probeRTT {
		if u.restoreState && u.state == startup && s.state != startup {
			s.fullReached = false
			s.state = startup
		}
		if u.restoreState && u.state == probeUp && s.state != probeUp {
			s.enterRefill()
		}
	}
	s.inRecovery = false
	s.undoCount++
	s.updateControls(0)
	s.cwnd = max(s.cwnd, min(u.cwnd, s.maximum()))
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
		l, err := s.sampler.lost(p.PacketNumber)
		if err != nil {
			s.samplingFault(err)
			return
		}
		if !l.known || !l.newlyLost || !l.congestion {
			continue
		}
		s.noteLoss(p.PacketNumber, l.state)
	}
	numbers := make([]congestion.PacketNumber, 0, len(e.Acked))
	for _, p := range e.Acked {
		if _, ok := s.sampler.packets[p.PacketNumber]; ok {
			numbers = append(numbers, p.PacketNumber)
		} else {
			s.unknown++
		}
	}
	minSampleRTT := time.Duration(0)
	if s.rtt != nil {
		minSampleRTT = s.rtt.MinRTT()
	}
	rs, err := s.sampler.ack(e.Time, numbers, minSampleRTT)
	if err != nil {
		s.samplingFault(err)
		return
	}
	roundStart := rs.hasData && rs.priorDelivered >= s.nextRound
	if roundStart {
		s.round++
		s.nextRound = s.sampler.totals.delivered
		s.roundsSinceProbe++
		s.limitedPrevious = s.limitedCurrent
		s.limitedCurrent = false
	}
	if rs.valid {
		if !rs.appLimited || rs.rate >= s.maxBandwidth() {
			s.bwCurrent = max(s.bwCurrent, rs.rate)
		}
		s.bwLatest = max(s.bwLatest, rs.rate)
	}
	if rs.hasData {
		s.flightLatest = max(s.flightLatest, rs.delivered)
	}
	lossRound := rs.hasData && rs.priorDelivered >= s.lossBoundary
	if lossRound {
		if s.state == startup && s.inRecovery && s.round > s.recoveryRound+1 && s.lossGroups >= 6 && s.roundLossBytes > mulDiv(s.roundMaxFlight, 2, 100) {
			s.undo.restoreState = true
			s.undo.state = startup
			s.fullReached = true
			s.flightLong = max(s.bdp(100), s.flightLatest)
			s.enterDrain()
		}
		if !s.accelerating() && s.lossInRound && s.maxBandwidth() > 0 {
			if s.bwShort == unlimited {
				s.bwShort = s.maxBandwidth()
			}
			if s.flightShort == unlimited {
				s.flightShort = s.cwnd
			}
			s.bwShort = max(s.bwLatest, mulDiv(s.bwShort, 7, 10))
			s.flightShort = max(s.flightLatest, mulDiv(s.flightShort, 7, 10))
		}
		s.lossBoundary = s.sampler.totals.delivered
		s.lossInRound = false
		s.roundLossBytes = 0
		s.roundMaxFlight = 0
		clear(s.roundLost)
		s.lossGroups = 0
	}
	if roundStart && rs.valid && !rs.appLimited && !s.fullNow {
		if s.fullBW == 0 || rs.rate >= mulDiv(s.fullBW, 125, 100) {
			s.fullBW = rs.rate
			s.plateauRounds = 0
		} else {
			s.plateauRounds++
			if s.plateauRounds >= 3 {
				s.fullNow = true
				s.fullReached = true
			}
		}
	}
	if s.inRecovery && rs.hasData && rs.packet > s.recoveryEnd {
		s.inRecovery = false
		s.cwnd = max(s.cwnd, s.priorCwnd)
	}
	if e.ECNCongestion {
		s.respondCE()
	}
	if s.state == startup && s.fullReached {
		s.enterDrain()
	}
	enteredProbe := false
	if s.state == drain && (s.inFlight <= s.inflightTarget(100) || s.round > s.drainRound+3) {
		s.enterDown()
		enteredProbe = true
	}
	if s.probingState() && rs.hasData && !enteredProbe {
		s.advanceProbe(rs, roundStart)
	}
	if rs.hasData {
		s.updateAggregation(rs.newlyAcked)
	}
	if e.RTTUpdated && e.RTT > 0 {
		s.updateMinRTT(e.RTT)
	}
	s.handleProbeRTT(rs, roundStart)
	s.updateControls(rs.newlyAcked)
	if lossRound {
		s.bwLatest = 0
		if rs.valid {
			s.bwLatest = rs.rate
		}
		s.flightLatest = rs.delivered
	}
	if rs.newlyAcked > 0 {
		s.idleRestart = false
	}
	s.trace()
}

func (s *Sender) noteLoss(pn congestion.PacketNumber, p sentPacket) {
	if !s.inRecovery || pn > s.recoveryEnd {
		s.priorCwnd = s.cwnd
		s.undo = undoState{valid: true, state: s.state, bwShort: s.bwShort, flightShort: s.flightShort, flightLong: s.flightLong, cwnd: s.cwnd, lost: make(map[congestion.PacketNumber]struct{})}
		s.inRecovery = true
		s.recoveryEnd = s.sampler.lastSent
		s.recoveryRound = s.round
	}
	// The transport retains at most 64 losses. An incomplete episode must
	// never be undone, and it need not retain an unbounded packet set.
	if s.undo.valid {
		if len(s.undo.lost) >= 64 {
			s.undo.valid = false
			clear(s.undo.lost)
		} else {
			s.undo.lost[pn] = struct{}{}
		}
	}
	if !s.lossInRound {
		s.lossBoundary = s.sampler.totals.delivered
	}
	s.lossInRound = true
	s.roundLossBytes += uint64(p.bytes)
	s.roundMaxFlight = max(s.roundMaxFlight, uint64(p.inFlight))
	if _, ok := s.roundLost[pn]; !ok {
		if len(s.roundLost) >= historyCapacity {
			s.samplingFault(errSampleCapacity)
			return
		}
		_, left := s.roundLost[pn-1]
		_, right := s.roundLost[pn+1]
		if !left && !right {
			s.lossGroups++
		}
		if left && right {
			s.lossGroups--
		}
		s.roundLost[pn] = struct{}{}
	}
	if s.probingState() && s.probeSamples {
		lost := s.sampler.totals.congestionLost - p.congestionLost
		if lost > mulDiv(uint64(p.inFlight), 2, 100) {
			prevFlight := uint64(max(0, p.inFlight-p.bytes))
			prevLost := lost - min(lost, uint64(p.bytes))
			threshold := mulDiv(prevFlight, 2, 100)
			prefix := uint64(0)
			if threshold > prevLost {
				prefix = mulDiv(threshold-prevLost, 100, 98)
			}
			s.handleExcessLoss(addBounded(prevFlight, min(prefix, uint64(p.bytes))), p.appLimited)
		}
	}
}

func (s *Sender) handleExcessLoss(flight uint64, appLimited bool) {
	s.prevHigh = true
	s.probeSamples = false
	if !appLimited {
		s.flightLong = max(flight, mulDiv(min(s.bdp(100), s.cwnd), 7, 10))
	}
	if s.state == probeUp {
		s.undo.restoreState = true
		s.undo.state = probeUp
		s.enterDown()
	}
}

func (s *Sender) respondCE() {
	s.ceCount++
	if s.seenCE && s.lastCERound == s.round {
		return
	}
	s.seenCE = true
	s.lastCERound = s.round
	s.undo.valid = false
	s.cwnd = max(s.floor(), mulDiv(s.cwnd, 7, 10))
	s.flightShort = min(s.flightShort, s.cwnd)
	if s.maxBandwidth() > 0 {
		s.bwShort = min(s.bwShort, max(1, mulDiv(s.maxBandwidth(), 7, 10)))
	}
	if s.state == startup {
		s.fullReached = true
		s.enterDrain()
	}
}

func (s *Sender) enterDrain() { s.state = drain; s.drainRound = s.round }
func (s *Sender) enterDown() {
	s.state = probeDown
	s.phase = acksStopping
	s.nextRound = s.sampler.totals.delivered
	s.cycleStamp = s.now
	s.probeWait = s.tuning.probeWaitBase + time.Duration(s.rng.Uint64N(uint64(s.tuning.probeWaitRange)))
	s.roundsSinceProbe = s.rng.Uint64N(2)
	s.upPerIncrease = unlimited
	s.lossInRound = false
	s.roundLossBytes = 0
	s.roundMaxFlight = 0
	clear(s.roundLost)
	s.lossGroups = 0
	s.bwLatest = 0
	s.flightLatest = 0
}

func (s *Sender) enterRefill() {
	s.state = probeRefill
	s.bwShort = unlimited
	s.flightShort = unlimited
	s.upRounds = 0
	s.upAcked = 0
	s.prevPrecaution = false
	s.phase = acksRefill
	s.nextRound = s.sampler.totals.delivered
}

func (s *Sender) enterUp(rate uint64) {
	s.state = probeUp
	s.phase = acksStarting
	s.nextRound = s.sampler.totals.delivered
	s.fullNow = false
	s.fullBW = rate
	s.plateauRounds = 0
	s.raiseSlope()
}

func (s *Sender) raiseSlope() {
	s.upPerIncrease = max(s.size, s.cwnd/(uint64(1)<<s.upRounds))
	s.upRounds = min(s.upRounds+1, 30)
}

func (s *Sender) advanceProbe(rs rateSample, roundStart bool) {
	if s.phase == acksStarting && roundStart {
		s.phase = acksFeedback
	}
	if s.phase == acksStopping && roundStart {
		s.probeSamples = false
		s.phase = acksInit
		if !rs.appLimited {
			s.bwPrevious = s.bwCurrent
			s.bwCurrent = 0
		}
		if s.prevPrecaution && !s.prevHigh {
			s.enterRefill()
			return
		}
	}
	tooHigh := rs.hasData && rs.congestionLostSinceSent > mulDiv(uint64(max(0, rs.inFlightAtSend)), 2, 100)
	if tooHigh && s.probeSamples {
		s.handleExcessLoss(uint64(max(0, rs.inFlightAtSend)), rs.appLimited)
		return
	}
	if !tooHigh && s.flightLong != unlimited {
		s.flightLong = max(s.flightLong, uint64(max(0, rs.inFlightAtSend)))
		if s.state == probeUp && (s.limitedCurrent || s.limitedPrevious) && s.cwnd >= s.flightLong {
			s.upAcked = addBounded(s.upAcked, rs.newlyAcked)
			if s.upPerIncrease != unlimited && s.upAcked >= s.upPerIncrease {
				delta := s.upAcked / s.upPerIncrease
				s.upAcked %= s.upPerIncrease
				s.flightLong = addBounded(s.flightLong, mulDiv(delta, s.size, 1))
			}
			if roundStart {
				s.raiseSlope()
			}
		}
	}
	switch s.state {
	case probeDown, probeCruise:
		rounds := min(s.tuning.probeRoundCap, max(uint64(1), min(s.bdp(100), s.cwnd)/s.size))
		if s.now.Sub(s.cycleStamp) > s.probeWait || s.roundsSinceProbe >= rounds {
			s.enterRefill()
			return
		}
		if s.state == probeDown && s.inFlight <= s.withHeadroom() && s.inFlight <= s.inflightTarget(100) {
			s.state = probeCruise
		}
	case probeRefill:
		if roundStart {
			s.probeSamples = true
			s.enterUp(rs.rate)
		}
	case probeUp:
		if s.prevHigh && s.inFlight >= s.flightLong {
			s.prevPrecaution = true
			s.prevHigh = false
			s.enterDown()
			return
		}
		if (s.limitedCurrent || s.limitedPrevious) && s.cwnd >= s.flightLong {
			s.fullNow = false
			s.fullBW = rs.rate
			s.plateauRounds = 0
		} else if s.fullNow {
			s.prevHigh = false
			s.enterDown()
		}
	}
}

func (s *Sender) updateMinRTT(rtt time.Duration) {
	expired := s.hasProbeStamp && s.now.Sub(s.probeStamp) > 5*time.Second
	if !s.hasProbeStamp || s.probeMin == 0 || rtt < s.probeMin || expired {
		s.probeMin = rtt
		s.probeStamp = s.now
		s.hasProbeStamp = true
	}
	if !s.hasMin || s.probeMin < s.minRTT || s.now.Sub(s.minStamp) > 10*time.Second {
		s.minRTT = s.probeMin
		s.minStamp = s.probeStamp
		s.hasMin = true
	}
	if expired && !s.idleRestart && s.state != probeRTT {
		s.priorCwnd = max(s.priorCwnd, s.cwnd)
		s.state = probeRTT
		s.probeTimer = false
		s.phase = acksStopping
		s.nextRound = s.sampler.totals.delivered
		s.probeCount++
	}
}

func (s *Sender) handleProbeRTT(rs rateSample, roundStart bool) {
	if s.state != probeRTT {
		return
	}
	_ = s.sampler.markAppLimited(congestion.ByteCount(s.inFlight)) // Controller-limited sampling, per ProbeRTT rules.
	if !s.probeTimer && s.inFlight <= s.probeWindow() {
		s.probeTimer = true
		s.probeDone = s.now.Add(200 * time.Millisecond)
		s.probeRound = s.round + 1
		s.nextRound = s.sampler.totals.delivered
	} else if s.probeTimer && s.round >= s.probeRound && s.now >= s.probeDone {
		s.exitProbeRTT()
	}
}

func (s *Sender) exitProbeRTT() {
	s.probeStamp = s.now
	s.hasProbeStamp = true
	s.cwnd = max(s.cwnd, s.priorCwnd)
	s.bwShort = unlimited
	s.flightShort = unlimited
	if s.fullReached {
		s.enterDown()
		s.state = probeCruise
	} else {
		s.state = startup
	}
}

func (s *Sender) updateAggregation(acked uint64) {
	expected := uint64(0)
	if s.aggValid {
		expected = durationBytes(s.bandwidth(), s.now.Sub(s.aggStamp))
	}
	if !s.aggValid || s.aggDelivered <= expected {
		s.aggStamp = s.now
		s.aggDelivered = 0
		s.aggValid = true
		expected = 0
	}
	s.aggDelivered = addBounded(s.aggDelivered, acked)
	extra := min(s.cwnd, s.aggDelivered-min(s.aggDelivered, expected))
	index := s.round % uint64(len(s.aggSlots))
	slot := &s.aggSlots[index]
	if !slot.valid || slot.round != s.round {
		*slot = aggregateSlot{round: s.round, valid: true}
	}
	slot.value = max(slot.value, extra)
	s.extraAcked = 0
	window := uint64(1)
	if s.fullReached {
		window = 10
	}
	for _, v := range s.aggSlots {
		if v.valid && s.round >= v.round && s.round-v.round < window {
			s.extraAcked = max(s.extraAcked, v.value)
		}
	}
}

func (s *Sender) probingState() bool { return s.state >= probeDown && s.state <= probeUp }
func (s *Sender) accelerating() bool {
	return s.state == startup || s.state == probeRefill || s.state == probeUp
}
func (s *Sender) floor() uint64        { return 4 * s.size }
func (s *Sender) maximum() uint64      { return uint64(congestion.MaxCongestionWindowPackets) * s.size }
func (s *Sender) maxBandwidth() uint64 { return max(s.bwCurrent, s.bwPrevious) }
func (s *Sender) bandwidth() uint64    { return min(s.maxBandwidth(), s.bwShort) }
func (s *Sender) bdp(gain uint64) uint64 {
	if !s.hasMin {
		return s.initial
	}
	return mulDiv(durationBytes(s.bandwidth(), s.minRTT), gain, 100)
}

func (s *Sender) inflightTarget(gain uint64) uint64 {
	result := max(s.bdp(gain), s.floor(), mulDiv(s.quantum, 3, 1))
	if s.state == probeUp {
		result = addBounded(result, 2*s.size)
	}
	return min(result, s.maximum())
}

func (s *Sender) withHeadroom() uint64 {
	if s.flightLong == unlimited {
		return unlimited
	}
	return max(s.floor(), s.flightLong-min(s.flightLong, max(s.size, mulDiv(s.flightLong, s.tuning.headroomPercent, 100))))
}
func (s *Sender) probeWindow() uint64 { return max(s.floor(), s.bdp(50)) }
func (s *Sender) updateQuantum()      { s.quantum = max(2*s.size, min(uint64(65536), s.rate/1000)) }
func (s *Sender) burst() uint64 {
	return max(s.quantum, durationBytes(s.rate, congestion.MinPacingDelay))
}

func (s *Sender) updateControls(acked uint64) {
	pacingGain, cwndGain := uint64(100), s.tuning.cwndGain
	switch s.state {
	case startup:
		pacingGain = s.tuning.startupPacingGain
	case drain:
		pacingGain = 50
	case probeDown:
		pacingGain = 90
	case probeUp:
		pacingGain = s.tuning.probeUpPacingGain
		cwndGain = s.tuning.probeUpCwndGain
	case probeRTT:
		cwndGain = 50
	}
	if bw := s.bandwidth(); bw > 0 {
		rate := max(1, mulDiv(mulDiv(bw, pacingGain, 100), 99, 100))
		if s.fullReached || rate > s.rate {
			s.rate = rate
		}
	}
	s.updateQuantum()
	cap := max(s.floor(), mulDiv(s.quantum, 3, 1), addBounded(s.bdp(cwndGain), s.extraAcked))
	if s.state == probeUp {
		cap = addBounded(cap, 2*s.size)
	}
	if s.fullReached {
		s.cwnd = min(addBounded(s.cwnd, acked), cap)
	} else if s.cwnd < cap || s.sampler.totals.delivered < s.initial {
		s.cwnd = addBounded(s.cwnd, acked)
	}
	s.cwnd = max(s.floor(), s.cwnd)
	if s.state == probeRTT {
		s.cwnd = min(s.cwnd, s.probeWindow())
	}
	bound := s.flightShort
	if s.probingState() {
		if s.state == probeCruise {
			bound = min(bound, s.withHeadroom())
		} else {
			bound = min(bound, s.flightLong)
		}
	}
	if s.state == probeRTT {
		bound = min(bound, s.withHeadroom())
	}
	s.cwnd = min(s.cwnd, max(s.floor(), bound), s.maximum())
}

func (s *Sender) Snapshot() Snapshot {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

func (s *Sender) snapshotLocked() Snapshot {
	return Snapshot{
		Profile: s.profile,
		State:   s.state.String(), Round: s.round, Bandwidth: s.maxBandwidth(), PacingRate: s.rate, Cwnd: s.cwnd, InFlight: s.inFlight,
		InflightLongterm: s.flightLong, InflightShortterm: s.flightShort, MinRTT: s.minRTT, FullBandwidth: s.fullReached,
		ProbeRTTCount: s.probeCount, SamplingErrors: s.faults, UnknownACKs: s.unknown, ECNEvents: s.ceCount, UndoCount: s.undoCount, PathResets: s.resets,
	}
}

func (s *Sender) trace() {
	if !s.debug {
		return
	}
	if s.debugStarted && s.debugState == s.state && s.now.Sub(s.debugStamp) < time.Second {
		return
	}
	s.debugStarted = true
	s.debugStamp = s.now
	s.debugState = s.state
	data, _ := json.Marshal(s.snapshotLocked())
	fmt.Fprintf(os.Stderr, "bbr3 snapshot %s\n", data)
}
