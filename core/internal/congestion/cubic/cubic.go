// SPDX-License-Identifier: MIT
// Adapted from quic-go internal/congestion/cubic.go (quic-go authors & Google).
// Copyright (c) 2016 the quic-go authors & Google, Inc.
// See LICENSE-THIRD-PARTY.md. Fork-specific changes are licensed under MIT-0.

package cubic

import (
	"math"
	"time"

	"github.com/apernet/quic-go/congestion"
	"github.com/apernet/quic-go/monotime"
)

const (
	cubicBeta = 0.7
	cubicC    = 0.4
	tcpAlpha  = 3 * (1 - cubicBeta) / (1 + cubicBeta)
)

// cubic implements the upstream CUBIC growth / TCP-friendly region and fast
// convergence. All windows are bytes; unlike upstream's dormant CUBIC branch,
// the curve uses the actual (possibly PMTU-updated) datagram size.
type cubic struct {
	maxDatagramSize congestion.ByteCount
	epoch           monotime.Time
	lastMax         congestion.ByteCount
	origin          float64
	timeToOrigin    float64
	tcpWindow       float64
}

func (c *cubic) afterLoss(window congestion.ByteCount) congestion.ByteCount {
	if window+c.maxDatagramSize < c.lastMax {
		c.lastMax = window * 17 / 20
	} else {
		c.lastMax = window
	}
	c.epoch = 0
	return window * 7 / 10
}

func (c *cubic) afterAck(acked, window congestion.ByteCount, minRTT time.Duration, now monotime.Time) congestion.ByteCount {
	if acked <= 0 {
		return window
	}
	mss := float64(c.maxDatagramSize)
	if c.epoch.IsZero() {
		c.epoch = now
		c.tcpWindow = float64(window)
		c.timeToOrigin = 0
		c.origin = float64(window)
		if c.lastMax > window {
			c.origin = float64(c.lastMax)
			c.timeToOrigin = math.Cbrt(float64(c.lastMax-window) / (cubicC * mss))
		}
	}
	elapsed := max(0, now.Sub(c.epoch).Seconds()+minRTT.Seconds())
	offset := elapsed - c.timeToOrigin
	target := c.origin + cubicC*mss*offset*offset*offset
	// Bound before converting to ByteCount, including after very long idle times.
	target = min(target, float64(window)+float64(acked)/2)
	c.tcpWindow += tcpAlpha * float64(acked) * mss / c.tcpWindow
	return max(window, congestion.ByteCount(max(target, c.tcpWindow)))
}

func (c *cubic) setMaxDatagramSize(size congestion.ByteCount) {
	c.maxDatagramSize = size
	c.epoch = 0 // Rebase the curve, keeping byte-sized window history.
}

func (c *cubic) reset() {
	*c = cubic{maxDatagramSize: c.maxDatagramSize}
}
