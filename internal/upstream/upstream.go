package upstream

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"
)

var ErrCircuitOpen = errors.New("upstream temporarily unavailable")

// Upstream provides a unified interface for communicating with DNS upstreams.
type Upstream interface {
	ID() string
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	Healthy() bool
	Probe(ctx context.Context, msg *dns.Msg) error
	RecordSuccess()
	RecordFailure(err error)
}

type healthState struct {
	maxFailures int
	cooldown    time.Duration

	failures     int
	backoffUntil time.Time
}

func newHealthState(maxFailures int, cooldown time.Duration) healthState {
	if maxFailures <= 0 {
		maxFailures = 3
	}
	if cooldown <= 0 {
		cooldown = 2 * time.Second
	}
	return healthState{maxFailures: maxFailures, cooldown: cooldown}
}

func (h *healthState) healthy() bool {
	if h.backoffUntil.IsZero() {
		return true
	}
	if time.Now().After(h.backoffUntil) {
		h.failures = 0
		h.backoffUntil = time.Time{}
		return true
	}
	return false
}

func (h *healthState) success() {
	h.failures = 0
	h.backoffUntil = time.Time{}
}

func (h *healthState) failure() {
	h.failures++
	if h.failures >= h.maxFailures {
		h.backoffUntil = time.Now().Add(h.cooldown)
	}
}

func recordFailure(recordHealth bool, err error, record func(error)) {
	if !recordHealth || err == nil {
		return
	}
	if errors.Is(err, context.Canceled) {
		return
	}
	record(err)
}
