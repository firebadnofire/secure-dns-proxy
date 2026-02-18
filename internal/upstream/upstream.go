// Package upstream defines abstractions and shared helpers for DNS upstream
// protocols (DoH, DoT, DoQ, and plain DNS).
package upstream

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ErrCircuitOpen signals that an upstream is in cooldown after failures.
var ErrCircuitOpen = errors.New("upstream temporarily unavailable")

// Upstream provides a unified interface for communicating with DNS upstreams.
type Upstream interface {
	// ID identifies the upstream instance for logging and metrics.
	ID() string
	// Exchange performs a DNS query against the upstream.
	Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error)
	// Healthy reports whether the upstream is currently eligible for use.
	Healthy() bool
	// Probe performs a lightweight health check query.
	Probe(ctx context.Context, msg *dns.Msg) error
	// RecordSuccess marks the upstream as healthy after a successful exchange.
	RecordSuccess()
	// RecordFailure updates failure counters and triggers backoff if needed.
	RecordFailure(err error)
}

// healthState tracks failures and cooldown for a single upstream.
type healthState struct {
	mu sync.Mutex

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

// healthy returns true when the upstream is usable or cooldown has expired.
func (h *healthState) healthy() bool {
	h.mu.Lock()
	defer h.mu.Unlock()

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

// success resets failure counters after a successful exchange.
func (h *healthState) success() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.failures = 0
	h.backoffUntil = time.Time{}
}

// failure increments failure counters and applies cooldown after thresholds.
func (h *healthState) failure() {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.failures++
	if h.failures >= h.maxFailures {
		h.backoffUntil = time.Now().Add(h.cooldown)
	}
}
