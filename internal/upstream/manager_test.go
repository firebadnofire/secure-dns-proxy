package upstream

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stubUpstream struct {
	id      string
	healthy bool
	resp    *dns.Msg
	err     error
	delay   time.Duration
}

func (s *stubUpstream) ID() string { return s.id }

func (s *stubUpstream) Exchange(ctx context.Context, _ *dns.Msg) (*dns.Msg, error) {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if s.err != nil {
		return nil, s.err
	}
	if s.resp == nil {
		return nil, errors.New("missing response")
	}
	return s.resp.Copy(), nil
}

func (s *stubUpstream) Healthy() bool                         { return s.healthy }
func (s *stubUpstream) Probe(context.Context, *dns.Msg) error { return nil }
func (s *stubUpstream) RecordSuccess()                        {}
func (s *stubUpstream) RecordFailure(error)                   {}

func TestRaceReturnsWithoutWaitingForSkippedUnhealthyUpstreams(t *testing.T) {
	success := new(dns.Msg)
	success.SetQuestion("example.org.", dns.TypeA)
	success.Answer = []dns.RR{&dns.A{
		Hdr: dns.RR_Header{Name: "example.org.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
		A:   []byte{1, 1, 1, 1},
	}}

	mgr := &Manager{
		upstreams: []Upstream{
			&stubUpstream{id: "u1", healthy: false, err: ErrCircuitOpen},
			&stubUpstream{id: "u2", healthy: true, resp: success, delay: 10 * time.Millisecond},
			&stubUpstream{id: "u3", healthy: false, err: ErrCircuitOpen},
		},
		fanout:           3,
		healthActionLast: make(map[string]time.Time),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	start := time.Now()
	resp, err := mgr.race(ctx, req)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected success, got error: %v", err)
	}
	if resp == nil || len(resp.Answer) == 0 {
		t.Fatalf("expected response with answers")
	}
	if elapsed > 150*time.Millisecond {
		t.Fatalf("race took too long: %s", elapsed)
	}
}

func TestRaceReturnsNoHealthyUpstreamsImmediately(t *testing.T) {
	mgr := &Manager{
		upstreams: []Upstream{
			&stubUpstream{id: "u1", healthy: false, err: ErrCircuitOpen},
			&stubUpstream{id: "u2", healthy: false, err: ErrCircuitOpen},
		},
		fanout:           2,
		healthActionLast: make(map[string]time.Time),
	}

	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()

	start := time.Now()
	_, err := mgr.race(ctx, req)
	elapsed := time.Since(start)

	if err == nil || !strings.Contains(err.Error(), "no healthy upstreams") {
		t.Fatalf("expected no healthy upstreams error, got: %v", err)
	}
	if elapsed > 100*time.Millisecond {
		t.Fatalf("expected fast failure, got %s", elapsed)
	}
}
