package upstream

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/miekg/dns"
)

type stubUpstream struct {
	id      string
	healthy bool
	resp    *dns.Msg
	err     error
	calls   int
}

func (s *stubUpstream) ID() string { return s.id }

func (s *stubUpstream) Exchange(_ context.Context, _ *dns.Msg) (*dns.Msg, error) {
	s.calls++
	return s.resp, s.err
}

func (s *stubUpstream) Healthy() bool                             { return s.healthy }
func (s *stubUpstream) Probe(_ context.Context, _ *dns.Msg) error { return s.err }
func (s *stubUpstream) RecordSuccess()                            {}
func (s *stubUpstream) RecordFailure(_ error)                     {}

func TestRoundRobinFallsBackAfterFailure(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.org.", dns.TypeA)
	okResp := new(dns.Msg)
	okResp.SetReply(req)

	fail := &stubUpstream{id: "fail", healthy: true, err: errors.New("first failed")}
	ok := &stubUpstream{id: "ok", healthy: true, resp: okResp}

	// rrCounter starts at 0; with 2 upstreams, round-robin starts at index 1 first.
	mgr := &Manager{upstreams: []Upstream{ok, fail}}

	resp, err := mgr.roundRobin(context.Background(), req)
	if err != nil {
		t.Fatalf("roundRobin() error = %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("roundRobin() returned invalid response: %#v", resp)
	}
	if fail.calls != 1 {
		t.Fatalf("expected failing upstream called once, got %d", fail.calls)
	}
	if ok.calls != 1 {
		t.Fatalf("expected fallback upstream called once, got %d", ok.calls)
	}
}

func TestRoundRobinReturnsLastError(t *testing.T) {
	wantErr := errors.New("upstream failed")
	up := &stubUpstream{id: "doq", healthy: true, err: wantErr}
	mgr := &Manager{upstreams: []Upstream{up}}

	_, err := mgr.roundRobin(context.Background(), new(dns.Msg))
	if !errors.Is(err, wantErr) {
		t.Fatalf("roundRobin() error = %v, want %v", err, wantErr)
	}
}

func TestRaceSkipsUnhealthyWithoutBlocking(t *testing.T) {
	req := new(dns.Msg)
	req.SetQuestion("example.net.", dns.TypeA)
	okResp := new(dns.Msg)
	okResp.SetReply(req)

	unhealthy := &stubUpstream{id: "bad", healthy: false}
	ok := &stubUpstream{id: "ok", healthy: true, resp: okResp}

	mgr := &Manager{
		upstreams: []Upstream{unhealthy, ok},
		fanout:    2,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	resp, err := mgr.race(ctx, req)
	if err != nil {
		t.Fatalf("race() error = %v", err)
	}
	if resp == nil || resp.Rcode != dns.RcodeSuccess {
		t.Fatalf("race() returned invalid response: %#v", resp)
	}
	if ok.calls != 1 {
		t.Fatalf("expected healthy upstream called once, got %d", ok.calls)
	}
}
