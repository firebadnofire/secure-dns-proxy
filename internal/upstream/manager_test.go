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
	called  int
}

func (s *stubUpstream) ID() string { return s.id }

func (s *stubUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	s.called++
	return s.resp, s.err
}

func (s *stubUpstream) Healthy() bool { return s.healthy }

func (s *stubUpstream) Probe(ctx context.Context, msg *dns.Msg) error { return nil }

func (s *stubUpstream) RecordSuccess()          {}
func (s *stubUpstream) RecordFailure(err error) {}

func TestRaceSkipsUnhealthyWithoutBlocking(t *testing.T) {
	success := &dns.Msg{}
	upstreams := []Upstream{
		&stubUpstream{id: "healthy-1", healthy: true, resp: success},
		&stubUpstream{id: "unhealthy", healthy: false, err: errors.New("should not run")},
		&stubUpstream{id: "healthy-2", healthy: true, err: context.DeadlineExceeded},
	}

	mgr := &Manager{policy: "race", fanout: 3, upstreams: upstreams}

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	query := new(dns.Msg)
	query.SetQuestion("example.com.", dns.TypeA)

	resp, err := mgr.Resolve(ctx, query)
	if err != nil {
		t.Fatalf("expected successful response, got error: %v", err)
	}
	if resp != success {
		t.Fatalf("expected response from healthy upstream, got %#v", resp)
	}

	if upstreams[1].(*stubUpstream).called != 0 {
		t.Fatalf("unhealthy upstream should not have been invoked")
	}
}

func TestRaceReturnsErrorWhenNoHealthyUpstreams(t *testing.T) {
	upstreams := []Upstream{
		&stubUpstream{id: "down-1", healthy: false, err: errors.New("down")},
		&stubUpstream{id: "down-2", healthy: false, err: errors.New("down")},
	}

	mgr := &Manager{policy: "race", fanout: 2, upstreams: upstreams}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	query := new(dns.Msg)
	query.SetQuestion("example.org.", dns.TypeA)

	if _, err := mgr.Resolve(ctx, query); err == nil {
		t.Fatalf("expected error when no healthy upstreams")
	}
}
