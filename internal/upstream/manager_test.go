package upstream

import (
	"context"
	"errors"
	"net"
	"testing"

	"github.com/miekg/dns"
)

// fakeUpstream is a minimal ResettableUpstream used for exercising Manager behavior.
type fakeUpstream struct {
	healthy     bool
	err         error
	resetCalled int
}

func (f *fakeUpstream) ID() string                            { return "fake" }
func (f *fakeUpstream) Healthy() bool                         { return f.healthy }
func (f *fakeUpstream) RecordSuccess()                        {}
func (f *fakeUpstream) RecordFailure(err error)               {}
func (f *fakeUpstream) Probe(context.Context, *dns.Msg) error { return f.err }
func (f *fakeUpstream) Reset()                                { f.resetCalled++; f.err = nil; f.healthy = true }
func (f *fakeUpstream) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if f.err != nil {
		return nil, f.err
	}
	resp := new(dns.Msg)
	resp.SetReply(msg)
	return resp, nil
}

func TestResolveRetriesAfterNetworkError(t *testing.T) {
	msg := new(dns.Msg)
	msg.SetQuestion("example.com.", dns.TypeA)

	upstream := &fakeUpstream{healthy: true, err: &net.DNSError{Err: "timeout", IsTimeout: true}}
	mgr := &Manager{upstreams: []Upstream{upstream}, policy: "sequential"}

	resp, err := mgr.Resolve(context.Background(), msg)
	if err != nil {
		t.Fatalf("expected retry to succeed after reset, got error: %v", err)
	}
	if resp == nil || len(resp.Question) == 0 {
		t.Fatalf("unexpected empty response after retry: %+v", resp)
	}
	if upstream.resetCalled != 1 {
		t.Fatalf("expected reset to be invoked once, got %d", upstream.resetCalled)
	}
}

func TestHandleNoHealthyWrapsError(t *testing.T) {
	mgr := &Manager{}
	lastErr := errors.New("dial failed")
	err, retry := mgr.handleNoHealthy(lastErr, false)
	if !retry {
		t.Fatalf("expected retry when no healthy upstreams")
	}
	if err == nil || !errors.Is(err, lastErr) {
		t.Fatalf("expected error to wrap lastErr, got %v", err)
	}
}
