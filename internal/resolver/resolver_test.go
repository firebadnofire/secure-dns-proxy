package resolver

import (
	"context"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/cache"
	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/upstream"
)

func TestResolvePreservesNXDOMAINThroughCache(t *testing.T) {
	var upstreamCalls atomic.Int32

	mux := dns.NewServeMux()
	mux.HandleFunc(".", func(w dns.ResponseWriter, req *dns.Msg) {
		upstreamCalls.Add(1)
		resp := new(dns.Msg)
		resp.SetRcode(req, dns.RcodeNameError)
		resp.Ns = []dns.RR{
			&dns.SOA{
				Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
				Ns:      "ns1.example.",
				Mbox:    "hostmaster.example.",
				Serial:  1,
				Refresh: 60,
				Retry:   60,
				Expire:  60,
				Minttl:  33,
			},
		}
		_ = w.WriteMsg(resp)
	})

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("ListenPacket() error = %v", err)
	}
	defer pc.Close()

	server := &dns.Server{PacketConn: pc, Handler: mux}
	go func() {
		_ = server.ActivateAndServe()
	}()
	defer func() {
		_ = server.Shutdown()
	}()

	addr := pc.LocalAddr().(*net.UDPAddr)
	cfg := config.Default()
	cfg.UpstreamGroups.DNS = []string{net.JoinHostPort("127.0.0.1", strconv.Itoa(addr.Port))}
	cfg.Cache = config.CacheConfig{
		Enabled:          true,
		Capacity:         8,
		NegativeTTL:      config.Duration(20 * time.Second),
		RespectRecordTTL: true,
	}
	cfg.HealthChecks.Enabled = false

	mgr, _, err := upstream.BuildManager(cfg, logging.New(logging.Level("error")), nil)
	if err != nil {
		t.Fatalf("BuildManager() error = %v", err)
	}

	res := New(cfg, cache.New(cfg.Cache), mgr, logging.New(logging.Level("error")), nil)

	req := new(dns.Msg)
	req.SetQuestion("missing.example.", dns.TypeA)
	req.Id = 100

	first, hit, err := res.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve() first error = %v", err)
	}
	if hit {
		t.Fatal("first Resolve() should be a cache miss")
	}
	if first.Rcode != dns.RcodeNameError {
		t.Fatalf("first Resolve() rcode = %d, want NXDOMAIN", first.Rcode)
	}
	if len(first.Ns) != 1 {
		t.Fatalf("first Resolve() authority count = %d, want 1", len(first.Ns))
	}

	req.Id = 101
	second, hit, err := res.Resolve(context.Background(), req)
	if err != nil {
		t.Fatalf("Resolve() second error = %v", err)
	}
	if !hit {
		t.Fatal("second Resolve() should be a cache hit")
	}
	if second.Rcode != dns.RcodeNameError {
		t.Fatalf("second Resolve() rcode = %d, want NXDOMAIN", second.Rcode)
	}
	if second.Id != 101 {
		t.Fatalf("second Resolve() id = %d, want 101", second.Id)
	}
	soa, ok := second.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("second Resolve() authority[0] = %T, want *dns.SOA", second.Ns[0])
	}
	if soa.Minttl != 33 {
		t.Fatalf("second Resolve() SOA minttl = %d, want 33", soa.Minttl)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream calls = %d, want 1", got)
	}
}
