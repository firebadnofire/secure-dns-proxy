package cache

import (
	"context"
	"testing"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

func TestFetchCachesNXDOMAINWithAuthoritySOA(t *testing.T) {
	c := New(config.CacheConfig{
		Enabled:          true,
		Capacity:         4,
		NegativeTTL:      config.Duration(30 * time.Second),
		RespectRecordTTL: true,
	})

	req := new(dns.Msg)
	req.SetQuestion("missing.example.", dns.TypeA)

	nxdomain := new(dns.Msg)
	nxdomain.SetRcode(req, dns.RcodeNameError)
	nxdomain.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
			Ns:      "ns1.example.",
			Mbox:    "hostmaster.example.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  60,
			Minttl:  42,
		},
	}

	loads := 0
	key := KeyFromQuestion(req.Question[0])

	first, hit, err := c.Fetch(context.Background(), key, func(context.Context) (*dns.Msg, error) {
		loads++
		return nxdomain, nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if hit {
		t.Fatal("first Fetch() should be a cache miss")
	}
	if first.Rcode != dns.RcodeNameError {
		t.Fatalf("first Fetch() rcode = %d, want NXDOMAIN", first.Rcode)
	}
	if len(first.Ns) != 1 {
		t.Fatalf("first Fetch() authority count = %d, want 1", len(first.Ns))
	}

	second, hit, err := c.Fetch(context.Background(), key, func(context.Context) (*dns.Msg, error) {
		loads++
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Fetch() cached error = %v", err)
	}
	if !hit {
		t.Fatal("second Fetch() should be a cache hit")
	}
	if second.Rcode != dns.RcodeNameError {
		t.Fatalf("cached Fetch() rcode = %d, want NXDOMAIN", second.Rcode)
	}
	soa, ok := second.Ns[0].(*dns.SOA)
	if !ok {
		t.Fatalf("cached Fetch() authority[0] = %T, want *dns.SOA", second.Ns[0])
	}
	if soa.Minttl != 42 {
		t.Fatalf("cached SOA minttl = %d, want 42", soa.Minttl)
	}
	if loads != 1 {
		t.Fatalf("loader called %d times, want 1", loads)
	}
}

func TestFetchCachesNODATA(t *testing.T) {
	c := New(config.CacheConfig{
		Enabled:          true,
		Capacity:         4,
		NegativeTTL:      config.Duration(30 * time.Second),
		RespectRecordTTL: true,
	})

	req := new(dns.Msg)
	req.SetQuestion("empty.example.", dns.TypeAAAA)

	nodata := new(dns.Msg)
	nodata.SetReply(req)
	nodata.Answer = nil
	nodata.Ns = []dns.RR{
		&dns.SOA{
			Hdr:     dns.RR_Header{Name: "example.", Rrtype: dns.TypeSOA, Class: dns.ClassINET, Ttl: 120},
			Ns:      "ns1.example.",
			Mbox:    "hostmaster.example.",
			Serial:  1,
			Refresh: 60,
			Retry:   60,
			Expire:  60,
			Minttl:  21,
		},
	}

	loads := 0
	key := KeyFromQuestion(req.Question[0])
	_, hit, err := c.Fetch(context.Background(), key, func(context.Context) (*dns.Msg, error) {
		loads++
		return nodata, nil
	})
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if hit {
		t.Fatal("first Fetch() should be a cache miss")
	}

	cached, hit, err := c.Fetch(context.Background(), key, func(context.Context) (*dns.Msg, error) {
		loads++
		return nil, nil
	})
	if err != nil {
		t.Fatalf("Fetch() cached error = %v", err)
	}
	if !hit {
		t.Fatal("second Fetch() should be a cache hit")
	}
	if cached.Rcode != dns.RcodeSuccess {
		t.Fatalf("cached Fetch() rcode = %d, want NOERROR", cached.Rcode)
	}
	if len(cached.Answer) != 0 {
		t.Fatalf("cached Fetch() answers = %d, want 0", len(cached.Answer))
	}
	if loads != 1 {
		t.Fatalf("loader called %d times, want 1", loads)
	}
}

func TestFetchDoesNotCacheSERVFAIL(t *testing.T) {
	c := New(config.CacheConfig{
		Enabled:          true,
		Capacity:         4,
		NegativeTTL:      config.Duration(30 * time.Second),
		RespectRecordTTL: true,
	})

	req := new(dns.Msg)
	req.SetQuestion("broken.example.", dns.TypeA)

	servfail := new(dns.Msg)
	servfail.SetRcode(req, dns.RcodeServerFailure)

	loads := 0
	key := KeyFromQuestion(req.Question[0])
	for i := 0; i < 2; i++ {
		_, hit, err := c.Fetch(context.Background(), key, func(context.Context) (*dns.Msg, error) {
			loads++
			return servfail, nil
		})
		if err != nil {
			t.Fatalf("Fetch() error = %v", err)
		}
		if hit {
			t.Fatalf("Fetch() call %d unexpectedly hit cache", i+1)
		}
	}
	if loads != 2 {
		t.Fatalf("loader called %d times, want 2", loads)
	}
}
