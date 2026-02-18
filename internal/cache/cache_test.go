package cache

import (
	"fmt"
	"testing"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

func TestSetUpdateDoesNotDuplicateOrderAndEvictsFIFO(t *testing.T) {
	cfg := config.CacheConfig{
		Enabled:          true,
		Capacity:         2,
		DefaultTTL:       config.Duration(30 * time.Second),
		NegativeTTL:      config.Duration(10 * time.Second),
		RespectRecordTTL: true,
	}
	c := New(cfg)

	msg := testARecordResponse(t, 60)
	c.Set("a", msg, time.Minute, false)
	c.Set("a", msg, time.Minute, false)
	c.Set("b", msg, time.Minute, false)
	c.Set("c", msg, time.Minute, false)

	c.mu.Lock()
	defer c.mu.Unlock()

	if _, ok := c.entries["a"]; ok {
		t.Fatalf("expected key 'a' to be evicted after FIFO overflow")
	}
	if _, ok := c.entries["b"]; !ok {
		t.Fatalf("expected key 'b' to remain cached")
	}
	if _, ok := c.entries["c"]; !ok {
		t.Fatalf("expected key 'c' to remain cached")
	}
	if c.order.Len() != 2 {
		t.Fatalf("unexpected order length: got %d, want 2", c.order.Len())
	}
}

func TestGetRemovesExpiredOrderEntry(t *testing.T) {
	cfg := config.CacheConfig{
		Enabled:          true,
		Capacity:         8,
		DefaultTTL:       config.Duration(30 * time.Second),
		NegativeTTL:      config.Duration(10 * time.Second),
		RespectRecordTTL: true,
	}
	c := New(cfg)

	msg := testARecordResponse(t, 60)
	c.Set("expired", msg, time.Minute, false)

	c.mu.Lock()
	c.entries["expired"].expires = time.Now().Add(-time.Second)
	c.mu.Unlock()

	if _, ok := c.Get("expired"); ok {
		t.Fatalf("expected expired entry miss")
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) != 0 {
		t.Fatalf("expected entries map to be empty, got %d entries", len(c.entries))
	}
	if c.order.Len() != 0 {
		t.Fatalf("expected order list to be empty, got %d", c.order.Len())
	}
}

func testARecordResponse(t *testing.T, ttl uint32) *dns.Msg {
	t.Helper()
	rr, err := dns.NewRR(fmt.Sprintf("example.org. %d IN A 1.1.1.1", ttl))
	if err != nil {
		t.Fatalf("failed to build RR: %v", err)
	}
	msg := new(dns.Msg)
	msg.SetQuestion("example.org.", dns.TypeA)
	msg.Rcode = dns.RcodeSuccess
	msg.Answer = []dns.RR{rr}
	return msg
}
