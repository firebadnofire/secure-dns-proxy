// Package cache implements DNS response caching with TTL handling and request
// coalescing.
package cache

import (
	"context"
	"sync"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/singleflight"

	"archuser.org/secure-dns-proxy/internal/config"
)

// entry is a single cached response plus metadata.
type entry struct {
	// msg is the cached DNS response.
	msg *dns.Msg
	// expires indicates when the entry becomes stale.
	expires time.Time
	// negative tracks NXDOMAIN-like responses for TTL calculation.
	negative bool
}

// Cache implements TTL-based positive and negative caching with request
// coalescing to avoid duplicate upstream lookups.
type Cache struct {
	// cfg contains cache behavior toggles and TTL defaults.
	cfg config.CacheConfig

	// mu protects entries and eviction order.
	mu      sync.Mutex
	entries map[string]entry
	order   []string

	// group coalesces concurrent requests for the same key.
	group singleflight.Group
}

// New constructs a new cache from configuration.
func New(cfg config.CacheConfig) *Cache {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 1
	}
	return &Cache{cfg: cfg, entries: make(map[string]entry)}
}

// UpdateConfig applies the provided configuration without clearing cache entries.
// If the cache is now oversized, it evicts from the front of the FIFO order.
func (c *Cache) UpdateConfig(cfg config.CacheConfig) {
	if cfg.Capacity <= 0 {
		cfg.Capacity = 1
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	c.cfg = cfg
	if len(c.entries) <= c.cfg.Capacity {
		return
	}

	excess := len(c.entries) - c.cfg.Capacity
	if excess > len(c.order) {
		excess = len(c.order)
	}
	for i := 0; i < excess; i++ {
		key := c.order[i]
		delete(c.entries, key)
	}
	c.order = c.order[excess:]
}

// KeyFromQuestion returns a stable cache key for the DNS question.
// It includes the name, type, and class so distinct queries do not collide.
func KeyFromQuestion(q dns.Question) string {
	return q.Name + "|" + dns.TypeToString[q.Qtype] + "|" + dns.ClassToString[q.Qclass]
}

// Get returns a cached response if available and not expired.
func (c *Cache) Get(key string) (*dns.Msg, bool) {
	if !c.cfg.Enabled {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	ent, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(ent.expires) {
		delete(c.entries, key)
		return nil, false
	}
	return ent.msg.Copy(), true
}

// Set inserts a response into the cache.
func (c *Cache) Set(key string, msg *dns.Msg, ttl time.Duration, negative bool) {
	if !c.cfg.Enabled || ttl <= 0 {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.cfg.Capacity {
		// simple FIFO eviction to limit state
		oldestKey := c.order[0]
		c.order = c.order[1:]
		delete(c.entries, oldestKey)
	}

	c.entries[key] = entry{msg: msg.Copy(), expires: time.Now().Add(ttl), negative: negative}
	c.order = append(c.order, key)
}

// Fetch returns a cached response or executes the loader once for concurrent
// callers, then stores the result using the computed TTL.
func (c *Cache) Fetch(ctx context.Context, key string, loader func(context.Context) (*dns.Msg, error)) (*dns.Msg, bool, error) {
	if msg, ok := c.Get(key); ok {
		return msg, true, nil
	}

	res, err, _ := c.group.Do(key, func() (interface{}, error) {
		return loader(ctx)
	})
	if err != nil {
		return nil, false, err
	}
	msg := res.(*dns.Msg)

	ttl, negative := c.ttlForMessage(msg)
	c.Set(key, msg, ttl, negative)
	return msg.Copy(), false, nil
}

// ttlForMessage determines the cache TTL for the provided DNS response and
// returns whether the response is negative.
func (c *Cache) ttlForMessage(msg *dns.Msg) (time.Duration, bool) {
	if msg == nil {
		return 0, false
	}
	negative := len(msg.Answer) == 0 && msg.Rcode != dns.RcodeSuccess

	var ttlSeconds uint32
	if negative {
		ttlSeconds = uint32(c.cfg.NegativeTTL.Duration().Seconds())
		for _, ns := range msg.Ns {
			if soa, ok := ns.(*dns.SOA); ok {
				ttlSeconds = soa.Minttl
				break
			}
		}
	} else {
		ttlSeconds = uint32(c.cfg.DefaultTTL.Duration().Seconds())
		if c.cfg.RespectRecordTTL {
			ttlSeconds = minTTL(msg.Answer)
		}
	}
	return time.Duration(ttlSeconds) * time.Second, negative
}

// minTTL returns the smallest TTL among a list of DNS resource records.
func minTTL(rrs []dns.RR) uint32 {
	if len(rrs) == 0 {
		return 0
	}
	ttl := rrs[0].Header().Ttl
	for _, rr := range rrs[1:] {
		if rr.Header().Ttl < ttl {
			ttl = rr.Header().Ttl
		}
	}
	return ttl
}
