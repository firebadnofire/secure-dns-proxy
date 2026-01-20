// Package resolver coordinates cache usage, rate limiting, and upstream
// resolution for incoming DNS queries.
package resolver

import (
	"context"
	"errors"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/cache"
	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/upstream"
)

// Resolver performs caching, request coalescing, and upstream selection.
type Resolver struct {
	// cache stores recently resolved DNS answers.
	cache *cache.Cache
	// upstream chooses and queries upstream resolvers.
	upstream *upstream.Manager
	// metrics is optional instrumentation.
	metrics *metrics.Metrics
	// limiter is a semaphore that caps concurrent upstream lookups.
	limiter chan struct{}
	// log emits structured logs for resolver actions.
	log logging.Logger
	// timeout bounds total upstream round trips.
	timeout time.Duration
}

// New builds a Resolver using the provided configuration and dependencies.
func New(cfg config.Config, cacheInstance *cache.Cache, upstream *upstream.Manager, log logging.Logger, metrics *metrics.Metrics) *Resolver {
	var limiter chan struct{}
	if cfg.RateLimit.MaxInFlight > 0 {
		// Buffered channel acts as a semaphore.
		limiter = make(chan struct{}, cfg.RateLimit.MaxInFlight)
	}
	if cacheInstance == nil {
		cacheInstance = cache.New(cfg.Cache)
	}
	return &Resolver{
		cache:    cacheInstance,
		upstream: upstream,
		metrics:  metrics,
		limiter:  limiter,
		log:      log,
		timeout:  cfg.Timeouts.Upstream.Duration(),
	}
}

// acquireLimiter blocks until a slot is available or the context cancels.
func (r *Resolver) acquireLimiter(ctx context.Context) error {
	if r.limiter == nil {
		return nil
	}
	select {
	case r.limiter <- struct{}{}:
		if r.metrics != nil {
			r.metrics.IncInFlight()
		}
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// releaseLimiter frees a slot and updates metrics.
func (r *Resolver) releaseLimiter() {
	if r.limiter == nil {
		return
	}
	select {
	case <-r.limiter:
		if r.metrics != nil {
			r.metrics.DecInFlight()
		}
	default:
	}
}

// Resolve handles a single DNS request, applying cache and rate limiting.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, bool, error) {
	if len(req.Question) == 0 {
		return nil, false, errors.New("empty question")
	}

	// Ensure the request advertises EDNS0 so larger responses are permitted.
	ensureEDNS(req)

	key := cache.KeyFromQuestion(req.Question[0])
	// loader executes the upstream request when cache miss occurs.
	loader := func(ctx context.Context) (*dns.Msg, error) {
		if err := r.acquireLimiter(ctx); err != nil {
			return nil, err
		}
		defer r.releaseLimiter()

		ctx, cancel := context.WithTimeout(ctx, r.timeout)
		defer cancel()

		resp, err := r.upstream.Resolve(ctx, req)
		return resp, err
	}

	resp, hit, err := r.cache.Fetch(ctx, key, loader)
	if err != nil {
		return nil, false, err
	}
	// Record cache outcomes when metrics are enabled.
	if hit && r.metrics != nil {
		r.metrics.RecordCacheHit()
	} else if r.metrics != nil {
		r.metrics.RecordCacheMiss()
	}

	// Keep request ID for client compatibility.
	resp.Id = req.Id
	return resp, hit, nil
}

// ensureEDNS adds a default OPT record so the proxy can receive larger answers.
func ensureEDNS(msg *dns.Msg) {
	if msg.IsEdns0() != nil {
		return
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	msg.Extra = append(msg.Extra, opt)
}
