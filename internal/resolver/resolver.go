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
	cache    *cache.Cache
	upstream *upstream.Manager
	metrics  *metrics.Metrics
	limiter  chan struct{}
	log      logging.Logger
	timeout  time.Duration
}

func New(cfg config.Config, upstream *upstream.Manager, log logging.Logger, metrics *metrics.Metrics) *Resolver {
	var limiter chan struct{}
	if cfg.RateLimit.MaxInFlight > 0 {
		limiter = make(chan struct{}, cfg.RateLimit.MaxInFlight)
	}
	return &Resolver{
		cache:    cache.New(cfg.Cache),
		upstream: upstream,
		metrics:  metrics,
		limiter:  limiter,
		log:      log,
		timeout:  cfg.Timeouts.Upstream,
	}
}

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

// Resolve handles a single DNS request.
func (r *Resolver) Resolve(ctx context.Context, req *dns.Msg) (*dns.Msg, bool, error) {
	if len(req.Question) == 0 {
		return nil, false, errors.New("empty question")
	}

	ensureEDNS(req)

	key := cache.KeyFromQuestion(req.Question[0])
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
	if hit && r.metrics != nil {
		r.metrics.RecordCacheHit()
	} else if r.metrics != nil {
		r.metrics.RecordCacheMiss()
	}

	// Keep request ID for client compatibility.
	resp.Id = req.Id
	return resp, hit, nil
}

func ensureEDNS(msg *dns.Msg) {
	if msg.IsEdns0() != nil {
		return
	}
	opt := &dns.OPT{Hdr: dns.RR_Header{Name: ".", Rrtype: dns.TypeOPT}}
	opt.SetUDPSize(dns.DefaultMsgSize)
	msg.Extra = append(msg.Extra, opt)
}
