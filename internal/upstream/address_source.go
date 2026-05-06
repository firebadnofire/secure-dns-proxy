package upstream

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

type resolvedAddressSet struct {
	addrs       []string
	expiresAt   time.Time
	nextRefresh time.Time
	lastError   error
}

type addressSource struct {
	hostname string
	port     string
	strategy string
	static   bool

	mu    sync.RWMutex
	state resolvedAddressSet
	rr    atomic.Uint64
}

func newAddressSource(hostname, port, strategy string, ips []net.IP, static bool) (*addressSource, error) {
	if hostname == "" || port == "" {
		return nil, fmt.Errorf("address source requires hostname and port")
	}
	if strategy == "" {
		strategy = "failover"
	}
	src := &addressSource{hostname: hostname, port: port, strategy: strategy, static: static}
	if err := src.replace(ips, time.Time{}, time.Time{}, nil); err != nil {
		return nil, err
	}
	return src, nil
}

func (s *addressSource) replace(ips []net.IP, expiresAt, nextRefresh time.Time, lastErr error) error {
	if len(ips) == 0 {
		return fmt.Errorf("no addresses configured for %s", s.hostname)
	}
	addrs := make([]string, 0, len(ips))
	for _, ip := range ips {
		if ip == nil {
			return fmt.Errorf("invalid address for %s", s.hostname)
		}
		addrs = append(addrs, net.JoinHostPort(ip.String(), s.port))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state = resolvedAddressSet{
		addrs:       addrs,
		expiresAt:   expiresAt,
		nextRefresh: nextRefresh,
		lastError:   lastErr,
	}
	return nil
}

func (s *addressSource) markRefreshFailure(next time.Time, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.lastError = err
	s.state.nextRefresh = next
}

func (s *addressSource) snapshot() resolvedAddressSet {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return resolvedAddressSet{
		addrs:       append([]string(nil), s.state.addrs...),
		expiresAt:   s.state.expiresAt,
		nextRefresh: s.state.nextRefresh,
		lastError:   s.state.lastError,
	}
}

func (s *addressSource) due(now time.Time) bool {
	if s.static {
		return false
	}
	state := s.snapshot()
	if len(state.addrs) == 0 {
		return true
	}
	return !state.nextRefresh.IsZero() && !now.Before(state.nextRefresh)
}

func (s *addressSource) dialContext(ctx context.Context, network string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	switch s.strategy {
	case "race":
		conn, addr, err := raceDial(ctx, s.snapshot().addrs, func(raceCtx context.Context, target string) (net.Conn, error) {
			return dial(raceCtx, network, target)
		}, func(conn net.Conn) { _ = conn.Close() })
		if err == nil {
			s.promote(addr)
		}
		return conn, err
	case "round_robin":
		return s.dialSequential(ctx, network, dial, s.roundRobinOrder(), false)
	default:
		return s.dialSequential(ctx, network, dial, s.snapshot().addrs, true)
	}
}

func (s *addressSource) dialQUIC(ctx context.Context, dial func(context.Context, string) (quic.EarlyConnection, error)) (quic.EarlyConnection, error) {
	switch s.strategy {
	case "race":
		conn, addr, err := raceDial(ctx, s.snapshot().addrs, dial, func(conn quic.EarlyConnection) {
			_ = conn.CloseWithError(0, "race loser")
		})
		if err == nil {
			s.promote(addr)
		}
		return conn, err
	case "round_robin":
		return s.dialQUICSequential(ctx, dial, s.roundRobinOrder(), false)
	default:
		return s.dialQUICSequential(ctx, dial, s.snapshot().addrs, true)
	}
}

func (s *addressSource) exchangeDNS(ctx context.Context, msg *dns.Msg, timeout time.Duration, recordHealth func(string)) (*dns.Msg, error) {
	order := s.snapshot().addrs
	if s.strategy == "round_robin" {
		order = s.roundRobinOrder()
	}
	var lastErr error
	for _, addr := range order {
		client := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := client.ExchangeContext(ctx, msg, addr)
		if err == nil && resp != nil && resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.ExchangeContext(ctx, msg, addr)
		}
		if err == nil {
			if s.strategy != "round_robin" {
				s.promote(addr)
			}
			if recordHealth != nil {
				recordHealth(addr)
			}
			return resp, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses configured for %s", s.hostname)
	}
	return nil, lastErr
}

func (s *addressSource) dialSequential(ctx context.Context, network string, dial func(context.Context, string, string) (net.Conn, error), addrs []string, promote bool) (net.Conn, error) {
	var lastErr error
	for _, addr := range addrs {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			if promote {
				s.promote(addr)
			}
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses configured for %s", s.hostname)
	}
	return nil, lastErr
}

func (s *addressSource) dialQUICSequential(ctx context.Context, dial func(context.Context, string) (quic.EarlyConnection, error), addrs []string, promote bool) (quic.EarlyConnection, error) {
	var lastErr error
	for _, addr := range addrs {
		conn, err := dial(ctx, addr)
		if err == nil {
			if promote {
				s.promote(addr)
			}
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no addresses configured for %s", s.hostname)
	}
	return nil, lastErr
}

func (s *addressSource) roundRobinOrder() []string {
	state := s.snapshot()
	if len(state.addrs) < 2 {
		return state.addrs
	}
	start := int(s.rr.Add(1)-1) % len(state.addrs)
	ordered := make([]string, 0, len(state.addrs))
	ordered = append(ordered, state.addrs[start:]...)
	ordered = append(ordered, state.addrs[:start]...)
	return ordered
}

func (s *addressSource) promote(addr string) {
	if addr == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.state.addrs {
		if s.state.addrs[i] != addr {
			continue
		}
		if i == 0 {
			return
		}
		copy(s.state.addrs[1:i+1], s.state.addrs[0:i])
		s.state.addrs[0] = addr
		return
	}
}

type addressResolver struct {
	bootstrapServer string
	timeout         time.Duration
	rng             *rand.Rand
}

func newAddressResolver(cfg config.Config) (*addressResolver, error) {
	server, err := chooseBootstrapServer(cfg.Bootstrap.Servers)
	if err != nil {
		return nil, err
	}
	return &addressResolver{
		bootstrapServer: server,
		timeout:         cfg.Timeouts.Read.Duration(),
		rng:             rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

func chooseBootstrapServer(servers []string) (string, error) {
	if len(servers) == 0 {
		return "", fmt.Errorf("bootstrap.servers must contain at least one IP")
	}
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	pick := stringsTrimmedIP(servers[rng.Intn(len(servers))])
	if pick == "" {
		return "", fmt.Errorf("bootstrap server cannot be empty")
	}
	if !stringsContainsPort(pick) {
		pick = net.JoinHostPort(pick, "53")
	}
	return pick, nil
}

type resolvedLookup struct {
	IPs []net.IP
	TTL time.Duration
}

func (r *addressResolver) resolveBootstrap(ctx context.Context, hostname string) (resolvedLookup, error) {
	if ip := net.ParseIP(hostname); ip != nil {
		return resolvedLookup{IPs: []net.IP{append(net.IP(nil), ip...)}, TTL: time.Hour}, nil
	}
	ips, ttl, err := queryIPs(ctx, r.bootstrapServer, hostname, r.timeout)
	if err != nil {
		return resolvedLookup{}, err
	}
	return resolvedLookup{IPs: ips, TTL: ttl}, nil
}

func queryIPs(ctx context.Context, server, hostname string, timeout time.Duration) ([]net.IP, time.Duration, error) {
	var ips []net.IP
	var minTTL time.Duration
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		msg := new(dns.Msg)
		msg.SetQuestion(dns.Fqdn(hostname), qtype)
		client := &dns.Client{Net: "udp", Timeout: timeout}
		resp, _, err := client.ExchangeContext(ctx, msg, server)
		if err == nil && resp != nil && resp.Truncated {
			client.Net = "tcp"
			resp, _, err = client.ExchangeContext(ctx, msg, server)
		}
		if err != nil {
			if len(ips) != 0 {
				continue
			}
			return nil, 0, err
		}
		for _, rr := range resp.Answer {
			switch v := rr.(type) {
			case *dns.A:
				ips = append(ips, append(net.IP(nil), v.A...))
				minTTL = lowerTTL(minTTL, time.Duration(v.Hdr.Ttl)*time.Second)
			case *dns.AAAA:
				ips = append(ips, append(net.IP(nil), v.AAAA...))
				minTTL = lowerTTL(minTTL, time.Duration(v.Hdr.Ttl)*time.Second)
			}
		}
	}
	if len(ips) == 0 {
		return nil, 0, fmt.Errorf("no usable IPs for %s", hostname)
	}
	if minTTL <= 0 {
		minTTL = time.Minute
	}
	return ips, minTTL, nil
}

func lowerTTL(current, candidate time.Duration) time.Duration {
	if candidate <= 0 {
		return current
	}
	if current == 0 || candidate < current {
		return candidate
	}
	return current
}

type hostnameResolutionCache struct {
	refresh  config.UpstreamRefreshConfig
	resolver *addressResolver

	mu      sync.RWMutex
	entries map[string]*addressSource
}

func newHostnameResolutionCache(cfg config.Config, resolver *addressResolver) (*hostnameResolutionCache, error) {
	cache := &hostnameResolutionCache{
		refresh:  cfg.UpstreamRefresh,
		resolver: resolver,
		entries:  make(map[string]*addressSource),
	}
	for _, up := range cfg.Upstreams {
		if up.LiteralIP != nil {
			continue
		}
		if _, ok := cache.entries[up.Hostname]; ok {
			continue
		}
		var initial []net.IP
		static := false
		switch {
		case len(up.StaticHostIPs) > 0:
			initial = cloneIPs(up.StaticHostIPs)
			static = true
		default:
			ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeouts.Upstream.Duration())
			lookup, err := resolver.resolveBootstrap(ctx, up.Hostname)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("resolve upstream host %s: %w", up.Hostname, err)
			}
			src, err := newAddressSource(up.Hostname, up.Port, "failover", lookup.IPs, false)
			if err != nil {
				return nil, err
			}
			now := time.Now()
			expiry := now.Add(lookup.TTL)
			next := scheduleRefresh(now, expiry, cfg.UpstreamRefresh, resolver.rng)
			if err := src.replace(lookup.IPs, expiry, next, nil); err != nil {
				return nil, err
			}
			cache.entries[up.Hostname] = src
			continue
		}
		src, err := newAddressSource(up.Hostname, up.Port, "failover", initial, static)
		if err != nil {
			return nil, err
		}
		cache.entries[up.Hostname] = src
	}
	return cache, nil
}

func (c *hostnameResolutionCache) sourceFor(up config.UpstreamConfig) (*addressSource, error) {
	if up.LiteralIP != nil {
		return newAddressSource(up.Hostname, up.Port, "failover", []net.IP{up.LiteralIP}, true)
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	src := c.entries[up.Hostname]
	if src == nil {
		return nil, fmt.Errorf("no address source for %s", up.Hostname)
	}
	return src, nil
}

func (c *hostnameResolutionCache) entriesSnapshot() []*addressSource {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]*addressSource, 0, len(c.entries))
	for _, entry := range c.entries {
		out = append(out, entry)
	}
	return out
}

func scheduleRefresh(now, expiry time.Time, cfg config.UpstreamRefreshConfig, rng *rand.Rand) time.Time {
	if expiry.IsZero() {
		return now.Add(cfg.FailureRetry.Duration())
	}
	base := expiry.Add(-cfg.RefreshThreshold.Duration())
	min := now.Add(cfg.MinTTL.Duration())
	if base.Before(min) {
		base = min
	}
	jitterWindow := time.Duration(cfg.JitterPercent) * time.Second / 100
	if jitterWindow <= 0 {
		return base
	}
	spread := time.Duration(rng.Int63n(int64(jitterWindow * 2)))
	return base.Add(spread - jitterWindow)
}

func cloneIPs(in []net.IP) []net.IP {
	out := make([]net.IP, 0, len(in))
	for _, ip := range in {
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}

func stringsTrimmedIP(v string) string { return strings.TrimSpace(v) }

func stringsContainsPort(v string) bool {
	if _, _, err := net.SplitHostPort(v); err == nil {
		return true
	}
	return false
}

type raceResult[T any] struct {
	value T
	addr  string
	err   error
}

func raceDial[T any](ctx context.Context, addrs []string, dial func(context.Context, string) (T, error), closeFn func(T)) (T, string, error) {
	var zero T
	if len(addrs) == 0 {
		return zero, "", fmt.Errorf("no addresses configured")
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan raceResult[T], len(addrs))
	var claimed atomic.Bool
	for _, addr := range addrs {
		addr := addr
		go func() {
			value, err := dial(raceCtx, addr)
			if err == nil {
				if !claimed.CompareAndSwap(false, true) {
					closeFn(value)
					err = context.Canceled
					value = zero
				}
			}
			results <- raceResult[T]{value: value, addr: addr, err: err}
		}()
	}

	var lastErr error
	for range addrs {
		result := <-results
		if result.err == nil {
			cancel()
			return result.value, result.addr, nil
		}
		if !errors.Is(result.err, context.Canceled) || lastErr == nil {
			lastErr = result.err
		}
	}
	if lastErr == nil {
		lastErr = context.Canceled
	}
	return zero, "", lastErr
}
