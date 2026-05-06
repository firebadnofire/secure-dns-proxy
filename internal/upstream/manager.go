// Package upstream implements DNS upstream protocols.
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/pool"
)

// Manager selects and orchestrates upstream exchanges.
type Manager struct {
	upstreams []Upstream
	policy    string
	fanout    int
	log       logging.Logger
	metrics   *metrics.Metrics
	rrCounter atomic.Uint64

	healthCfg       config.HealthCheckConfig
	upstreamTimeout time.Duration
	refreshCfg      config.UpstreamRefreshConfig
	refreshCache    *hostnameResolutionCache
	resolver        *addressResolver
}

// BuildManager constructs upstream clients and pools from config.
func BuildManager(cfg config.Config, log logging.Logger, metrics *metrics.Metrics) (*Manager, *http.Client, error) {
	if err := cfg.Normalize(); err != nil {
		return nil, nil, err
	}

	resolver, err := newAddressResolver(cfg)
	if err != nil {
		return nil, nil, err
	}
	refreshCache, err := newHostnameResolutionCache(cfg, resolver)
	if err != nil {
		return nil, nil, err
	}

	dialer := &net.Dialer{Timeout: cfg.Timeouts.Dial.Duration()}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}

	dohDialers, err := buildDoHDialers(cfg.Upstreams, refreshCache)
	if err != nil {
		return nil, nil, err
	}
	transport := &http.Transport{
		MaxIdleConns:        cfg.Pools.HTTPTransport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Pools.HTTPTransport.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Pools.HTTPTransport.IdleConnTimeout.Duration(),
		ForceAttemptHTTP2:   true,
		TLSHandshakeTimeout: cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration(),
		TLSClientConfig:     tlsConfig.Clone(),
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if src, ok := dohDialers[addr]; ok {
				return src.dialContext(ctx, network, dialer.DialContext)
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	httpClient := &http.Client{Transport: transport}

	mgr := &Manager{
		policy:          cfg.UpstreamPolicy,
		fanout:          cfg.UpstreamRaceFanout,
		log:             log,
		metrics:         metrics,
		healthCfg:       cfg.HealthChecks,
		upstreamTimeout: cfg.Timeouts.Upstream.Duration(),
		refreshCfg:      cfg.UpstreamRefresh,
		refreshCache:    refreshCache,
		resolver:        resolver,
	}

	healthEnabled := cfg.HealthChecks.Enabled
	trackTraffic := false
	for _, upCfg := range cfg.Upstreams {
		u, err := buildUpstream(upCfg, cfg, httpClient, dialer, tlsConfig, refreshCache, log, metrics, trackTraffic, healthEnabled)
		if err != nil {
			return nil, nil, err
		}
		mgr.upstreams = append(mgr.upstreams, u)
	}

	return mgr, httpClient, nil
}

func buildDoHDialers(upstreams []config.UpstreamConfig, cache *hostnameResolutionCache) (map[string]*addressSource, error) {
	dialers := make(map[string]*addressSource)
	for _, up := range upstreams {
		if up.Protocol != "https" {
			continue
		}
		src, err := cache.sourceFor(up)
		if err != nil {
			return nil, err
		}
		dialers[net.JoinHostPort(up.Hostname, up.Port)] = src
	}
	return dialers, nil
}

func buildUpstream(upCfg config.UpstreamConfig, cfg config.Config, httpClient *http.Client, dialer *net.Dialer, tlsConf *tls.Config, cache *hostnameResolutionCache, log logging.Logger, metrics *metrics.Metrics, trackTraffic bool, healthEnabled bool) (Upstream, error) {
	switch upCfg.Protocol {
	case "dns":
		src, err := cache.sourceFor(upCfg)
		if err != nil {
			return nil, err
		}
		return NewPlainDNS(upCfg, src, cfg.Timeouts.Upstream.Duration(), trackTraffic, healthEnabled), nil
	case "https":
		return NewDoH(upCfg, httpClient, trackTraffic, healthEnabled), nil
	case "tls":
		src, err := cache.sourceFor(upCfg)
		if err != nil {
			return nil, err
		}
		factory := MakeTLSFactory(src, tlsConf, dialer)
		tlsPool := pool.NewTLSConnPool(cfg.Pools.TLS.Size, cfg.Pools.TLS.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go tlsPool.Prewarm(context.Background())
		}
		return NewDoT(upCfg, src, tlsPool, trackTraffic, healthEnabled), nil
	case "quic":
		src, err := cache.sourceFor(upCfg)
		if err != nil {
			return nil, err
		}
		quicTLS := tlsConf.Clone()
		quicTLS.NextProtos = []string{"doq"}
		if quicTLS.ServerName == "" {
			quicTLS.ServerName = upCfg.Hostname
		}
		factory := MakeQUICFactory(src, quicTLS)
		quicPool := pool.NewQUICConnPool(cfg.Pools.QUIC.Size, cfg.Pools.QUIC.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go quicPool.Prewarm(context.Background())
		}
		return NewDoQ(upCfg, src, quicPool, quicTLS, trackTraffic, healthEnabled), nil
	default:
		return nil, fmt.Errorf("unsupported protocol %s", upCfg.Protocol)
	}
}

// StartBackground starts health checks and upstream refresh work.
func (m *Manager) StartBackground(ctx context.Context) {
	m.StartHealthChecks(ctx)
	if !m.refreshCfg.Enabled || m.refreshCache == nil {
		return
	}
	ticker := time.NewTicker(5 * time.Second)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.refreshDueHosts(ctx)
			}
		}
	}()
}

func (m *Manager) refreshDueHosts(ctx context.Context) {
	now := time.Now()
	for _, src := range m.refreshCache.entriesSnapshot() {
		if !src.due(now) {
			continue
		}
		go m.refreshSource(ctx, src)
	}
}

func (m *Manager) refreshSource(ctx context.Context, src *addressSource) {
	if src.static {
		return
	}
	lookupCtx, cancel := context.WithTimeout(ctx, m.upstreamTimeout)
	defer cancel()

	lookup, err := m.resolveHostnameSecure(lookupCtx, src.hostname)
	if err != nil {
		src.markRefreshFailure(time.Now().Add(m.refreshCfg.FailureRetry.Duration()), err)
		if m.log != nil {
			m.log.Warn("upstream refresh failed", "hostname", src.hostname, "error", err)
		}
		return
	}
	now := time.Now()
	expiry := now.Add(lookup.TTL)
	next := scheduleRefresh(now, expiry, m.refreshCfg, m.resolver.rng)
	if err := src.replace(lookup.IPs, expiry, next, nil); err != nil {
		src.markRefreshFailure(time.Now().Add(m.refreshCfg.FailureRetry.Duration()), err)
		return
	}
}

func (m *Manager) resolveHostnameSecure(ctx context.Context, hostname string) (resolvedLookup, error) {
	var ips []net.IP
	var minTTL time.Duration
	for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
		req := new(dns.Msg)
		req.SetQuestion(dns.Fqdn(hostname), qtype)
		resp, err := m.Resolve(ctx, req)
		if err != nil {
			if len(ips) != 0 {
				continue
			}
			return resolvedLookup{}, err
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
		return resolvedLookup{}, fmt.Errorf("no secure upstream IPs returned for %s", hostname)
	}
	if minTTL <= 0 {
		minTTL = m.refreshCfg.MinTTL.Duration()
	}
	return resolvedLookup{IPs: ips, TTL: minTTL}, nil
}

// Resolve forwards the query according to the configured policy.
func (m *Manager) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	switch m.policy {
	case "sequential":
		return m.sequential(ctx, msg)
	case "race":
		return m.race(ctx, msg)
	default:
		return m.roundRobin(ctx, msg)
	}
}

func (m *Manager) sequential(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	var lastErr error
	for _, up := range m.upstreams {
		if !up.Healthy() {
			continue
		}
		resp, err := up.Exchange(ctx, msg)
		if err == nil {
			if m.metrics != nil {
				m.metrics.RecordSuccess()
			}
			return resp, nil
		}
		lastErr = err
		if m.metrics != nil {
			m.metrics.RecordFailure()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no healthy upstreams")
	}
	return nil, lastErr
}

func (m *Manager) roundRobin(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(m.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	start := int(m.rrCounter.Add(1) % uint64(len(m.upstreams)))
	var lastErr error
	for i := 0; i < len(m.upstreams); i++ {
		idx := (start + i) % len(m.upstreams)
		up := m.upstreams[idx]
		if !up.Healthy() {
			continue
		}
		resp, err := up.Exchange(ctx, msg)
		if err == nil {
			if m.metrics != nil {
				m.metrics.RecordSuccess()
			}
			return resp, nil
		}
		if m.metrics != nil {
			m.metrics.RecordFailure()
		}
		lastErr = err
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("no healthy upstreams")
}

func (m *Manager) race(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if len(m.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured")
	}
	fanout := m.fanout
	if fanout <= 0 || fanout > len(m.upstreams) {
		fanout = len(m.upstreams)
	}
	type result struct {
		resp *dns.Msg
		err  error
	}
	resCh := make(chan result, fanout)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	start := int(m.rrCounter.Add(1) % uint64(len(m.upstreams)))
	launched := 0
	for i := 0; i < len(m.upstreams) && launched < fanout; i++ {
		idx := (start + i) % len(m.upstreams)
		up := m.upstreams[idx]
		if !up.Healthy() {
			continue
		}
		launched++
		go func(u Upstream) {
			resp, err := u.Exchange(ctx, msg)
			resCh <- result{resp: resp, err: err}
		}(up)
	}
	if launched == 0 {
		return nil, fmt.Errorf("no healthy upstreams")
	}

	var lastErr error
	for i := 0; i < launched; i++ {
		select {
		case r := <-resCh:
			if r.err == nil && r.resp != nil {
				cancel()
				if m.metrics != nil {
					m.metrics.RecordSuccess()
				}
				return r.resp, nil
			}
			lastErr = r.err
			if m.metrics != nil {
				m.metrics.RecordFailure()
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no successful upstream response")
	}
	return nil, lastErr
}

func (m *Manager) StartHealthChecks(ctx context.Context) {
	if !m.healthCfg.Enabled {
		return
	}
	interval := m.healthCfg.Interval.Duration()
	if interval <= 0 {
		interval = 120 * time.Second
	}
	query := m.healthCfg.Query
	if query == "" {
		query = "."
	}
	tmpl := new(dns.Msg)
	tmpl.SetQuestion(dns.Fqdn(query), dns.TypeA)

	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				m.dispatchHealthChecks(ctx, tmpl)
			}
		}
	}()
}

func (m *Manager) dispatchHealthChecks(ctx context.Context, tmpl *dns.Msg) {
	for _, up := range m.upstreams {
		probe := tmpl.Copy()
		if probe == nil {
			probe = tmpl
		}
		probeCtx := ctx
		var cancel context.CancelFunc
		if m.upstreamTimeout > 0 {
			probeCtx, cancel = context.WithTimeout(ctx, m.upstreamTimeout)
		}
		go func(u Upstream, c context.CancelFunc, msg *dns.Msg, pctx context.Context) {
			if c != nil {
				defer c()
			}
			if err := u.Probe(pctx, msg); err != nil && m.log != nil {
				m.log.Debug("upstream health probe failed", "upstream", u.ID(), "error", err)
			}
		}(up, cancel, probe, probeCtx)
	}
}

func (m *Manager) DoHealthProbe(ctx context.Context, msg *dns.Msg) []error {
	errs := make([]error, len(m.upstreams))
	for i, up := range m.upstreams {
		probe := msg.Copy()
		if probe == nil {
			probe = msg
		}
		errs[i] = up.Probe(ctx, probe)
	}
	return errs
}
