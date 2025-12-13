package upstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
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

	lastReset atomic.Int64

	healthCfg       config.HealthCheckConfig
	upstreamTimeout time.Duration
}

// BuildManager constructs upstream clients and pools from config.
func BuildManager(cfg config.Config, log logging.Logger, metrics *metrics.Metrics) (*Manager, *http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        cfg.Pools.HTTPTransport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Pools.HTTPTransport.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Pools.HTTPTransport.IdleConnTimeout.Duration(),
		TLSHandshakeTimeout: cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration(),
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS},
	}
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Dial.Duration()}
	transport.DialContext = dialer.DialContext
	httpClient := &http.Client{Transport: transport}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}

	mgr := &Manager{policy: cfg.UpstreamPolicy, fanout: cfg.UpstreamRaceFanout, log: log, metrics: metrics, healthCfg: cfg.HealthChecks, upstreamTimeout: cfg.Timeouts.Upstream.Duration()}

	trackTraffic := !cfg.HealthChecks.Enabled

	for _, upCfg := range cfg.Upstreams {
		u, err := buildUpstream(upCfg, cfg, httpClient, dialer, tlsConfig, log, metrics, trackTraffic)
		if err != nil {
			return nil, nil, err
		}
		mgr.upstreams = append(mgr.upstreams, u)
	}

	return mgr, httpClient, nil
}

func buildUpstream(upCfg config.UpstreamConfig, cfg config.Config, httpClient *http.Client, dialer *net.Dialer, tlsConf *tls.Config, log logging.Logger, metrics *metrics.Metrics, trackTraffic bool) (Upstream, error) {
	target := upCfg.URL
	if !strings.Contains(target, "://") {
		target = "dns://" + target
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream %s: %w", target, err)
	}
	switch parsed.Scheme {
	case "dns":
		addr := parsed.Host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "53")
		}
		return NewPlainDNS(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, cfg.Timeouts.Upstream.Duration(), trackTraffic), nil
	case "https":
		return NewDoH(upCfg, httpClient, trackTraffic), nil
	case "tls":
		addr := parsed.Host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "853")
		}
		factory := MakeTLSFactory(addr, tlsConf, dialer)
		tlsPool := pool.NewTLSConnPool(cfg.Pools.TLS.Size, cfg.Pools.TLS.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go tlsPool.Prewarm(context.Background())
		}
		return NewDoT(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, tlsPool, trackTraffic), nil
	case "quic":
		addr := parsed.Host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "784")
		}
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid quic upstream %s: %w", target, err)
		}
		quicTLS := tlsConf.Clone()
		quicTLS.NextProtos = []string{"doq"}
		if quicTLS.ServerName == "" {
			quicTLS.ServerName = host
		}
		factory := MakeQUICFactory(addr, quicTLS, dialer)
		quicPool := pool.NewQUICConnPool(cfg.Pools.QUIC.Size, cfg.Pools.QUIC.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go quicPool.Prewarm(context.Background())
		}
		return NewDoQ(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, quicPool, quicTLS, trackTraffic), nil
	default:
		return nil, fmt.Errorf("unsupported scheme %s", parsed.Scheme)
	}
}

// Resolve forwards the query according to the configured policy.
//
// If all upstreams are unhealthy and a reset is triggered, the request is
// retried once so callers don't need to issue a second query after a network
// change.
func (m *Manager) Resolve(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	for attempt := 0; attempt < 2; attempt++ {
		var (
			resp  *dns.Msg
			err   error
			retry bool
		)

		switch m.policy {
		case "sequential":
			resp, err, retry = m.sequential(ctx, msg)
		case "race":
			resp, err, retry = m.race(ctx, msg)
		default:
			resp, err, retry = m.roundRobin(ctx, msg)
		}

		if !retry {
			return resp, err
		}
	}
	return nil, fmt.Errorf("no healthy upstreams after reset")
}

func (m *Manager) sequential(ctx context.Context, msg *dns.Msg) (*dns.Msg, error, bool) {
	var (
		lastErr    error
		forceReset bool
	)
	for _, up := range m.upstreams {
		if !up.Healthy() {
			continue
		}
		resp, err := up.Exchange(ctx, msg)
		if err == nil {
			if m.metrics != nil {
				m.metrics.RecordSuccess()
			}
			return resp, nil, false
		}
		lastErr = err
		if isNetworkError(err) {
			forceReset = true
		}
		if m.metrics != nil {
			m.metrics.RecordFailure()
		}
	}
	err, retry := m.handleNoHealthy(lastErr, forceReset)
	return nil, err, retry
}

func (m *Manager) roundRobin(ctx context.Context, msg *dns.Msg) (*dns.Msg, error, bool) {
	if len(m.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured"), false
	}
	start := int(m.rrCounter.Add(1) % uint64(len(m.upstreams)))
	var (
		lastErr    error
		forceReset bool
	)
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
			return resp, nil, false
		}
		lastErr = err
		if isNetworkError(err) {
			forceReset = true
		}
		if m.metrics != nil {
			m.metrics.RecordFailure()
		}
	}
	err, retry := m.handleNoHealthy(lastErr, forceReset)
	return nil, err, retry
}

func (m *Manager) race(ctx context.Context, msg *dns.Msg) (*dns.Msg, error, bool) {
	if len(m.upstreams) == 0 {
		return nil, fmt.Errorf("no upstreams configured"), false
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

	for i := 0; i < fanout; i++ {
		up := m.upstreams[(int(m.rrCounter.Add(1))+i)%len(m.upstreams)]
		if !up.Healthy() {
			continue
		}
		go func(u Upstream) {
			resp, err := u.Exchange(ctx, msg)
			resCh <- result{resp: resp, err: err}
		}(up)
	}

	var lastErr error
	forceReset := false
	for i := 0; i < fanout; i++ {
		select {
		case r := <-resCh:
			if r.err == nil && r.resp != nil {
				cancel()
				if m.metrics != nil {
					m.metrics.RecordSuccess()
				}
				return r.resp, nil, false
			}
			lastErr = r.err
			if isNetworkError(r.err) {
				forceReset = true
			}
			if m.metrics != nil {
				m.metrics.RecordFailure()
			}
		case <-ctx.Done():
			return nil, ctx.Err(), false
		}
	}
	err, retry := m.handleNoHealthy(lastErr, forceReset)
	return nil, err, retry
}

func (m *Manager) handleNoHealthy(lastErr error, forceReset bool) (error, bool) {
	if lastErr == nil {
		lastErr = fmt.Errorf("no healthy upstreams")
	}

	// Best-effort reset when every upstream is unhealthy to clear stale
	// pooled connections after connectivity changes.
	now := time.Now().UnixNano()
	prev := m.lastReset.Load()
	if forceReset || now-prev >= int64(5*time.Second) {
		if forceReset || m.lastReset.CompareAndSwap(prev, now) {
			if m.log != nil {
				m.log.Info("all upstreams unhealthy, resetting pooled connections")
			}
			m.ResetConnections()
			return lastErr, true
		}
	}

	return lastErr, false
}

func isNetworkError(err error) bool {
	if err == nil {
		return false
	}
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	return false
}

// StartHealthChecks periodically probes upstreams without relying on request traffic.
func (m *Manager) StartHealthChecks(ctx context.Context) {
	if !m.healthCfg.Enabled {
		return
	}
	interval := m.healthCfg.Interval.Duration()
	if interval <= 0 {
		interval = 10 * time.Second
	}
	query := m.healthCfg.Query
	if query == "" {
		query = "example.com."
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

// DoHealthProbe checks upstream liveness without altering metrics.
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

// ResetConnections clears reusable upstream state after a local network change.
func (m *Manager) ResetConnections() {
	for _, up := range m.upstreams {
		if resettable, ok := up.(ResettableUpstream); ok {
			resettable.Reset()
		}
	}
}

// StartNetworkWatcher polls network interface state and triggers upstream
// resets when a change is detected. This mitigates stale pooled connections
// after switching networks (e.g., Wi-Fi hopping).
func (m *Manager) StartNetworkWatcher(ctx context.Context, interval time.Duration) {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	baseline := networkFingerprint()
	ticker := time.NewTicker(interval)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				snapshot := networkFingerprint()
				if snapshot != baseline {
					baseline = snapshot
					if m.log != nil {
						m.log.Info("network change detected, resetting upstreams")
					}
					m.ResetConnections()
				}
			}
		}
	}()
}

func networkFingerprint() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	var entries []string
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil || len(addrs) == 0 {
			continue
		}
		for _, addr := range addrs {
			entries = append(entries, fmt.Sprintf("%s:%s", iface.Name, addr.String()))
		}
	}
	sort.Strings(entries)
	return strings.Join(entries, ";")
}
