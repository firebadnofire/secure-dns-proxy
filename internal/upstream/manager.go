package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"

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
}

// BuildManager constructs upstream clients and pools from config.
func BuildManager(cfg config.Config, log logging.Logger, metrics *metrics.Metrics) (*Manager, *http.Client, error) {
	transport := &http.Transport{
		MaxIdleConns:        cfg.Pools.HTTPTransport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Pools.HTTPTransport.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Pools.HTTPTransport.IdleConnTimeout.Duration(),
		TLSHandshakeTimeout: cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration(),
	}
	httpClient := &http.Client{Transport: transport}

	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Dial.Duration()}

	mgr := &Manager{policy: cfg.UpstreamPolicy, fanout: cfg.UpstreamRaceFanout, log: log, metrics: metrics}

	for _, upCfg := range cfg.Upstreams {
		u, err := buildUpstream(upCfg, cfg, httpClient, dialer, tlsConfig, log, metrics)
		if err != nil {
			return nil, nil, err
		}
		mgr.upstreams = append(mgr.upstreams, u)
	}

	return mgr, httpClient, nil
}

func buildUpstream(upCfg config.UpstreamConfig, cfg config.Config, httpClient *http.Client, dialer *net.Dialer, tlsConf *tls.Config, log logging.Logger, metrics *metrics.Metrics) (Upstream, error) {
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
		return NewPlainDNS(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, cfg.Timeouts.Upstream.Duration()), nil
	case "https":
		return NewDoH(upCfg, httpClient), nil
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
		return NewDoT(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, tlsPool), nil
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
		return NewDoQ(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, quicPool, quicTLS), nil
	default:
		return nil, fmt.Errorf("unsupported scheme %s", parsed.Scheme)
	}
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
	for i := 0; i < fanout; i++ {
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

// DoHealthProbe checks upstream liveness without altering metrics.
func (m *Manager) DoHealthProbe(ctx context.Context, msg *dns.Msg) []error {
	errs := make([]error, len(m.upstreams))
	for i, up := range m.upstreams {
		if !up.Healthy() {
			errs[i] = ErrCircuitOpen
			continue
		}
		_, err := up.Exchange(ctx, msg)
		errs[i] = err
	}
	return errs
}
