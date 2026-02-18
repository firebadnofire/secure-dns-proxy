// Package upstream implements DNS upstream protocols.
package upstream

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"
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
	// upstreams holds the configured upstream resolvers.
	upstreams []Upstream
	// policy selects the strategy for picking upstreams.
	policy string
	// fanout configures how many upstreams to query in "race" mode.
	fanout int
	// log emits structured diagnostics.
	log logging.Logger
	// metrics records upstream success/failure counters.
	metrics *metrics.Metrics
	// rrCounter tracks the next upstream index for round robin.
	rrCounter atomic.Uint64

	// healthCfg configures background probing behavior.
	healthCfg config.HealthCheckConfig
	// upstreamTimeout bounds health probe duration.
	upstreamTimeout time.Duration
	// healthAction controls what to do when probes keep failing.
	healthAction config.HealthFailActionConfig
	// healthActionLast tracks when the last action ran per upstream.
	healthActionLast map[string]time.Time
	// healthActionMu protects healthActionLast.
	healthActionMu sync.Mutex
	// restartTriggered ensures restart action runs once.
	restartTriggered atomic.Bool
	// restartFn exits the process for restart-oriented deployment environments.
	restartFn func(code int)
}

// BuildManager constructs upstream clients and pools from config.
func BuildManager(cfg config.Config, log logging.Logger, metrics *metrics.Metrics) (*Manager, *http.Client, error) {
	// Shared HTTP transport for DoH upstreams.
	transport := &http.Transport{
		MaxIdleConns:        cfg.Pools.HTTPTransport.MaxIdleConns,
		MaxIdleConnsPerHost: cfg.Pools.HTTPTransport.MaxIdleConnsPerHost,
		IdleConnTimeout:     cfg.Pools.HTTPTransport.IdleConnTimeout.Duration(),
		TLSHandshakeTimeout: cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration(),
	}
	httpClient := &http.Client{Transport: transport}

	// TLS config and dialer are shared across TLS/QUIC upstreams.
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.InsecureTLS}
	dialer := &net.Dialer{Timeout: cfg.Timeouts.Dial.Duration()}

	// Manager stores policy and health check configuration.
	mgr := &Manager{
		policy:           cfg.UpstreamPolicy,
		fanout:           cfg.UpstreamRaceFanout,
		log:              log,
		metrics:          metrics,
		healthCfg:        cfg.HealthChecks,
		upstreamTimeout:  cfg.Timeouts.Upstream.Duration(),
		healthAction:     cfg.HealthChecks.OnFailure,
		healthActionLast: make(map[string]time.Time),
		restartFn:        os.Exit,
	}

	healthEnabled := cfg.HealthChecks.Enabled
	// Probe-only health is the default so request traffic does not flap health state.
	trackTraffic := false

	for _, upCfg := range cfg.Upstreams {
		// Build each upstream according to its scheme.
		u, err := buildUpstream(upCfg, cfg, httpClient, dialer, tlsConfig, log, metrics, trackTraffic, healthEnabled)
		if err != nil {
			return nil, nil, err
		}
		mgr.upstreams = append(mgr.upstreams, u)
	}

	return mgr, httpClient, nil
}

// buildUpstream parses the upstream URL and returns a concrete upstream type.
func buildUpstream(upCfg config.UpstreamConfig, cfg config.Config, httpClient *http.Client, dialer *net.Dialer, tlsConf *tls.Config, log logging.Logger, metrics *metrics.Metrics, trackTraffic bool, healthEnabled bool) (Upstream, error) {
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
		// Plain DNS defaults to port 53.
		addr := parsed.Host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "53")
		}
		return NewPlainDNS(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, cfg.Timeouts.Upstream.Duration(), trackTraffic, healthEnabled), nil
	case "https":
		// DNS-over-HTTPS uses shared HTTP client.
		return NewDoH(upCfg, httpClient, trackTraffic, healthEnabled), nil
	case "tls":
		// DNS-over-TLS defaults to port 853.
		addr := parsed.Host
		if !strings.Contains(addr, ":") {
			addr = net.JoinHostPort(addr, "853")
		}
		// TLS pools reuse encrypted connections.
		factory := MakeTLSFactory(addr, tlsConf, dialer)
		tlsPool := pool.NewTLSConnPool(cfg.Pools.TLS.Size, cfg.Pools.TLS.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go tlsPool.Prewarm(context.Background())
		}
		return NewDoT(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, tlsPool, trackTraffic, healthEnabled), nil
	case "quic":
		// DNS-over-QUIC defaults to port 784.
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
		// QUIC pools reuse connections and enable 0-RTT when possible.
		factory := MakeQUICFactory(addr, quicTLS, dialer)
		quicPool := pool.NewQUICConnPool(cfg.Pools.QUIC.Size, cfg.Pools.QUIC.IdleTimeout.Duration(), factory, log, metrics)
		if cfg.PrewarmPools {
			go quicPool.Prewarm(context.Background())
		}
		return NewDoQ(config.UpstreamConfig{URL: addr, MaxFailures: upCfg.MaxFailures, Cooldown: upCfg.Cooldown}, quicPool, quicTLS, trackTraffic, healthEnabled), nil
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

// sequential tries each upstream in order until one succeeds.
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

// roundRobin cycles through upstreams, skipping unhealthy ones.
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

// race issues concurrent requests to multiple upstreams and returns the first success.
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
	candidates := m.pickHealthyUpstreams(fanout)
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no healthy upstreams")
	}
	resCh := make(chan result, len(candidates))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, up := range candidates {
		go func(u Upstream) {
			resp, err := u.Exchange(ctx, msg)
			select {
			case resCh <- result{resp: resp, err: err}:
			case <-ctx.Done():
			}
		}(up)
	}

	var lastErr error
	for i := 0; i < len(candidates); i++ {
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

// StartHealthChecks periodically probes upstreams without relying on request traffic.
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

// dispatchHealthChecks fires a probe for each upstream.
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
			if err := u.Probe(pctx, msg); err != nil {
				if m.log != nil {
					m.log.Warn("upstream health probe failed", "upstream", u.ID(), "error", err)
				}
				m.handleProbeFailure(u, err)
			}
		}(up, cancel, probe, probeCtx)
	}
}

// pickHealthyUpstreams selects up to fanout healthy upstreams in round-robin order.
func (m *Manager) pickHealthyUpstreams(fanout int) []Upstream {
	if len(m.upstreams) == 0 || fanout <= 0 {
		return nil
	}
	start := int(m.rrCounter.Add(1) % uint64(len(m.upstreams)))
	candidates := make([]Upstream, 0, fanout)
	for i := 0; i < len(m.upstreams) && len(candidates) < fanout; i++ {
		up := m.upstreams[(start+i)%len(m.upstreams)]
		if up.Healthy() {
			candidates = append(candidates, up)
		}
	}
	return candidates
}

func (m *Manager) handleProbeFailure(up Upstream, probeErr error) {
	policy := normalizeHealthPolicy(m.healthAction.Policy)
	if policy == "warn" || policy == "" {
		return
	}
	// Apply non-warn actions only when the upstream is currently unhealthy.
	if up.Healthy() {
		return
	}
	if !m.shouldRunHealthAction(up.ID()) {
		return
	}
	switch policy {
	case "restart":
		m.triggerRestart(up.ID(), probeErr)
	case "execute_script":
		go m.runHealthFailureScript(up.ID(), probeErr)
	case "desktop_notify":
		go m.sendDesktopNotification(up.ID(), probeErr)
	default:
		if m.log != nil {
			m.log.Warn("unknown health failure policy", "policy", policy)
		}
	}
}

func normalizeHealthPolicy(policy string) string {
	if policy == "" {
		return "warn"
	}
	return strings.ToLower(strings.TrimSpace(policy))
}

func (m *Manager) shouldRunHealthAction(upstreamID string) bool {
	cooldown := m.healthAction.Cooldown.Duration()
	if cooldown <= 0 {
		cooldown = 5 * time.Minute
	}
	now := time.Now()

	m.healthActionMu.Lock()
	defer m.healthActionMu.Unlock()

	last, ok := m.healthActionLast[upstreamID]
	if ok && now.Sub(last) < cooldown {
		return false
	}
	m.healthActionLast[upstreamID] = now
	return true
}

func (m *Manager) triggerRestart(upstreamID string, probeErr error) {
	if !m.restartTriggered.CompareAndSwap(false, true) {
		return
	}
	if m.log != nil {
		m.log.Error("health failure policy requested restart", "upstream", upstreamID, "error", probeErr)
	}
	go func() {
		time.Sleep(100 * time.Millisecond)
		if m.restartFn != nil {
			m.restartFn(1)
		}
	}()
}

func (m *Manager) runHealthFailureScript(upstreamID string, probeErr error) {
	script := strings.TrimSpace(m.healthAction.Script)
	if script == "" {
		if m.log != nil {
			m.log.Warn("health failure script policy selected but script is empty", "upstream", upstreamID)
		}
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, script, m.healthAction.Args...)
	cmd.Env = append(os.Environ(),
		"SDP_UPSTREAM="+upstreamID,
		"SDP_ERROR="+probeErr.Error(),
		"SDP_HEALTH_POLICY=execute_script",
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if m.log != nil {
			m.log.Warn("health failure script failed", "upstream", upstreamID, "error", err, "output", trimOutput(out))
		}
		return
	}
	if m.log != nil {
		m.log.Info("health failure script completed", "upstream", upstreamID, "output", trimOutput(out))
	}
}

func (m *Manager) sendDesktopNotification(upstreamID string, probeErr error) {
	title := strings.TrimSpace(m.healthAction.NotifyTitle)
	if title == "" {
		title = "secure-dns-proxy"
	}
	message := fmt.Sprintf("Upstream %s is unhealthy: %v", upstreamID, probeErr)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.CommandContext(ctx, "osascript", "-e", fmt.Sprintf("display notification %q with title %q", message, title))
	case "linux":
		cmd = exec.CommandContext(ctx, "notify-send", title, message)
	default:
		if m.log != nil {
			m.log.Warn("desktop notification not supported on this OS", "os", runtime.GOOS)
		}
		return
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		if m.log != nil {
			m.log.Warn("desktop notification failed", "upstream", upstreamID, "error", err, "output", trimOutput(out))
		}
		return
	}
	if m.log != nil {
		m.log.Info("desktop notification sent", "upstream", upstreamID)
	}
}

func trimOutput(out []byte) string {
	const max = 256
	s := strings.TrimSpace(string(out))
	if len(s) <= max {
		return s
	}
	return s[:max] + "...(truncated)"
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
