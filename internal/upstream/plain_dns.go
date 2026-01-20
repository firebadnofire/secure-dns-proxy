// Package upstream implements DNS upstream protocols.
package upstream

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

// PlainDNS speaks classic UDP/TCP DNS to an upstream resolver.
type PlainDNS struct {
	// address is the host:port of the upstream.
	address string
	// timeout bounds the UDP/TCP exchange.
	timeout time.Duration
	// health tracks failure counts and cooldowns.
	health healthState
	// trackTraffic toggles whether to record health for traffic.
	trackTraffic bool
	// healthEnabled toggles circuit breaking for this upstream.
	healthEnabled bool
}

// NewPlainDNS constructs a PlainDNS upstream with health tracking.
func NewPlainDNS(cfg config.UpstreamConfig, timeout time.Duration, trackTraffic bool, healthEnabled bool) *PlainDNS {
	return &PlainDNS{address: cfg.URL, timeout: timeout, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

// ID returns a stable identifier used in logs and metrics.
func (p *PlainDNS) ID() string { return fmt.Sprintf("dns://%s", p.address) }

// Healthy reports whether the upstream is eligible for use.
func (p *PlainDNS) Healthy() bool { return p.health.healthy() }

// RecordSuccess resets failure counters.
func (p *PlainDNS) RecordSuccess() { p.health.success() }

// RecordFailure increments failure counters and triggers cooldown if needed.
func (p *PlainDNS) RecordFailure(err error) { p.health.failure() }

// Exchange sends a DNS query, honoring health/circuit breaker settings.
func (p *PlainDNS) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if p.healthEnabled && !p.Healthy() {
		return nil, ErrCircuitOpen
	}
	return p.doExchange(ctx, msg, p.healthEnabled && p.trackTraffic)
}

// Probe is a lightweight health check that does not log traffic metrics.
func (p *PlainDNS) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := p.doExchange(ctx, msg, p.healthEnabled)
	return err
}

// doExchange performs UDP exchange, falling back to TCP when truncated.
func (p *PlainDNS) doExchange(ctx context.Context, msg *dns.Msg, recordHealth bool) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: p.timeout}
	resp, rtt, err := c.ExchangeContext(ctx, msg, p.address)
	_ = rtt
	if err == nil && resp != nil && resp.Truncated {
		// Retry over TCP if the UDP response was truncated.
		c.Net = "tcp"
		resp, rtt, err = c.ExchangeContext(ctx, msg, p.address)
		_ = rtt
	}
	if err != nil {
		// Record failure when health tracking is enabled.
		if recordHealth {
			p.RecordFailure(err)
		}
		return nil, err
	}
	if recordHealth {
		p.RecordSuccess()
	}
	return resp, nil
}

// BootstrapResolver resolves hostnames using the system resolver when upstream
// is configured with a hostname instead of an IP address.
func BootstrapResolver(ctx context.Context, hostport string) (string, error) {
	host, port, err := net.SplitHostPort(hostport)
	if err != nil {
		return hostport, nil
	}
	ip := net.ParseIP(host)
	if ip != nil {
		return hostport, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", err
	}
	if len(addrs) == 0 {
		return "", fmt.Errorf("no ip for %s", host)
	}
	return net.JoinHostPort(addrs[0].IP.String(), port), nil
}
