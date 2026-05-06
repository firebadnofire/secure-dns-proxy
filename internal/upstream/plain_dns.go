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
	// source provides refreshable addresses for the upstream.
	source *addressSource
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
func NewPlainDNS(cfg config.UpstreamConfig, source *addressSource, timeout time.Duration, trackTraffic bool, healthEnabled bool) *PlainDNS {
	return &PlainDNS{source: source, timeout: timeout, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

// ID returns a stable identifier used in logs and metrics.
func (p *PlainDNS) ID() string {
	return fmt.Sprintf("dns://%s", net.JoinHostPort(p.source.hostname, p.source.port))
}

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
	resp, err := p.source.exchangeDNS(ctx, msg, p.timeout, nil)
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
