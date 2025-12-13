package upstream

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

type PlainDNS struct {
	address       string
	timeout       time.Duration
	health        healthState
	trackTraffic  bool
	healthEnabled bool
}

func NewPlainDNS(cfg config.UpstreamConfig, timeout time.Duration, trackTraffic bool, healthEnabled bool) *PlainDNS {
	return &PlainDNS{address: cfg.URL, timeout: timeout, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

func (p *PlainDNS) ID() string { return fmt.Sprintf("dns://%s", p.address) }

func (p *PlainDNS) Healthy() bool { return p.health.healthy() }

func (p *PlainDNS) RecordSuccess() { p.health.success() }

func (p *PlainDNS) RecordFailure(err error) { p.health.failure() }

func (p *PlainDNS) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if p.healthEnabled && !p.Healthy() {
		return nil, ErrCircuitOpen
	}
	return p.doExchange(ctx, msg, p.healthEnabled && p.trackTraffic)
}

func (p *PlainDNS) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := p.doExchange(ctx, msg, p.healthEnabled)
	return err
}

func (p *PlainDNS) doExchange(ctx context.Context, msg *dns.Msg, recordHealth bool) (*dns.Msg, error) {
	c := &dns.Client{Net: "udp", Timeout: p.timeout}
	resp, rtt, err := c.ExchangeContext(ctx, msg, p.address)
	_ = rtt
	if err == nil && resp != nil && resp.Truncated {
		c.Net = "tcp"
		resp, rtt, err = c.ExchangeContext(ctx, msg, p.address)
		_ = rtt
	}
	if err != nil {
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

// BootstrapResolver resolves hostnames using system resolver when upstream is configured with hostname only.
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
