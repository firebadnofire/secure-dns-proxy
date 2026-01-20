// Package upstream implements DNS upstream protocols.
package upstream

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

// DoH implements DNS-over-HTTPS exchanges.
type DoH struct {
	// url is the HTTPS endpoint for the DoH server.
	url string
	// client performs the HTTP requests.
	client *http.Client
	// health tracks failures for circuit breaking.
	health healthState
	// trackTraffic toggles whether to count success/failure on normal traffic.
	trackTraffic bool
	// healthEnabled toggles circuit breaker logic.
	healthEnabled bool
}

// NewDoH constructs a DoH upstream with shared HTTP client transport.
func NewDoH(cfg config.UpstreamConfig, client *http.Client, trackTraffic bool, healthEnabled bool) *DoH {
	return &DoH{url: cfg.URL, client: client, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

// ID returns the upstream URL for logging and selection.
func (d *DoH) ID() string { return d.url }

// Healthy reports whether the upstream is eligible for use.
func (d *DoH) Healthy() bool { return d.health.healthy() }

// RecordSuccess resets failure counters.
func (d *DoH) RecordSuccess() { d.health.success() }

// RecordFailure increments failure counters and triggers cooldown.
func (d *DoH) RecordFailure(err error) { d.health.failure() }

// Exchange performs a DNS-over-HTTPS query, honoring circuit breaker state.
func (d *DoH) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if d.healthEnabled && !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.healthEnabled && d.trackTraffic)
}

func (d *DoH) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, d.healthEnabled)
	return err
}

// doExchange serializes the DNS message, performs an HTTP POST, and parses
// the response body.
func (d *DoH) doExchange(ctx context.Context, msg *dns.Msg, recordHealth bool) (*dns.Msg, error) {
	payload, err := msg.Pack()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.url, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/dns-message")
	req.Header.Set("accept", "application/dns-message")

	resp, err := d.client.Do(req)
	if err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		if recordHealth {
			d.RecordFailure(fmt.Errorf("http status %d", resp.StatusCode))
		}
		return nil, fmt.Errorf("doh upstream returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	dnsResp := new(dns.Msg)
	if err := dnsResp.Unpack(body); err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if recordHealth {
		d.RecordSuccess()
	}
	return dnsResp, nil
}
