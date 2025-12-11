package upstream

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
)

type DoH struct {
	url          string
	client       *http.Client
	health       healthState
	trackTraffic bool
}

func NewDoH(cfg config.UpstreamConfig, client *http.Client, trackTraffic bool) *DoH {
	return &DoH{url: cfg.URL, client: client, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic}
}

func (d *DoH) ID() string { return d.url }

func (d *DoH) Healthy() bool { return d.health.healthy() }

func (d *DoH) RecordSuccess() { d.health.success() }

func (d *DoH) RecordFailure(err error) { d.health.failure() }

func (d *DoH) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.trackTraffic)
}

func (d *DoH) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, true)
	return err
}

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
		if isNetworkError(err) {
			closeIdleHTTPConnections(d.client)
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
		if isNetworkError(err) {
			closeIdleHTTPConnections(d.client)
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

func isNetworkError(err error) bool {
	var netErr net.Error
	return errors.As(err, &netErr)
}

func closeIdleHTTPConnections(client *http.Client) {
	if transport, ok := client.Transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}
