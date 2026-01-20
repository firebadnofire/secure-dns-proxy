// Package upstream implements DNS upstream protocols.
package upstream

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/pool"
)

// DoT implements DNS-over-TLS exchanges using a connection pool.
type DoT struct {
	// address is the TLS endpoint host:port.
	address string
	// pool provides reusable TLS connections.
	pool *pool.TLSConnPool
	// health tracks failures for circuit breaking.
	health healthState
	// trackTraffic toggles whether to count success/failure on normal traffic.
	trackTraffic bool
	// healthEnabled toggles circuit breaker logic.
	healthEnabled bool
}

// NewDoT constructs a DoT upstream with pooled TLS connections.
func NewDoT(cfg config.UpstreamConfig, pool *pool.TLSConnPool, trackTraffic bool, healthEnabled bool) *DoT {
	return &DoT{address: cfg.URL, pool: pool, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

// ID returns the upstream address used for logging and selection.
func (d *DoT) ID() string { return d.address }

// Healthy reports whether the upstream is eligible for use.
func (d *DoT) Healthy() bool { return d.health.healthy() }

// RecordSuccess resets failure counters.
func (d *DoT) RecordSuccess() { d.health.success() }

// RecordFailure increments failure counters and triggers cooldown.
func (d *DoT) RecordFailure(err error) { d.health.failure() }

// Exchange performs a DNS-over-TLS query, honoring circuit breaker state.
func (d *DoT) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if d.healthEnabled && !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.healthEnabled && d.trackTraffic)
}

func (d *DoT) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, d.healthEnabled)
	return err
}

// doExchange acquires a TLS connection, writes the DNS query, and reads a reply.
func (d *DoT) doExchange(ctx context.Context, msg *dns.Msg, recordHealth bool) (*dns.Msg, error) {
	conn, release, err := d.pool.Acquire(ctx)
	if err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	releaseOnce := func(e error) {
		if release != nil {
			release(e)
			release = nil
		}
	}
	defer releaseOnce(nil)

	if deadline, ok := ctx.Deadline(); ok {
		// Enforce the caller's deadline on the socket.
		_ = conn.SetDeadline(deadline)
	}

	tcp := &dns.Conn{Conn: conn}
	if err := tcp.WriteMsg(msg); err != nil {
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	resp, err := tcp.ReadMsg()
	releaseOnce(err)
	if err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if recordHealth {
		d.RecordSuccess()
	}
	return resp, nil
}

// MakeTLSFactory returns a dialer for the TLS pool.
// It wraps the net.Dialer and TLS config into a factory callback.
func MakeTLSFactory(address string, tlsConfig *tls.Config, dialer *net.Dialer) pool.TLSConnFactory {
	return func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		return d.DialContext(ctx, "tcp", address)
	}
}
