package upstream

import (
	"context"
	"crypto/tls"
	"net"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/pool"
)

type DoT struct {
	address      string
	pool         *pool.TLSConnPool
	health       healthState
	trackTraffic bool
}

func NewDoT(cfg config.UpstreamConfig, pool *pool.TLSConnPool, trackTraffic bool) *DoT {
	return &DoT{address: cfg.URL, pool: pool, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic}
}

func (d *DoT) ID() string { return d.address }

func (d *DoT) Healthy() bool { return d.health.healthy() }

func (d *DoT) RecordSuccess() { d.health.success() }

func (d *DoT) RecordFailure(err error) { d.health.failure() }

func (d *DoT) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.trackTraffic)
}

func (d *DoT) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, true)
	return err
}

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
func MakeTLSFactory(address string, tlsConfig *tls.Config, dialer *net.Dialer) pool.TLSConnFactory {
	return func(ctx context.Context) (net.Conn, error) {
		d := tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		return d.DialContext(ctx, "tcp", address)
	}
}
