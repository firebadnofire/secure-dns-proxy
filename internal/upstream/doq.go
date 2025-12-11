package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/pool"
)

type DoQ struct {
	address string
	pool    *pool.QUICConnPool
	tlsConf *tls.Config
	health  healthState
}

func NewDoQ(cfg config.UpstreamConfig, pool *pool.QUICConnPool, tlsConf *tls.Config) *DoQ {
	return &DoQ{address: cfg.URL, pool: pool, tlsConf: tlsConf, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration())}
}

func (d *DoQ) ID() string { return d.address }

func (d *DoQ) Healthy() bool { return d.health.healthy() }

func (d *DoQ) RecordSuccess() { d.health.success() }

func (d *DoQ) RecordFailure(err error) { d.health.failure() }

func (d *DoQ) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	session, release, err := d.pool.Acquire(ctx)
	if err != nil {
		d.RecordFailure(err)
		return nil, err
	}
	releaseOnce := func(e error) {
		if release != nil {
			release(e)
			release = nil
		}
	}
	defer releaseOnce(nil)

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		releaseOnce(err)
		d.RecordFailure(err)
		return nil, err
	}

	payload, err := msg.Pack()
	if err != nil {
		releaseOnce(err)
		return nil, err
	}
	if _, err := stream.Write(payload); err != nil {
		stream.CancelWrite(0)
		releaseOnce(err)
		d.RecordFailure(err)
		return nil, err
	}
	if err := stream.Close(); err != nil {
		stream.CancelWrite(0)
		releaseOnce(err)
		d.RecordFailure(err)
		return nil, err
	}

	respBuf, err := io.ReadAll(stream)
	releaseOnce(err)
	if err != nil {
		d.RecordFailure(err)
		return nil, err
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		d.RecordFailure(err)
		return nil, err
	}
	d.RecordSuccess()
	return response, nil
}

// MakeQUICFactory constructs a QUIC dialer suitable for pooling.
func MakeQUICFactory(address string, tlsConf *tls.Config, dialer *net.Dialer) pool.QUICConnFactory {
	return func(ctx context.Context) (quic.Connection, error) {
		d := *dialer
		d.Timeout = 0
		return quic.DialAddrEarly(ctx, address, tlsConf, &quic.Config{KeepAlivePeriod: 30 * time.Second})
	}
}
