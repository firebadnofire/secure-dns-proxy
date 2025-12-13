package upstream

import (
	"context"
	"crypto/tls"
	"io"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/pool"
)

type DoQ struct {
	address      string
	pool         *pool.QUICConnPool
	tlsConf      *tls.Config
	health       healthState
	trackTraffic bool
}

func NewDoQ(cfg config.UpstreamConfig, pool *pool.QUICConnPool, tlsConf *tls.Config, trackTraffic bool) *DoQ {
	return &DoQ{address: cfg.URL, pool: pool, tlsConf: tlsConf, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic}
}

func (d *DoQ) ID() string { return d.address }

func (d *DoQ) Healthy() bool { return d.health.healthy() }

func (d *DoQ) RecordSuccess() { d.health.success() }

func (d *DoQ) RecordFailure(err error) { d.health.failure() }

func (d *DoQ) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.trackTraffic)
}

func (d *DoQ) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, true)
	return err
}

func (d *DoQ) doExchange(ctx context.Context, msg *dns.Msg, recordHealth bool) (*dns.Msg, error) {
	session, release, err := d.pool.Acquire(ctx)
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

	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
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
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if err := stream.Close(); err != nil {
		stream.CancelWrite(0)
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}

	respBuf, err := io.ReadAll(stream)
	releaseOnce(err)
	if err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}

	response := new(dns.Msg)
	if err := response.Unpack(respBuf); err != nil {
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if recordHealth {
		d.RecordSuccess()
	}
	return response, nil
}

// MakeQUICFactory constructs a QUIC dialer suitable for pooling.
func MakeQUICFactory(addresses []string, tlsConf *tls.Config, serverName string) pool.QUICConnFactory {
	return func(ctx context.Context) (quic.Connection, error) {
		var lastErr error
		for _, address := range addresses {
			conf := tlsConf.Clone()
			if conf == nil {
				conf = &tls.Config{}
			}
			if conf.ServerName == "" {
				conf.ServerName = serverName
			}
			conn, err := quic.DialAddrEarly(ctx, address, conf, &quic.Config{KeepAlivePeriod: 30 * time.Second})
			if err == nil {
				return conn, nil
			}
			lastErr = err
		}
		return nil, lastErr
	}
}
