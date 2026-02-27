// Package upstream implements DNS upstream protocols.
package upstream

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"

	quic "github.com/quic-go/quic-go"

	"github.com/miekg/dns"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/pool"
)

// DoQ implements DNS-over-QUIC exchanges.
type DoQ struct {
	// address is the QUIC endpoint host:port.
	address string
	// pool provides reusable QUIC connections.
	pool *pool.QUICConnPool
	// tlsConf configures TLS for the QUIC connection.
	tlsConf *tls.Config
	// health tracks failures for circuit breaking.
	health healthState
	// trackTraffic toggles whether to count success/failure on normal traffic.
	trackTraffic bool
	// healthEnabled toggles circuit breaker logic.
	healthEnabled bool
}

// NewDoQ constructs a DoQ upstream with pooled QUIC connections.
func NewDoQ(cfg config.UpstreamConfig, pool *pool.QUICConnPool, tlsConf *tls.Config, trackTraffic bool, healthEnabled bool) *DoQ {
	return &DoQ{address: cfg.URL, pool: pool, tlsConf: tlsConf, health: newHealthState(cfg.MaxFailures, cfg.Cooldown.Duration()), trackTraffic: trackTraffic, healthEnabled: healthEnabled}
}

// ID returns the upstream address for logging and selection.
func (d *DoQ) ID() string { return d.address }

// Healthy reports whether the upstream is eligible for use.
func (d *DoQ) Healthy() bool { return d.health.healthy() }

// RecordSuccess resets failure counters.
func (d *DoQ) RecordSuccess() { d.health.success() }

// RecordFailure increments failure counters and triggers cooldown.
func (d *DoQ) RecordFailure(err error) { d.health.failure() }

// Exchange performs a DNS-over-QUIC query, honoring circuit breaker state.
func (d *DoQ) Exchange(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	if d.healthEnabled && !d.Healthy() {
		return nil, ErrCircuitOpen
	}
	return d.doExchange(ctx, msg, d.healthEnabled && d.trackTraffic)
}

func (d *DoQ) Probe(ctx context.Context, msg *dns.Msg) error {
	_, err := d.doExchange(ctx, msg, d.healthEnabled)
	return err
}

// doExchange opens a QUIC stream, writes the DNS query, and reads the response.
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

	// Open a bidirectional stream for this query.
	stream, err := session.OpenStreamSync(ctx)
	if err != nil {
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = stream.SetDeadline(deadline)
	}

	if err := writeDoQMessage(stream, msg); err != nil {
		// Cancel write to unblock the peer if write fails.
		stream.CancelWrite(0)
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}
	if err := stream.Close(); err != nil {
		// Close can fail if the peer resets; still record failure.
		stream.CancelWrite(0)
		releaseOnce(err)
		if recordHealth {
			d.RecordFailure(err)
		}
		return nil, err
	}

	response, err := readDoQMessage(stream)
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
	return response, nil
}

// writeDoQMessage serializes DNS payload with the RFC 9250 2-byte length prefix.
func writeDoQMessage(w io.Writer, msg *dns.Msg) error {
	payload, err := msg.Pack()
	if err != nil {
		return err
	}
	if len(payload) == 0 {
		return fmt.Errorf("doq message cannot be empty")
	}
	if len(payload) > 0xffff {
		return fmt.Errorf("doq message too large: %d bytes", len(payload))
	}

	var hdr [2]byte
	binary.BigEndian.PutUint16(hdr[:], uint16(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(payload)
	return err
}

// readDoQMessage reads a single RFC 9250 length-prefixed DNS message.
func readDoQMessage(r io.Reader) (*dns.Msg, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	size := int(binary.BigEndian.Uint16(hdr[:]))
	if size == 0 {
		return nil, fmt.Errorf("doq frame length is zero")
	}

	buf := make([]byte, size)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	resp := new(dns.Msg)
	if err := resp.Unpack(buf); err != nil {
		return nil, err
	}
	return resp, nil
}

// MakeQUICFactory constructs a QUIC dialer suitable for pooling.
func MakeQUICFactory(address string, tlsConf *tls.Config, dialer *net.Dialer) pool.QUICConnFactory {
	return func(ctx context.Context) (quic.Connection, error) {
		d := *dialer
		d.Timeout = 0
		return quic.DialAddrEarly(ctx, address, tlsConf, &quic.Config{KeepAlivePeriod: 30 * time.Second})
	}
}
