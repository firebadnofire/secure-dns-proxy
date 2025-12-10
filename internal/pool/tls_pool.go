package pool

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
)

type TLSConnFactory func(ctx context.Context) (net.Conn, error)

type pooledTLSConn struct {
	conn     net.Conn
	lastUsed time.Time
}

// TLSConnPool manages reusable TLS connections with configurable capacity.
type TLSConnPool struct {
	size        int
	idleTimeout time.Duration
	conns       chan pooledTLSConn
	factory     TLSConnFactory
	log         logging.Logger
	metrics     *metrics.Metrics
}

func NewTLSConnPool(size int, idleTimeout time.Duration, factory TLSConnFactory, log logging.Logger, metrics *metrics.Metrics) *TLSConnPool {
	if size <= 0 {
		size = 1
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &TLSConnPool{size: size, idleTimeout: idleTimeout, conns: make(chan pooledTLSConn, size), factory: factory, log: log, metrics: metrics}
}

// Acquire returns a connection and a release function to be called when finished.
func (p *TLSConnPool) Acquire(ctx context.Context) (net.Conn, func(error), error) {
	for {
		select {
		case pc := <-p.conns:
			if time.Since(pc.lastUsed) > p.idleTimeout {
				_ = pc.conn.Close()
				continue
			}
			if tcp, ok := pc.conn.(*tls.Conn); ok {
				_ = tcp.SetDeadline(time.Time{})
			}
			if p.metrics != nil {
				p.metrics.RecordPoolHit()
			}
			conn := pc.conn
			return conn, func(err error) { p.Release(conn, err) }, nil
		default:
			if p.metrics != nil {
				p.metrics.RecordPoolMiss()
			}
			conn, err := p.factory(ctx)
			if err != nil {
				return nil, nil, err
			}
			return conn, func(err error) { p.Release(conn, err) }, nil
		}
	}
}

// Prewarm fills the pool up to capacity to reduce handshake latency.
func (p *TLSConnPool) Prewarm(ctx context.Context) {
	for i := 0; i < p.size; i++ {
		conn, err := p.factory(ctx)
		if err != nil {
			p.log.Warn("prewarm tls conn failed", "error", err)
			return
		}
		p.tryStore(conn)
	}
}

// Release returns connection to pool if healthy.
func (p *TLSConnPool) Release(conn net.Conn, err error) {
	if conn == nil {
		return
	}
	if err != nil {
		_ = conn.Close()
		return
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		_ = tlsConn.SetDeadline(time.Time{})
	}
	p.tryStore(conn)
}

func (p *TLSConnPool) tryStore(conn net.Conn) {
	select {
	case p.conns <- pooledTLSConn{conn: conn, lastUsed: time.Now()}:
	default:
		_ = conn.Close()
	}
}
