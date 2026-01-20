// Package pool provides reusable connection pools for upstream protocols.
package pool

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
)

// TLSConnFactory creates a new TLS connection on demand.
type TLSConnFactory func(ctx context.Context) (net.Conn, error)

// pooledTLSConn stores a connection plus the last-used time.
type pooledTLSConn struct {
	conn     net.Conn
	lastUsed time.Time
}

// TLSConnPool manages reusable TLS connections with configurable capacity.
type TLSConnPool struct {
	// size is the maximum number of idle connections.
	size int
	// idleTimeout closes idle connections after this duration.
	idleTimeout time.Duration
	// conns holds idle connections.
	conns chan pooledTLSConn
	// factory builds new TLS connections when the pool is empty.
	factory TLSConnFactory
	// log emits warnings during prewarm.
	log logging.Logger
	// metrics records pool hit/miss counters.
	metrics *metrics.Metrics
}

// NewTLSConnPool constructs a TLS connection pool with sane defaults.
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
			// Discard stale connections.
			if time.Since(pc.lastUsed) > p.idleTimeout {
				_ = pc.conn.Close()
				continue
			}
			// Clear deadlines before reuse.
			if tcp, ok := pc.conn.(*tls.Conn); ok {
				_ = tcp.SetDeadline(time.Time{})
			}
			if p.metrics != nil {
				p.metrics.RecordPoolHit()
			}
			conn := pc.conn
			return conn, func(err error) { p.Release(conn, err) }, nil
		default:
			// Pool miss; dial a new connection.
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
		// Close on error to avoid reusing broken connections.
		_ = conn.Close()
		return
	}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		// Clear deadlines before putting back in the pool.
		_ = tlsConn.SetDeadline(time.Time{})
	}
	p.tryStore(conn)
}

// tryStore attempts to return a connection to the pool or closes it if full.
func (p *TLSConnPool) tryStore(conn net.Conn) {
	select {
	case p.conns <- pooledTLSConn{conn: conn, lastUsed: time.Now()}:
	default:
		_ = conn.Close()
	}
}
