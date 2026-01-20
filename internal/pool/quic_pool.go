// Package pool provides reusable connection pools for upstream protocols.
package pool

import (
	"context"
	"time"

	quic "github.com/quic-go/quic-go"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
)

// QUICConnFactory creates a new QUIC connection on demand.
type QUICConnFactory func(ctx context.Context) (quic.Connection, error)

// pooledQUIC stores a connection plus the last-used time.
type pooledQUIC struct {
	conn     quic.Connection
	lastUsed time.Time
}

// QUICConnPool manages QUIC sessions for DoQ reuse.
type QUICConnPool struct {
	// size is the maximum number of idle connections.
	size int
	// idleTimeout closes idle connections after this duration.
	idleTimeout time.Duration
	// conns holds idle connections.
	conns chan pooledQUIC
	// factory builds new QUIC connections when the pool is empty.
	factory QUICConnFactory
	// log emits warnings during prewarm.
	log logging.Logger
	// metrics records pool hit/miss counters.
	metrics *metrics.Metrics
}

// NewQUICConnPool constructs a QUIC connection pool with sane defaults.
func NewQUICConnPool(size int, idleTimeout time.Duration, factory QUICConnFactory, log logging.Logger, metrics *metrics.Metrics) *QUICConnPool {
	if size <= 0 {
		size = 1
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &QUICConnPool{size: size, idleTimeout: idleTimeout, conns: make(chan pooledQUIC, size), factory: factory, log: log, metrics: metrics}
}

// Acquire returns a connection and a release function to be called when finished.
func (p *QUICConnPool) Acquire(ctx context.Context) (quic.Connection, func(error), error) {
	for {
		select {
		case pc := <-p.conns:
			// Discard stale sessions.
			if time.Since(pc.lastUsed) > p.idleTimeout {
				pc.conn.CloseWithError(0, "expired")
				continue
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

// Prewarm establishes sessions ahead of traffic.
func (p *QUICConnPool) Prewarm(ctx context.Context) {
	for i := 0; i < p.size; i++ {
		conn, err := p.factory(ctx)
		if err != nil {
			p.log.Warn("prewarm quic conn failed", "error", err)
			return
		}
		p.tryStore(conn)
	}
}

// Release returns session to pool when healthy.
func (p *QUICConnPool) Release(conn quic.Connection, err error) {
	if conn == nil {
		return
	}
	if err != nil {
		// Close on error to avoid reusing broken sessions.
		conn.CloseWithError(0, "error")
		return
	}
	p.tryStore(conn)
}

// tryStore attempts to return a connection to the pool or closes it if full.
func (p *QUICConnPool) tryStore(conn quic.Connection) {
	select {
	case p.conns <- pooledQUIC{conn: conn, lastUsed: time.Now()}:
	default:
		conn.CloseWithError(0, "overflow")
	}
}
