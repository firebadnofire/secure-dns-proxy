package pool

import (
	"context"
	"time"

	quic "github.com/quic-go/quic-go"

	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
)

type QUICConnFactory func(ctx context.Context) (quic.Connection, error)

type pooledQUIC struct {
	conn     quic.Connection
	lastUsed time.Time
}

// QUICConnPool manages QUIC sessions for DoQ reuse.
type QUICConnPool struct {
	size        int
	idleTimeout time.Duration
	conns       chan pooledQUIC
	factory     QUICConnFactory
	log         logging.Logger
	metrics     *metrics.Metrics
}

func NewQUICConnPool(size int, idleTimeout time.Duration, factory QUICConnFactory, log logging.Logger, metrics *metrics.Metrics) *QUICConnPool {
	if size <= 0 {
		size = 1
	}
	if idleTimeout <= 0 {
		idleTimeout = 60 * time.Second
	}
	return &QUICConnPool{size: size, idleTimeout: idleTimeout, conns: make(chan pooledQUIC, size), factory: factory, log: log, metrics: metrics}
}

func (p *QUICConnPool) Acquire(ctx context.Context) (quic.Connection, func(error), error) {
	for {
		select {
		case pc := <-p.conns:
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
		conn.CloseWithError(0, "error")
		return
	}
	p.tryStore(conn)
}

func (p *QUICConnPool) tryStore(conn quic.Connection) {
	select {
	case p.conns <- pooledQUIC{conn: conn, lastUsed: time.Now()}:
	default:
		conn.CloseWithError(0, "overflow")
	}
}

// Drain closes and discards all pooled QUIC sessions.
func (p *QUICConnPool) Drain() {
	for {
		select {
		case pc := <-p.conns:
			pc.conn.CloseWithError(0, "drain")
		default:
			return
		}
	}
}
