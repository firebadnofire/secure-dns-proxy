package upstream

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	quic "github.com/quic-go/quic-go"
)

type bootstrapDialTargets struct {
	hostname string
	port     string
	strategy string

	mu    sync.Mutex
	addrs []string
	rr    atomic.Uint64
}

func newBootstrapDialTargets(hostname, port string, ips []net.IP, strategy string) (*bootstrapDialTargets, error) {
	if hostname == "" || port == "" {
		return nil, fmt.Errorf("bootstrap target requires hostname and port")
	}
	if strategy == "" {
		strategy = "failover"
	}
	targets := &bootstrapDialTargets{hostname: hostname, port: port, strategy: strategy}
	for _, ip := range ips {
		if ip == nil {
			return nil, fmt.Errorf("bootstrap contains invalid ip")
		}
		targets.addrs = append(targets.addrs, net.JoinHostPort(ip.String(), port))
	}
	return targets, nil
}

func (b *bootstrapDialTargets) dialContext(ctx context.Context, network string, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if len(b.addrs) == 0 {
		return dial(ctx, network, net.JoinHostPort(b.hostname, b.port))
	}
	switch b.strategy {
	case "race":
		conn, addr, err := raceDial(ctx, b.snapshot(), func(raceCtx context.Context, target string) (net.Conn, error) {
			return dial(raceCtx, network, target)
		}, func(conn net.Conn) {
			_ = conn.Close()
		})
		if err == nil {
			b.promote(addr)
		}
		return conn, err
	case "round_robin":
		return b.dialSequential(ctx, network, dial, b.roundRobinOrder(), false)
	default:
		return b.dialSequential(ctx, network, dial, b.snapshot(), true)
	}
}

func (b *bootstrapDialTargets) dialQUIC(ctx context.Context, dial func(context.Context, string) (quic.EarlyConnection, error)) (quic.EarlyConnection, error) {
	if len(b.addrs) == 0 {
		return dial(ctx, net.JoinHostPort(b.hostname, b.port))
	}
	switch b.strategy {
	case "race":
		conn, addr, err := raceDial(ctx, b.snapshot(), dial, func(conn quic.EarlyConnection) {
			_ = conn.CloseWithError(0, "race loser")
		})
		if err == nil {
			b.promote(addr)
		}
		return conn, err
	case "round_robin":
		return b.dialQUICSequential(ctx, dial, b.roundRobinOrder(), false)
	default:
		return b.dialQUICSequential(ctx, dial, b.snapshot(), true)
	}
}

func (b *bootstrapDialTargets) dialSequential(ctx context.Context, network string, dial func(context.Context, string, string) (net.Conn, error), addrs []string, promote bool) (net.Conn, error) {
	var lastErr error
	for _, addr := range addrs {
		conn, err := dial(ctx, network, addr)
		if err == nil {
			if promote {
				b.promote(addr)
			}
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no bootstrap addresses configured")
	}
	return nil, lastErr
}

func (b *bootstrapDialTargets) dialQUICSequential(ctx context.Context, dial func(context.Context, string) (quic.EarlyConnection, error), addrs []string, promote bool) (quic.EarlyConnection, error) {
	var lastErr error
	for _, addr := range addrs {
		conn, err := dial(ctx, addr)
		if err == nil {
			if promote {
				b.promote(addr)
			}
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no bootstrap addresses configured")
	}
	return nil, lastErr
}

func (b *bootstrapDialTargets) snapshot() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.addrs...)
}

func (b *bootstrapDialTargets) roundRobinOrder() []string {
	addrs := b.snapshot()
	if len(addrs) < 2 {
		return addrs
	}
	start := int(b.rr.Add(1)-1) % len(addrs)
	ordered := make([]string, 0, len(addrs))
	ordered = append(ordered, addrs[start:]...)
	ordered = append(ordered, addrs[:start]...)
	return ordered
}

func (b *bootstrapDialTargets) promote(addr string) {
	if addr == "" {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for i := range b.addrs {
		if b.addrs[i] != addr {
			continue
		}
		if i == 0 {
			return
		}
		copy(b.addrs[1:i+1], b.addrs[0:i])
		b.addrs[0] = addr
		return
	}
}

type raceResult[T any] struct {
	value T
	addr  string
	err   error
}

func raceDial[T any](ctx context.Context, addrs []string, dial func(context.Context, string) (T, error), closeFn func(T)) (T, string, error) {
	var zero T
	if len(addrs) == 0 {
		return zero, "", fmt.Errorf("no bootstrap addresses configured")
	}
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan raceResult[T], len(addrs))
	var claimed atomic.Bool
	for _, addr := range addrs {
		addr := addr
		go func() {
			value, err := dial(raceCtx, addr)
			if err == nil {
				if !claimed.CompareAndSwap(false, true) {
					closeFn(value)
					err = context.Canceled
					value = zero
				}
			}
			results <- raceResult[T]{value: value, addr: addr, err: err}
		}()
	}

	var lastErr error
	for range addrs {
		result := <-results
		if result.err == nil {
			cancel()
			return result.value, result.addr, nil
		}
		if !errors.Is(result.err, context.Canceled) || lastErr == nil {
			lastErr = result.err
		}
	}
	if lastErr == nil {
		lastErr = context.Canceled
	}
	return zero, "", lastErr
}
