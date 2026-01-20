// Package metrics holds lightweight counters for proxy instrumentation.
package metrics

import "sync/atomic"

// Metrics stores counters updated by various components.
// Atomic types allow lock-free increments on hot paths.
type Metrics struct {
	// UpstreamSuccess/Failures capture upstream response outcomes.
	UpstreamSuccess  atomic.Uint64
	UpstreamFailures atomic.Uint64
	// CacheHits/Misses track cache performance.
	CacheHits   atomic.Uint64
	CacheMisses atomic.Uint64
	// PoolHits/Misses track connection pool reuse efficiency.
	PoolHits   atomic.Uint64
	PoolMisses atomic.Uint64
	// InFlightRequests counts active upstream exchanges.
	InFlightRequests atomic.Int64
	// Requests counts total DNS queries seen by the proxy.
	Requests atomic.Uint64
	// TrafficInBytes/OutBytes track byte counts for ingress/egress.
	TrafficInBytes  atomic.Uint64
	TrafficOutBytes atomic.Uint64
}

// RecordCacheHit increments the cache hit counter.
func (m *Metrics) RecordCacheHit() { m.CacheHits.Add(1) }

// RecordCacheMiss increments the cache miss counter.
func (m *Metrics) RecordCacheMiss() { m.CacheMisses.Add(1) }

// RecordPoolHit increments the connection pool hit counter.
func (m *Metrics) RecordPoolHit() { m.PoolHits.Add(1) }

// RecordPoolMiss increments the connection pool miss counter.
func (m *Metrics) RecordPoolMiss() { m.PoolMisses.Add(1) }

// RecordSuccess increments the upstream success counter.
func (m *Metrics) RecordSuccess() { m.UpstreamSuccess.Add(1) }

// RecordFailure increments the upstream failure counter.
func (m *Metrics) RecordFailure() { m.UpstreamFailures.Add(1) }

// IncInFlight increments the active upstream request gauge.
func (m *Metrics) IncInFlight() { m.InFlightRequests.Add(1) }

// DecInFlight decrements the active upstream request gauge.
func (m *Metrics) DecInFlight() { m.InFlightRequests.Add(-1) }

// RecordRequest increments the total request counter and returns the new total.
func (m *Metrics) RecordRequest() uint64 {
	return m.Requests.Add(1)
}

// AddTraffic records ingress and egress byte counts and returns new totals.
func (m *Metrics) AddTraffic(inBytes, outBytes uint64) (uint64, uint64) {
	inTotal := m.TrafficInBytes.Add(inBytes)
	outTotal := m.TrafficOutBytes.Add(outBytes)
	return inTotal, outTotal
}
