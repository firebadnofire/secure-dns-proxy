package metrics

import "sync/atomic"

type Metrics struct {
	UpstreamSuccess  atomic.Uint64
	UpstreamFailures atomic.Uint64
	CacheHits        atomic.Uint64
	CacheMisses      atomic.Uint64
	PoolHits         atomic.Uint64
	PoolMisses       atomic.Uint64
	InFlightRequests atomic.Int64
	Requests         atomic.Uint64
	TrafficInBytes   atomic.Uint64
	TrafficOutBytes  atomic.Uint64
}

func (m *Metrics) RecordCacheHit()  { m.CacheHits.Add(1) }
func (m *Metrics) RecordCacheMiss() { m.CacheMisses.Add(1) }
func (m *Metrics) RecordPoolHit()   { m.PoolHits.Add(1) }
func (m *Metrics) RecordPoolMiss()  { m.PoolMisses.Add(1) }
func (m *Metrics) RecordSuccess()   { m.UpstreamSuccess.Add(1) }
func (m *Metrics) RecordFailure()   { m.UpstreamFailures.Add(1) }
func (m *Metrics) IncInFlight()     { m.InFlightRequests.Add(1) }
func (m *Metrics) DecInFlight()     { m.InFlightRequests.Add(-1) }

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
