# Scaling secure-dns-proxy toward dnsdist-class deployments

This document explains what is needed to operate `secure-dns-proxy` at large-enterprise or carrier-scale loads and how it differs from purpose-built load-balancing proxies such as PowerDNS dnsdist.

## Current capabilities
- Single-process Go binary using the Go runtime for scheduling.
- UDP/TCP ingress using `miekg/dns` with per-request goroutines.
- Upstream policies: round-robin, sequential fallback, or parallel race fanout.
- Passive health tracking with simple backoff/circuit-breaker behavior.
- Connection pooling for DoT/DoQ and shared transport for DoH to reduce handshake churn.
- In-memory positive/negative caching with request coalescing.
- Basic backpressure via a global in-flight limiter.

## Gaps relative to dnsdist
- No kernel-bypass I/O (DPDK/eBPF/AF_XDP) or multi-process sharding; packet ingress remains limited by the Go runtime and kernel UDP socket performance.
- No per-frontend worker pinning, receive-side scaling tuning, or NUMA-aware memory layout.
- Limited observability (no built-in Prometheus/StatsD exporter, histograms, or tracing) compared to dnsdist's mature telemetry.
- Simplified health checking: lacks active probes, per-upstream SLO tracking, and latency-aware load balancing.
- Rule engine absent (e.g., dnsdist's Lua), so adaptive routing, ACLs, or per-tenant policies require code changes.
- Cache is in-memory only with FIFO eviction; not shared across instances and lacks persistence or clustering.

## Feasibility and recommended path
It is feasible to evolve `secure-dns-proxy` toward dnsdist-like scalability, but it requires significant engineering beyond the current single-binary design. The following roadmap items are prioritized for enterprise readiness:

1. **Ingress throughput**
   - Introduce worker sharding (one process or goroutine set per CPU core) and pin sockets to CPUs.
   - Add support for `SO_REUSEPORT` with multiple listeners to improve parallel accept/recv throughput.
   - Investigate kernel-bypass (AF_XDP or io_uring) for high-QPS UDP paths.

2. **Advanced load balancing**
   - Implement latency-aware and EWMA-based policies in addition to round-robin/race.
   - Add active health probes with configurable intervals and failure budgets.
   - Support per-upstream weightings and automatic removal/rehabilitation based on health.

3. **Caching and coalescing**
   - Replace FIFO with size- and TTL-aware eviction (ARC/LRU) and consider sharded caches for lock contention reduction.
   - Provide optional distributed cache (e.g., memcached/redis) or peer-to-peer cache sync to improve multi-instance hit rates.

4. **Backpressure and admission control**
   - Move from a global in-flight semaphore to per-protocol/per-upstream quotas.
   - Add adaptive shedding (e.g., fail fast when queues build) and per-source rate limits to protect the service under floods.

5. **Observability**
   - Export Prometheus/StatsD metrics with histograms for latency and pool behavior.
   - Integrate OpenTelemetry tracing hooks for upstream calls and cache decisions.
   - Add structured access/event logging with sampling controls.

6. **Deployment topology**
   - Support multi-instance clustering with consistent hashing of queries (by client or query key) to improve cache locality.
   - Provide configuration reloads and runtime control plane (e.g., gRPC/REST) for dynamic upstream and policy changes.

7. **Resilience and security**
   - Harden TLS/QUIC settings for modern cipher suites and key logging controls.
   - Add ACLs, DNS response policy zones (RPZ), and query inspection hooks for enterprise governance.

## Configuration guidance for load-balanced upstreams
The current proxy supports upstream load balancing through the `upstream_policy` field. For enterprise deployments, start with latency-friendly race fanout and tune pool sizes for reuse:

```jsonc
{
  "upstream_policy": "race",           // or "round_robin" / "sequential"
  "upstream_race_fanout": 3,            // number of upstreams to query in parallel
  "pools": {
    "tls": {"size": 128, "idle_timeout": "120s"},
    "quic": {"size": 64, "idle_timeout": "120s"},
    "http_transport": {
      "max_idle_conns": 512,
      "max_idle_conns_per_host": 128,
      "idle_conn_timeout": "120s",
      "tls_handshake_timeout": "5s"
    }
  },
  "rate_limit": {"max_in_flight": 8192},
  "prewarm_pools": true
}
```

For highly bursty workloads, prefer `race` with a small fanout to hide slow upstreams. For steady-state balanced load, `round_robin` provides even distribution with lower upstream amplification.

## Bottom line
`secure-dns-proxy` can be evolved into a dnsdist-scale system, but it will require substantial additions: advanced load balancing and health probing, richer cache and observability, adaptive backpressure, multi-instance sharding, and potentially kernel-bypass ingress. The present codebase is a solid foundation for a high-performance stub but is not yet a drop-in replacement for dnsdist in large enterprise environments.
