# secure-dns-proxy

`secure-dns-proxy` is a local DNS stub that accepts UDP/TCP DNS queries and forwards them to plaintext DNS, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), or DNS-over-QUIC (DoQ) upstreams. The rewrite focuses on efficient connection reuse, pluggable upstream policies, caching, and safe concurrency for high-QPS workloads.

## Features
- UDP/TCP ingress backed by `miekg/dns` with graceful shutdown
- Pluggable upstream selection: round-robin (default), sequential fallback, or parallel race fanout
- Connection reuse pools for DoT and DoQ with optional pre-warming
- Shared HTTP transport for DoH keep-alives
- Positive and negative TTL caching with request coalescing
- Rate limiting/backpressure to cap concurrent upstream work
- Circuit-breaker style upstream health tracking
- Structured logging and lightweight internal metrics hooks
- EDNS0 support with sane defaults

## Getting started
Build with Go 1.22 or newer:

```sh
go build ./cmd/secure-dns-proxy
```

Run with a JSON configuration file:

```sh
./secure-dns-proxy --config config.example.json
```

## Installation

Use the provided Makefile to install the binary, example configuration, systemd service unit, and sysctl tuning for QUIC UDP buffers:

```sh
sudo make install
```

By default this places the binary in `/usr/local/bin`, an example config in `/etc/secure-dns-proxy/config.example.json`, a systemd unit at `/etc/systemd/system/secure-dns-proxy.service`, and a sysctl drop-in at `/etc/sysctl.d/80-secure-dns-proxy.conf`. To run the service, create `/etc/secure-dns-proxy/config.json` with your settings and enable/start the unit:

```sh
sudo systemctl enable --now secure-dns-proxy.service
```

### Example configuration (config.example.json)
```json
{
  "bind_address": "127.0.0.35",
  "port": 53,
  "insecure_tls": false,
  "upstream_policy": "round_robin",
  "upstream_race_fanout": 2,
  "upstreams": [
    {"url": "https://doh.archuser.org/dns-query"},
    {"url": "tls://doh.archuser.org:853"},
    {"url": "quic://doh.archuser.org:853"}
  ],
  "cache": {
    "enabled": true,
    "capacity": 2048,
    "default_ttl": "15s",
    "negative_ttl": "10s",
    "respect_record_ttl": true
  },
  "pools": {
    "tls": {"size": 16, "idle_timeout": "90s"},
    "quic": {"size": 8, "idle_timeout": "90s"},
    "http_transport": {
      "max_idle_conns": 128,
      "max_idle_conns_per_host": 32,
      "idle_conn_timeout": "90s",
      "tls_handshake_timeout": "5s"
    }
  },
  "timeouts": {
    "upstream": "5s",
    "dial": "2s",
    "read": "3s"
  },
  "rate_limit": {"max_in_flight": 1024},
  "logging": {"level": "info"},
  "metrics": {"enabled": true},
  "prewarm_pools": true
}
```

> **Cold start tip:** enabling `prewarm_pools` primes DoT/DoQ connections during startup. If prewarming cannot complete (e.g.,
> due to firewalls or ALPN mismatches), the first live query may spend extra time establishing connections before reusing pool
> state for subsequent lookups.

### Notes on architecture changes
- **DoH transport reuse:** a single tuned `http.Client` backs all DoH requests to preserve keep-alives.
- **Connection pools:** DoT and DoQ share configurable pools with optional pre-warming to reduce handshake latency.
- **DoQ correctness:** requests close the write side only after sending, then read the response before closing the stream.
- **Timeout hygiene:** timeouts are enforced via contexts without leaking deadlines onto pooled connections.
- **Caching & coalescing:** identical in-flight queries collapse to one upstream call; responses populate positive/negative TTL caches per RFC 2308.
- **Health & policy:** upstreams track failures and back off; round-robin, sequential, and race policies balance resiliency and latency.
- **Backpressure:** a limiter caps concurrent upstream work to prevent dial storms during spikes.
- **Logging:** only state changes and errors are logged; verbosity is configurable.

## License
GNU Affero General Public License v3.0
