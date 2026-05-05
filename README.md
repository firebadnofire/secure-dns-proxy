# secure-dns-proxy

`secure-dns-proxy` is a local DNS stub meant to replace `systemd-resolved` with a modern resolver that speaks plaintext DNS, DNS-over-HTTPS (DoH), DNS-over-TLS (DoT), and DNS-over-QUIC (DoQ). The rewrite focuses on efficient connection reuse, pluggable upstream policies, caching, and safe concurrency for high-QPS workloads.

## Features
- UDP/TCP ingress backed by `miekg/dns` with graceful shutdown
- Pluggable upstream selection: round-robin (default), sequential fallback, or parallel race fanout
- Connection reuse pools for DoT and DoQ with optional pre-warming
- Shared HTTP transport for DoH keep-alives
- Positive and negative TTL caching with request coalescing
- Rate limiting/backpressure to cap concurrent upstream work
- Active health probes (root query every 120s by default) keep health independent of live traffic; can be disabled to treat all upstreams as available
- Structured logging and lightweight internal metrics hooks
- EDNS0 support with sane defaults

## Requirements

### Build dependencies
- Go 1.22 or newer
- `make`

### Runtime dependencies
- Linux host with UDP/TCP port 53 available (the binary can run without `systemd` if launched manually)
- Optional: `setcap` to grant `CAP_NET_BIND_SERVICE` for binding privileged ports without running as root

### `make install` dependencies
The `make install` target installs a systemd service unit and sysctl drop-in; it therefore requires `systemd`, root privileges, and a writable `/etc` tree. If you do not use `systemd`, build and launch the binary manually instead of running `make install`.

## Getting started
Build with Go 1.22 or newer:

```sh
go build ./cmd/secure-dns-proxy
```

Run with a TOML configuration file:

```sh
./secure-dns-proxy --config config.example.toml
```

## Installation

Use the provided Makefile to install the binary, default/example configuration, systemd service unit, and sysctl tuning for QUIC UDP buffers:

```sh
sudo make install
```

By default this places the binary in `/usr/local/bin`, a runnable config in `/etc/secure-dns-proxy/config.toml`, an example config at `/etc/secure-dns-proxy/config.example.toml`, a systemd unit at `/etc/systemd/system/secure-dns-proxy.service`, and a sysctl drop-in at `/etc/sysctl.d/80-secure-dns-proxy.conf`. The installer also creates a dedicated `secure-dns-proxy` system user/group and owns the runnable config and `/etc/secure-dns-proxy` directory to that account.

To upgrade an existing installation while preserving user accounts and configuration files, rebuild and replace the binaries:

```sh
sudo make upgrade
```

Enable/start the unit after installation:

```sh
sudo systemctl enable --now secure-dns-proxy.service
```

The service unit requests `CAP_NET_BIND_SERVICE` and `CAP_NET_ADMIN`, allows unlimited memlock, and ships a sysctl drop-in that raises `net.core.rmem_max`/`net.core.rmem_default` and `net.core.wmem_max`/`net.core.wmem_default` to 8 MiB to satisfy QUIC UDP buffer sizing guidance. If you prefer different values, adjust `/etc/sysctl.d/80-secure-dns-proxy.conf` and reload via `sudo sysctl --system`.

On each restart the systemd unit clears `/run/secure-dns-proxy` to flush any cached runtime state before the process starts.

To remove the installation (binary, configs, unit, sysctl drop-in, and service account), use either target:

```sh
sudo make uninstall
# or
sudo make deinstall
```

### Distribution packages

The release workflow builds systemd and OpenRC tarballs plus Puppy, Debian, and
RPM-family packages. Distro-specific package artifacts use this naming pattern:

```text
secure-dns-proxy-${VERSION}-{distro}.pkg
```

The distro segment includes the target package family and architecture, for
example:

```text
secure-dns-proxy-v1.1.4-puppy-x86_64.pet
secure-dns-proxy-v1.1.4-debian-amd64.deb
secure-dns-proxy-v1.1.4-fedora-x86_64.rpm
```

Build local packages with:

```sh
make pet VERSION=v1.1.4 PET_GOARCH=amd64 PET_ARCH=x86_64
make deb VERSION=v1.1.4 DEB_GOARCH=amd64 DEB_ARCH=amd64
make rpm VERSION=v1.1.4 RPM_GOARCH=amd64 RPM_ARCH=x86_64
make openrc-package VERSION=v1.1.4-linux-arm64
```

The `.deb` target requires `dpkg-deb`; the `.rpm` target requires `rpmbuild`.
The PET, DEB, and RPM packages install `/usr/local/bin/secure-dns-proxy`, install
an example configuration, and preserve an existing
`/etc/secure-dns-proxy/config.toml` by creating it from the default template only
when it does not already exist. Puppy and OpenRC systems do not provide the
systemd sandboxing used by the systemd tarball and systemd packages; review
`packaging/puppy/README.md` or the OpenRC release README before distributing or
enabling those packages.

### Example configuration (config.example.toml)
```toml
bind_address = "127.0.0.35"
port = 53
insecure_tls = false
upstream_policy = "round_robin"
upstream_race_fanout = 2
prewarm_pools = true

[[upstreams]]
url = "https://doh.archuser.org/dns-query"
bootstrap = ["9.9.9.9", "149.112.112.112"]
bootstrap_strategy = "failover"

[[upstreams]]
url = "tls://doh.archuser.org:853"

[[upstreams]]
url = "quic://dns.adguard-dns.com:853"

[cache]
enabled = true
capacity = 2048
default_ttl = "15s"
negative_ttl = "10s"
respect_record_ttl = true

[pools.tls]
size = 16
idle_timeout = "90s"

[pools.quic]
size = 8
idle_timeout = "90s"

[pools.http_transport]
max_idle_conns = 128
max_idle_conns_per_host = 32
idle_conn_timeout = "90s"
tls_handshake_timeout = "5s"

[timeouts]
upstream = "5s"
dial = "2s"
read = "3s"

[rate_limit]
max_in_flight = 1024

[logging]
level = "info"

[metrics]
enabled = true

[health_checks]
enabled = true
interval = "120s"
query = "."
```

> **Cold start tip:** enabling `prewarm_pools` primes DoT/DoQ connections during startup. If prewarming cannot complete (e.g.,
> due to firewalls or ALPN mismatches), the first live query may spend extra time establishing connections before reusing pool
> state for subsequent lookups.

> **Bootstrap tip:** `bootstrap` accepts either a single IP string or an array of IP strings. When set for DoH, DoT, or DoQ,
> the proxy dials those IPs directly without using system DNS, while still using the upstream hostname for HTTP host routing,
> TLS SNI, and certificate validation. `bootstrap_strategy` defaults to `failover` and also supports `race` and `round_robin`.

### Notes on architecture changes
- **DoH transport reuse:** a single tuned `http.Client` backs all DoH requests to preserve keep-alives.
- **Connection pools:** DoT and DoQ share configurable pools with optional pre-warming to reduce handshake latency.
- **DoQ correctness:** requests close the write side only after sending, then read the response before closing the stream.
- **Timeout hygiene:** timeouts are enforced via contexts without leaking deadlines onto pooled connections.
- **Caching & coalescing:** identical in-flight queries collapse to one upstream call; responses populate positive/negative TTL caches per RFC 2308.
- **Health & policy:** upstreams are driven by dedicated health probes (on by default) instead of live query traffic; disabling health checks treats all upstreams as available. Round-robin, sequential, and race policies balance resiliency and latency.
- **Backpressure:** a limiter caps concurrent upstream work to prevent dial storms during spikes.
- **Logging:** only state changes and errors are logged; verbosity is configurable.

## License
GNU Affero General Public License v3.0
