package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadTOMLConfig(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "config.toml", `
bind_address = "127.0.0.1"
port = 8053
insecure_tls = true
upstream_policy = "race"
upstream_race_fanout = 3
prewarm_pools = false

[[upstreams]]
url = "https://example.com/dns-query"
bootstrap = "192.0.2.10"
max_failures = 4
cooldown = "45s"
weight = 7

[[upstreams]]
url = "tls://resolver.example:853"
bootstrap = "192.0.2.20"
max_failures = 2
cooldown = 120000000000
weight = 3

[cache]
enabled = false
capacity = 512
default_ttl = "20s"
negative_ttl = "7s"
respect_record_ttl = false

[pools.tls]
size = 24
idle_timeout = "2m"

[pools.quic]
size = 10
idle_timeout = 45000000000

[pools.http_transport]
max_idle_conns = 256
max_idle_conns_per_host = 48
idle_conn_timeout = "75s"
tls_handshake_timeout = "4s"

[timeouts]
upstream = 5000000000
dial = "1500ms"
read = "2500ms"

[rate_limit]
max_in_flight = 2048

[logging]
level = "debug"

[metrics]
enabled = false

[health_checks]
enabled = false
interval = "30s"
query = "example.org."
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.BindAddress != "127.0.0.1" {
		t.Fatalf("bind address = %q", cfg.BindAddress)
	}
	if cfg.Port != 8053 {
		t.Fatalf("port = %d", cfg.Port)
	}
	if !cfg.InsecureTLS {
		t.Fatalf("insecure_tls = false")
	}
	if cfg.UpstreamPolicy != "race" {
		t.Fatalf("upstream policy = %q", cfg.UpstreamPolicy)
	}
	if cfg.UpstreamRaceFanout != 3 {
		t.Fatalf("upstream race fanout = %d", cfg.UpstreamRaceFanout)
	}
	if len(cfg.Upstreams) != 2 {
		t.Fatalf("upstreams = %d", len(cfg.Upstreams))
	}
	if len(cfg.Upstreams[0].Bootstrap) != 1 || cfg.Upstreams[0].Bootstrap[0].String() != "192.0.2.10" {
		t.Fatalf("bootstrap[0] = %v", cfg.Upstreams[0].Bootstrap)
	}
	if cfg.Upstreams[0].BootstrapStrategy != "failover" {
		t.Fatalf("bootstrap_strategy[0] = %q", cfg.Upstreams[0].BootstrapStrategy)
	}
	if cfg.Upstreams[0].Cooldown.Duration() != 45*time.Second {
		t.Fatalf("cooldown = %s", cfg.Upstreams[0].Cooldown.Duration())
	}
	if len(cfg.Upstreams[1].Bootstrap) != 1 || cfg.Upstreams[1].Bootstrap[0].String() != "192.0.2.20" {
		t.Fatalf("bootstrap[1] = %v", cfg.Upstreams[1].Bootstrap)
	}
	if cfg.Upstreams[1].Cooldown.Duration() != 120*time.Second {
		t.Fatalf("cooldown[1] = %s", cfg.Upstreams[1].Cooldown.Duration())
	}
	if cfg.Upstreams[1].Weight != 3 {
		t.Fatalf("weight[1] = %d", cfg.Upstreams[1].Weight)
	}
	if cfg.Cache.Enabled {
		t.Fatalf("cache.enabled = true")
	}
	if cfg.Cache.Capacity != 512 {
		t.Fatalf("cache.capacity = %d", cfg.Cache.Capacity)
	}
	if cfg.Cache.DefaultTTL.Duration() != 20*time.Second {
		t.Fatalf("cache.default_ttl = %s", cfg.Cache.DefaultTTL.Duration())
	}
	if cfg.Cache.NegativeTTL.Duration() != 7*time.Second {
		t.Fatalf("cache.negative_ttl = %s", cfg.Cache.NegativeTTL.Duration())
	}
	if cfg.Cache.RespectRecordTTL {
		t.Fatalf("cache.respect_record_ttl = true")
	}
	if cfg.Pools.TLS.Size != 24 {
		t.Fatalf("pools.tls.size = %d", cfg.Pools.TLS.Size)
	}
	if cfg.Pools.TLS.IdleTimeout.Duration() != 2*time.Minute {
		t.Fatalf("pools.tls.idle_timeout = %s", cfg.Pools.TLS.IdleTimeout.Duration())
	}
	if cfg.Pools.QUIC.Size != 10 {
		t.Fatalf("pools.quic.size = %d", cfg.Pools.QUIC.Size)
	}
	if cfg.Pools.QUIC.IdleTimeout.Duration() != 45*time.Second {
		t.Fatalf("pools.quic.idle_timeout = %s", cfg.Pools.QUIC.IdleTimeout.Duration())
	}
	if cfg.Pools.HTTPTransport.MaxIdleConns != 256 {
		t.Fatalf("pools.http_transport.max_idle_conns = %d", cfg.Pools.HTTPTransport.MaxIdleConns)
	}
	if cfg.Pools.HTTPTransport.MaxIdleConnsPerHost != 48 {
		t.Fatalf("pools.http_transport.max_idle_conns_per_host = %d", cfg.Pools.HTTPTransport.MaxIdleConnsPerHost)
	}
	if cfg.Pools.HTTPTransport.IdleConnTimeout.Duration() != 75*time.Second {
		t.Fatalf("pools.http_transport.idle_conn_timeout = %s", cfg.Pools.HTTPTransport.IdleConnTimeout.Duration())
	}
	if cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration() != 4*time.Second {
		t.Fatalf("pools.http_transport.tls_handshake_timeout = %s", cfg.Pools.HTTPTransport.TLSHandshakeTimeout.Duration())
	}
	if cfg.Timeouts.Upstream.Duration() != 5*time.Second {
		t.Fatalf("upstream timeout = %s", cfg.Timeouts.Upstream.Duration())
	}
	if cfg.Timeouts.Dial.Duration() != 1500*time.Millisecond {
		t.Fatalf("dial timeout = %s", cfg.Timeouts.Dial.Duration())
	}
	if cfg.Timeouts.Read.Duration() != 2500*time.Millisecond {
		t.Fatalf("read timeout = %s", cfg.Timeouts.Read.Duration())
	}
	if cfg.RateLimit.MaxInFlight != 2048 {
		t.Fatalf("rate_limit.max_in_flight = %d", cfg.RateLimit.MaxInFlight)
	}
	if cfg.Logging.Level != "debug" {
		t.Fatalf("logging.level = %q", cfg.Logging.Level)
	}
	if cfg.Metrics.Enabled {
		t.Fatalf("metrics.enabled = true")
	}
	if cfg.HealthChecks.Enabled {
		t.Fatalf("health_checks.enabled = true")
	}
	if cfg.HealthChecks.Interval.Duration() != 30*time.Second {
		t.Fatalf("health_checks.interval = %s", cfg.HealthChecks.Interval.Duration())
	}
	if cfg.HealthChecks.Query != "example.org." {
		t.Fatalf("health_checks.query = %q", cfg.HealthChecks.Query)
	}
	if cfg.PrewarmPools {
		t.Fatalf("prewarm pools = true")
	}
}

func TestLoadUsesDefaultsForUnsetValues(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "partial.toml", `
port = 5300

[[upstreams]]
url = "https://example.com/dns-query"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	def := Default()
	if cfg.BindAddress != def.BindAddress {
		t.Fatalf("bind address = %q, want %q", cfg.BindAddress, def.BindAddress)
	}
	if cfg.Port != 5300 {
		t.Fatalf("port = %d", cfg.Port)
	}
	if cfg.Timeouts.Upstream.Duration() != def.Timeouts.Upstream.Duration() {
		t.Fatalf("upstream timeout = %s, want %s", cfg.Timeouts.Upstream.Duration(), def.Timeouts.Upstream.Duration())
	}
	if cfg.Cache.Capacity != def.Cache.Capacity {
		t.Fatalf("cache.capacity = %d, want %d", cfg.Cache.Capacity, def.Cache.Capacity)
	}
	if cfg.PrewarmPools != def.PrewarmPools {
		t.Fatalf("prewarm_pools = %v, want %v", cfg.PrewarmPools, def.PrewarmPools)
	}
}

func TestLoadSkipsMissingPaths(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "fallback.toml", `
bind_address = "127.0.0.99"

[[upstreams]]
url = "tls://resolver.example:853"
`)

	cfg, err := Load(filepath.Join(t.TempDir(), "missing.toml"), path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.BindAddress != "127.0.0.99" {
		t.Fatalf("bind address = %q", cfg.BindAddress)
	}
}

func TestLoadRejectsInvalidDurations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name: "bad duration string",
			data: `
[[upstreams]]
url = "https://example.com/dns-query"

[timeouts]
upstream = "not-a-duration"
`,
			wantErr: "time: invalid duration",
		},
		{
			name: "unsupported duration type",
			data: `
[[upstreams]]
url = "https://example.com/dns-query"

[timeouts]
upstream = true
`,
			wantErr: "invalid duration type bool",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			path := writeConfigFile(t, tc.name+".toml", tc.data)
			_, err := Load(path)
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %q, want substring %q", err, tc.wantErr)
			}
		})
	}
}

func TestLoadMissingConfig(t *testing.T) {
	t.Parallel()

	_, err := Load(filepath.Join(t.TempDir(), "missing.toml"))
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no configuration file found") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadParsesBootstrapArrayAndStrategy(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "bootstrap-array.toml", `
[[upstreams]]
url = "quic://resolver.example:784"
bootstrap = ["192.0.2.10", "2001:db8::1"]
bootstrap_strategy = "round_robin"
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Upstreams) != 1 {
		t.Fatalf("upstreams = %d", len(cfg.Upstreams))
	}
	if len(cfg.Upstreams[0].Bootstrap) != 2 {
		t.Fatalf("bootstrap len = %d", len(cfg.Upstreams[0].Bootstrap))
	}
	if cfg.Upstreams[0].Bootstrap[0].String() != "192.0.2.10" {
		t.Fatalf("bootstrap[0] = %s", cfg.Upstreams[0].Bootstrap[0])
	}
	if cfg.Upstreams[0].Bootstrap[1].String() != "2001:db8::1" {
		t.Fatalf("bootstrap[1] = %s", cfg.Upstreams[0].Bootstrap[1])
	}
	if cfg.Upstreams[0].BootstrapStrategy != "round_robin" {
		t.Fatalf("bootstrap_strategy = %q", cfg.Upstreams[0].BootstrapStrategy)
	}
}

func TestLoadRejectsNonIPBootstrap(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "bad-bootstrap.toml", `
[[upstreams]]
url = "https://resolver.example/dns-query"
bootstrap = "resolver.example"
`)

	_, err := Load(path)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "not an IP address") {
		t.Fatalf("error = %q", err)
	}
}

func writeConfigFile(t *testing.T, name string, data string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
