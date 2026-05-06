package config

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoadParsesCanonicalSchema(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "config.toml", `
bind_address = "127.0.0.1"
port = 8053
insecure_tls = true
upstream_policy = "race"
upstream_race_fanout = 3
prewarm_pools = false

[bootstrap]
servers = ["9.9.9.9", "149.112.112.112"]

[upstreams]
dns = ["1.1.1.1", "resolver.example:5300"]
doh = ["https://example.com/dns-query"]
dot = ["tls://resolver.example:853"]
doq = ["quic://resolver.example:784"]

[hosts]
"example.com" = ["192.0.2.10", "2001:db8::10"]
"resolver.example" = ["192.0.2.20"]

[upstream_refresh]
enabled = true
refresh_threshold = "45s"
min_ttl = "20s"
failure_retry = "15s"
jitter_percent = 25

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

	if len(cfg.Upstreams) != 5 {
		t.Fatalf("upstreams = %d", len(cfg.Upstreams))
	}
	if cfg.Upstreams[0].Protocol != "dns" || cfg.Upstreams[1].Protocol != "dns" {
		t.Fatalf("dns upstream normalization failed: %#v %#v", cfg.Upstreams[0], cfg.Upstreams[1])
	}
	if cfg.Upstreams[2].Protocol != "https" || cfg.Upstreams[2].Hostname != "example.com" {
		t.Fatalf("doh upstream normalization failed: %#v", cfg.Upstreams[2])
	}
	if got := len(cfg.Upstreams[2].StaticHostIPs); got != 2 {
		t.Fatalf("static host IPs = %d, want 2", got)
	}
	if cfg.Upstreams[3].Protocol != "tls" || cfg.Upstreams[4].Protocol != "quic" {
		t.Fatalf("secure upstream normalization failed: %#v %#v", cfg.Upstreams[3], cfg.Upstreams[4])
	}
	if cfg.UpstreamRefresh.RefreshThreshold.Duration() != 45*time.Second {
		t.Fatalf("refresh threshold = %s", cfg.UpstreamRefresh.RefreshThreshold.Duration())
	}
	if cfg.UpstreamRefresh.MinTTL.Duration() != 20*time.Second {
		t.Fatalf("min ttl = %s", cfg.UpstreamRefresh.MinTTL.Duration())
	}
	if cfg.UpstreamRefresh.FailureRetry.Duration() != 15*time.Second {
		t.Fatalf("failure retry = %s", cfg.UpstreamRefresh.FailureRetry.Duration())
	}
	if cfg.UpstreamRefresh.JitterPercent != 25 {
		t.Fatalf("jitter percent = %d", cfg.UpstreamRefresh.JitterPercent)
	}
	if cfg.Bootstrap.Servers[0] != "9.9.9.9" {
		t.Fatalf("bootstrap server = %q", cfg.Bootstrap.Servers[0])
	}
}

func TestLoadUsesBootstrapDefaults(t *testing.T) {
	t.Parallel()

	path := writeConfigFile(t, "defaults.toml", `
[upstreams]
doh = ["https://example.com/dns-query"]
`)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if len(cfg.Bootstrap.Servers) != 2 {
		t.Fatalf("bootstrap servers = %d", len(cfg.Bootstrap.Servers))
	}
	if cfg.Bootstrap.Servers[0] != "1.1.1.1" || cfg.Bootstrap.Servers[1] != "1.0.0.1" {
		t.Fatalf("bootstrap defaults = %v", cfg.Bootstrap.Servers)
	}
	if cfg.UpstreamRefresh.RefreshThreshold.Duration() != 30*time.Second {
		t.Fatalf("refresh threshold default = %s", cfg.UpstreamRefresh.RefreshThreshold.Duration())
	}
}

func TestLoadRejectsInvalidEntries(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		data    string
		wantErr string
	}{
		{
			name: "bad doh scheme",
			data: `
[upstreams]
doh = ["cloudflare"]
`,
			wantErr: `invalid upstreams.doh entry "cloudflare": missing https:// scheme`,
		},
		{
			name: "bad bootstrap ip",
			data: `
[bootstrap]
servers = ["resolver.example"]

[upstreams]
doh = ["https://example.com/dns-query"]
`,
			wantErr: `invalid bootstrap.servers entry "resolver.example": not an IP address`,
		},
		{
			name: "bad hosts ip",
			data: `
[upstreams]
doh = ["https://example.com/dns-query"]

[hosts]
"example.com" = ["resolver.example"]
`,
			wantErr: `value "resolver.example" is not an IP address`,
		},
		{
			name: "no upstreams",
			data: `
bind_address = "127.0.0.1"
`,
			wantErr: `at least one upstream must be configured in [upstreams]`,
		},
		{
			name: "bad jitter",
			data: `
[upstreams]
doh = ["https://example.com/dns-query"]

[upstream_refresh]
jitter_percent = 99
`,
			wantErr: `upstream_refresh.jitter_percent must be between 1 and 95`,
		},
		{
			name: "bad duration",
			data: `
[upstreams]
doh = ["https://example.com/dns-query"]

[timeouts]
upstream = true
`,
			wantErr: `invalid duration type bool`,
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

func writeConfigFile(t *testing.T, name string, data string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
