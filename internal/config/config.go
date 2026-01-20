// Package config defines the JSON configuration schema and default values used
// by the proxy.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Duration is a thin wrapper so JSON can accept both quoted durations
// ("5s", "1m") and raw nanoseconds.
// It retains time.Duration semantics for arithmetic when converted with
// Duration().
type Duration time.Duration

// UnmarshalJSON implements encoding/json unmarshalling for Duration.
// It supports string durations first, then numeric nanoseconds as a fallback.
func (d *Duration) UnmarshalJSON(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("empty duration")
	}

	// Attempt string-based duration first.
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		parsed, err := time.ParseDuration(s)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	}

	// Fallback to numeric nanoseconds.
	var n int64
	if err := json.Unmarshal(b, &n); err == nil {
		*d = Duration(time.Duration(n))
		return nil
	}

	return fmt.Errorf("invalid duration: %s", string(b))
}

// Duration converts the custom Duration type back to time.Duration so other
// packages can use standard time arithmetic.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config describes the full runtime configuration for the proxy.
// Each field maps to a JSON property in the config file.
type Config struct {
	// BindAddress/Port define where the DNS server listens.
	BindAddress string `json:"bind_address"`
	Port        int    `json:"port"`
	// InsecureTLS disables TLS verification for upstreams (use with caution).
	InsecureTLS bool `json:"insecure_tls"`
	// Upstreams is the full list of resolver endpoints.
	Upstreams []UpstreamConfig `json:"upstreams"`

	// UpstreamPolicy chooses the strategy for selecting upstreams.
	UpstreamPolicy string `json:"upstream_policy"`
	// UpstreamRaceFanout controls parallelism for the "race" policy.
	UpstreamRaceFanout int `json:"upstream_race_fanout"`

	// HealthChecks configures active probing of upstreams.
	HealthChecks HealthCheckConfig `json:"health_checks"`

	// Cache controls DNS answer caching.
	Cache CacheConfig `json:"cache"`
	// Pools tunes connection reuse pools for upstream protocols.
	Pools PoolConfig `json:"pools"`
	// Timeouts applies to upstream dial/read operations.
	Timeouts TimeoutConfig `json:"timeouts"`
	// RateLimit caps concurrent upstream exchanges.
	RateLimit RateLimit `json:"rate_limit"`
	// Logging controls verbosity.
	Logging LoggingConfig `json:"logging"`
	// Metrics toggles instrumentation.
	Metrics MetricsConfig `json:"metrics"`
	// PrewarmPools determines whether connection pools prefill at startup.
	PrewarmPools bool `json:"prewarm_pools"`
}

// UpstreamConfig describes a single upstream resolver endpoint.
type UpstreamConfig struct {
	// URL is the DoH/DoT/DoQ/plain DNS target.
	URL string `json:"url"`
	// Bootstrap is an optional override for hostname resolution.
	Bootstrap string `json:"bootstrap"`
	// MaxFailures defines failures before an upstream is marked unhealthy.
	MaxFailures int `json:"max_failures"`
	// Cooldown specifies how long to wait before retrying an unhealthy upstream.
	Cooldown Duration `json:"cooldown"`
	// Weight influences weighted selection policies.
	Weight int `json:"weight"`
}

// HealthCheckConfig configures active health probing.
// When enabled, upstream health state is driven by dedicated probes rather than
// by regular query successes/failures.
type HealthCheckConfig struct {
	// Enabled toggles background probes.
	Enabled bool `json:"enabled"`
	// Interval sets how often probes run.
	Interval Duration `json:"interval"`
	// Query is the DNS name used for probing.
	Query string `json:"query"`
}

// CacheConfig tunes the TTL cache behavior.
type CacheConfig struct {
	// Enabled toggles caching.
	Enabled bool `json:"enabled"`
	// Capacity limits stored entries.
	Capacity int `json:"capacity"`
	// DefaultTTL is applied to positive answers when record TTL is ignored.
	DefaultTTL Duration `json:"default_ttl"`
	// NegativeTTL is applied to NXDOMAIN responses.
	NegativeTTL Duration `json:"negative_ttl"`
	// RespectRecordTTL honors TTL values from upstream answers.
	RespectRecordTTL bool `json:"respect_record_ttl"`
}

// PoolConfig tunes upstream connection reuse.
type PoolConfig struct {
	// TLS/QUIC pool sizes and idle timeouts for those protocols.
	TLS  SizedPoolConfig `json:"tls"`
	QUIC SizedPoolConfig `json:"quic"`

	// HTTPTransport configures the underlying DoH HTTP client.
	HTTPTransport HTTPTransportConfig `json:"http_transport"`
}

// SizedPoolConfig sets pool sizes and idle handling.
type SizedPoolConfig struct {
	// Size is the maximum number of idle connections.
	Size int `json:"size"`
	// IdleTimeout evicts unused connections after the duration.
	IdleTimeout Duration `json:"idle_timeout"`
}

// HTTPTransportConfig exposes knobs for the DoH client transport.
type HTTPTransportConfig struct {
	// MaxIdleConns caps total idle connections.
	MaxIdleConns int `json:"max_idle_conns"`
	// MaxIdleConnsPerHost caps idle connections per upstream host.
	MaxIdleConnsPerHost int `json:"max_idle_conns_per_host"`
	// IdleConnTimeout evicts idle HTTP connections.
	IdleConnTimeout Duration `json:"idle_conn_timeout"`
	// TLSHandshakeTimeout bounds handshake duration.
	TLSHandshakeTimeout Duration `json:"tls_handshake_timeout"`
}

// TimeoutConfig controls upstream interaction timeouts.
type TimeoutConfig struct {
	// Upstream is the overall timeout for an upstream exchange.
	Upstream Duration `json:"upstream"`
	// Dial bounds TCP/TLS/QUIC connection establishment.
	Dial Duration `json:"dial"`
	// Read bounds read operations on upstream sockets.
	Read Duration `json:"read"`
}

// RateLimit caps simultaneous upstream exchanges.
type RateLimit struct {
	// MaxInFlight caps simultaneous upstream requests to avoid overload.
	MaxInFlight int `json:"max_in_flight"`
}

// LoggingConfig exposes verbosity.
type LoggingConfig struct {
	// Level maps to the logging verbosity (info, debug, warn, ...).
	Level string `json:"level"`
}

// MetricsConfig toggles instrumentation.
type MetricsConfig struct {
	// Enabled toggles Prometheus-style counters.
	Enabled bool `json:"enabled"`
}

// Default returns a Config pre-populated with reasonable defaults.
// These values mirror config.default.json for convenient programmatic usage.
func Default() Config {
	return Config{
		BindAddress:        "127.0.0.35",
		Port:               53,
		InsecureTLS:        false,
		UpstreamPolicy:     "round_robin",
		UpstreamRaceFanout: 2,
		HealthChecks: HealthCheckConfig{
			Enabled:  true,
			Interval: Duration(120 * time.Second),
			Query:    ".",
		},
		Cache: CacheConfig{
			Enabled:          true,
			Capacity:         2048,
			DefaultTTL:       Duration(15 * time.Second),
			NegativeTTL:      Duration(10 * time.Second),
			RespectRecordTTL: true,
		},
		Pools: PoolConfig{
			TLS:  SizedPoolConfig{Size: 16, IdleTimeout: Duration(90 * time.Second)},
			QUIC: SizedPoolConfig{Size: 8, IdleTimeout: Duration(90 * time.Second)},
			HTTPTransport: HTTPTransportConfig{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     Duration(90 * time.Second),
				TLSHandshakeTimeout: Duration(5 * time.Second),
			},
		},
		Timeouts: TimeoutConfig{
			Upstream: Duration(5 * time.Second),
			Dial:     Duration(2 * time.Second),
			Read:     Duration(3 * time.Second),
		},
		RateLimit:    RateLimit{MaxInFlight: 1024},
		Logging:      LoggingConfig{Level: "info"},
		Metrics:      MetricsConfig{Enabled: true},
		PrewarmPools: true,
	}
}

// Load parses configuration from JSON file paths. First existing path wins,
// otherwise defaults are returned.
func Load(paths ...string) (Config, error) {
	cfg := Default()
	if len(paths) == 0 {
		return cfg, nil
	}

	for _, p := range paths {
		if p == "" {
			continue
		}
		data, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return cfg, fmt.Errorf("read config %s: %w", p, err)
		}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", p, err)
		}
		return cfg, nil
	}

	return cfg, fmt.Errorf("no configuration file found in %v", paths)
}
