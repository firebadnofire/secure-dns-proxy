// Package config defines the TOML configuration schema and default values used
// by the proxy.
package config

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration is a thin wrapper so TOML can accept both quoted durations
// ("5s", "1m") and raw nanoseconds.
// It retains time.Duration semantics for arithmetic when converted with
// Duration().
type Duration time.Duration

// UnmarshalTOML supports both string durations and raw nanoseconds.
func (d *Duration) UnmarshalTOML(v any) error {
	switch value := v.(type) {
	case string:
		parsed, err := time.ParseDuration(value)
		if err != nil {
			return err
		}
		*d = Duration(parsed)
		return nil
	case int64:
		*d = Duration(time.Duration(value))
		return nil
	default:
		return fmt.Errorf("invalid duration type %T", v)
	}
}

// Duration converts the custom Duration type back to time.Duration so other
// packages can use standard time arithmetic.
func (d Duration) Duration() time.Duration {
	return time.Duration(d)
}

// Config describes the full runtime configuration for the proxy.
// Each field maps to a TOML property in the config file.
type Config struct {
	// BindAddress/Port define where the DNS server listens.
	BindAddress string `toml:"bind_address"`
	Port        int    `toml:"port"`
	// InsecureTLS disables TLS verification for upstreams (use with caution).
	InsecureTLS bool `toml:"insecure_tls"`
	// Upstreams is the full list of resolver endpoints.
	Upstreams []UpstreamConfig `toml:"upstreams"`

	// UpstreamPolicy chooses the strategy for selecting upstreams.
	UpstreamPolicy string `toml:"upstream_policy"`
	// UpstreamRaceFanout controls parallelism for the "race" policy.
	UpstreamRaceFanout int `toml:"upstream_race_fanout"`

	// HealthChecks configures active probing of upstreams.
	HealthChecks HealthCheckConfig `toml:"health_checks"`

	// Cache controls DNS answer caching.
	Cache CacheConfig `toml:"cache"`
	// Pools tunes connection reuse pools for upstream protocols.
	Pools PoolConfig `toml:"pools"`
	// Timeouts applies to upstream dial/read operations.
	Timeouts TimeoutConfig `toml:"timeouts"`
	// RateLimit caps concurrent upstream exchanges.
	RateLimit RateLimit `toml:"rate_limit"`
	// Logging controls verbosity.
	Logging LoggingConfig `toml:"logging"`
	// Metrics toggles instrumentation.
	Metrics MetricsConfig `toml:"metrics"`
	// PrewarmPools determines whether connection pools prefill at startup.
	PrewarmPools bool `toml:"prewarm_pools"`
}

// UpstreamConfig describes a single upstream resolver endpoint.
type UpstreamConfig struct {
	// URL is the DoH/DoT/DoQ/plain DNS target.
	URL string `toml:"url"`
	// Bootstrap is an optional override for hostname resolution.
	Bootstrap string `toml:"bootstrap"`
	// MaxFailures defines failures before an upstream is marked unhealthy.
	MaxFailures int `toml:"max_failures"`
	// Cooldown specifies how long to wait before retrying an unhealthy upstream.
	Cooldown Duration `toml:"cooldown"`
	// Weight influences weighted selection policies.
	Weight int `toml:"weight"`
}

// HealthCheckConfig configures active health probing.
// When enabled, upstream health state is driven by dedicated probes rather than
// by regular query successes/failures.
type HealthCheckConfig struct {
	// Enabled toggles background probes.
	Enabled bool `toml:"enabled"`
	// Interval sets how often probes run.
	Interval Duration `toml:"interval"`
	// Query is the DNS name used for probing.
	Query string `toml:"query"`
}

// CacheConfig tunes the TTL cache behavior.
type CacheConfig struct {
	// Enabled toggles caching.
	Enabled bool `toml:"enabled"`
	// Capacity limits stored entries.
	Capacity int `toml:"capacity"`
	// DefaultTTL is applied to positive answers when record TTL is ignored.
	DefaultTTL Duration `toml:"default_ttl"`
	// NegativeTTL is applied to NXDOMAIN responses.
	NegativeTTL Duration `toml:"negative_ttl"`
	// RespectRecordTTL honors TTL values from upstream answers.
	RespectRecordTTL bool `toml:"respect_record_ttl"`
}

// PoolConfig tunes upstream connection reuse.
type PoolConfig struct {
	// TLS/QUIC pool sizes and idle timeouts for those protocols.
	TLS  SizedPoolConfig `toml:"tls"`
	QUIC SizedPoolConfig `toml:"quic"`

	// HTTPTransport configures the underlying DoH HTTP client.
	HTTPTransport HTTPTransportConfig `toml:"http_transport"`
}

// SizedPoolConfig sets pool sizes and idle handling.
type SizedPoolConfig struct {
	// Size is the maximum number of idle connections.
	Size int `toml:"size"`
	// IdleTimeout evicts unused connections after the duration.
	IdleTimeout Duration `toml:"idle_timeout"`
}

// HTTPTransportConfig exposes knobs for the DoH client transport.
type HTTPTransportConfig struct {
	// MaxIdleConns caps total idle connections.
	MaxIdleConns int `toml:"max_idle_conns"`
	// MaxIdleConnsPerHost caps idle connections per upstream host.
	MaxIdleConnsPerHost int `toml:"max_idle_conns_per_host"`
	// IdleConnTimeout evicts idle HTTP connections.
	IdleConnTimeout Duration `toml:"idle_conn_timeout"`
	// TLSHandshakeTimeout bounds handshake duration.
	TLSHandshakeTimeout Duration `toml:"tls_handshake_timeout"`
}

// TimeoutConfig controls upstream interaction timeouts.
type TimeoutConfig struct {
	// Upstream is the overall timeout for an upstream exchange.
	Upstream Duration `toml:"upstream"`
	// Dial bounds TCP/TLS/QUIC connection establishment.
	Dial Duration `toml:"dial"`
	// Read bounds read operations on upstream sockets.
	Read Duration `toml:"read"`
}

// RateLimit caps simultaneous upstream exchanges.
type RateLimit struct {
	// MaxInFlight caps simultaneous upstream requests to avoid overload.
	MaxInFlight int `toml:"max_in_flight"`
}

// LoggingConfig exposes verbosity.
type LoggingConfig struct {
	// Level maps to the logging verbosity (info, debug, warn, ...).
	Level string `toml:"level"`
}

// MetricsConfig toggles instrumentation.
type MetricsConfig struct {
	// Enabled toggles Prometheus-style counters.
	Enabled bool `toml:"enabled"`
}

// Default returns a Config pre-populated with reasonable defaults.
// These values mirror config.default.toml for convenient programmatic usage.
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

// Load parses configuration from TOML file paths. First existing path wins,
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
		if err := toml.Unmarshal(data, &cfg); err != nil {
			return cfg, fmt.Errorf("parse config %s: %w", p, err)
		}
		return cfg, nil
	}

	return cfg, fmt.Errorf("no configuration file found in %v", paths)
}
