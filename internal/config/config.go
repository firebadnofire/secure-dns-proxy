package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// Config describes the full runtime configuration for the proxy.
type Config struct {
	BindAddress string           `json:"bind_address"`
	Port        int              `json:"port"`
	InsecureTLS bool             `json:"insecure_tls"`
	Upstreams   []UpstreamConfig `json:"upstreams"`

	UpstreamPolicy     string `json:"upstream_policy"`
	UpstreamRaceFanout int    `json:"upstream_race_fanout"`

	Cache        CacheConfig   `json:"cache"`
	Pools        PoolConfig    `json:"pools"`
	Timeouts     TimeoutConfig `json:"timeouts"`
	RateLimit    RateLimit     `json:"rate_limit"`
	Logging      LoggingConfig `json:"logging"`
	Metrics      MetricsConfig `json:"metrics"`
	PrewarmPools bool          `json:"prewarm_pools"`
}

// UpstreamConfig describes a single upstream resolver.
type UpstreamConfig struct {
	URL         string        `json:"url"`
	Bootstrap   string        `json:"bootstrap"`
	MaxFailures int           `json:"max_failures"`
	Cooldown    time.Duration `json:"cooldown"`
	Weight      int           `json:"weight"`
}

// CacheConfig tunes the TTL cache behavior.
type CacheConfig struct {
	Enabled          bool          `json:"enabled"`
	Capacity         int           `json:"capacity"`
	DefaultTTL       time.Duration `json:"default_ttl"`
	NegativeTTL      time.Duration `json:"negative_ttl"`
	RespectRecordTTL bool          `json:"respect_record_ttl"`
}

// PoolConfig tunes upstream connection reuse.
type PoolConfig struct {
	TLS  SizedPoolConfig `json:"tls"`
	QUIC SizedPoolConfig `json:"quic"`

	HTTPTransport HTTPTransportConfig `json:"http_transport"`
}

// SizedPoolConfig sets pool sizes and idle handling.
type SizedPoolConfig struct {
	Size        int           `json:"size"`
	IdleTimeout time.Duration `json:"idle_timeout"`
}

// HTTPTransportConfig exposes knobs for the DoH client transport.
type HTTPTransportConfig struct {
	MaxIdleConns        int           `json:"max_idle_conns"`
	MaxIdleConnsPerHost int           `json:"max_idle_conns_per_host"`
	IdleConnTimeout     time.Duration `json:"idle_conn_timeout"`
	TLSHandshakeTimeout time.Duration `json:"tls_handshake_timeout"`
}

// TimeoutConfig controls upstream interaction timeouts.
type TimeoutConfig struct {
	Upstream time.Duration `json:"upstream"`
	Dial     time.Duration `json:"dial"`
	Read     time.Duration `json:"read"`
}

// RateLimit caps simultaneous upstream exchanges.
type RateLimit struct {
	MaxInFlight int `json:"max_in_flight"`
}

// LoggingConfig exposes verbosity.
type LoggingConfig struct {
	Level string `json:"level"`
}

// MetricsConfig toggles instrumentation.
type MetricsConfig struct {
	Enabled bool `json:"enabled"`
}

// Default returns a Config pre-populated with reasonable defaults.
func Default() Config {
	return Config{
		BindAddress:        "127.0.0.35",
		Port:               53,
		InsecureTLS:        false,
		UpstreamPolicy:     "round_robin",
		UpstreamRaceFanout: 2,
		Cache: CacheConfig{
			Enabled:          true,
			Capacity:         2048,
			DefaultTTL:       15 * time.Second,
			NegativeTTL:      10 * time.Second,
			RespectRecordTTL: true,
		},
		Pools: PoolConfig{
			TLS:  SizedPoolConfig{Size: 16, IdleTimeout: 90 * time.Second},
			QUIC: SizedPoolConfig{Size: 8, IdleTimeout: 90 * time.Second},
			HTTPTransport: HTTPTransportConfig{
				MaxIdleConns:        128,
				MaxIdleConnsPerHost: 32,
				IdleConnTimeout:     90 * time.Second,
				TLSHandshakeTimeout: 5 * time.Second,
			},
		},
		Timeouts: TimeoutConfig{
			Upstream: 5 * time.Second,
			Dial:     2 * time.Second,
			Read:     3 * time.Second,
		},
		RateLimit:    RateLimit{MaxInFlight: 1024},
		Logging:      LoggingConfig{Level: "info"},
		Metrics:      MetricsConfig{Enabled: true},
		PrewarmPools: true,
	}
}

// Load parses configuration from JSON file paths. First existing path wins.
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
