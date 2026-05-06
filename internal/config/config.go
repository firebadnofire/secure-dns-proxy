// Package config defines the TOML configuration schema and default values used
// by the proxy.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Duration is a thin wrapper so TOML can accept both quoted durations
// ("5s", "1m") and raw nanoseconds.
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

// Duration converts the custom Duration type back to time.Duration.
func (d Duration) Duration() time.Duration { return time.Duration(d) }

// IPList stores normalized literal IP addresses.
type IPList []net.IP

// UnmarshalTOML accepts either a single IP string or an array of IP strings.
func (l *IPList) UnmarshalTOML(v any) error {
	if v == nil {
		*l = nil
		return nil
	}
	raw, err := coerceStringList(v)
	if err != nil {
		return fmt.Errorf("must be a string or array of strings")
	}
	ips, err := parseIPList(raw)
	if err != nil {
		return err
	}
	*l = ips
	return nil
}

// Config describes the full runtime configuration for the proxy.
// TOML-facing fields are normalized into Upstreams during Load/Normalize.
type Config struct {
	BindAddress string `toml:"bind_address"`
	Port        int    `toml:"port"`
	InsecureTLS bool   `toml:"insecure_tls"`

	UpstreamGroups  UpstreamGroups        `toml:"upstreams"`
	Bootstrap       BootstrapConfig       `toml:"bootstrap"`
	Hosts           HostOverrides         `toml:"hosts"`
	UpstreamRefresh UpstreamRefreshConfig `toml:"upstream_refresh"`

	UpstreamPolicy     string            `toml:"upstream_policy"`
	UpstreamRaceFanout int               `toml:"upstream_race_fanout"`
	HealthChecks       HealthCheckConfig `toml:"health_checks"`
	Cache              CacheConfig       `toml:"cache"`
	Pools              PoolConfig        `toml:"pools"`
	Timeouts           TimeoutConfig     `toml:"timeouts"`
	RateLimit          RateLimit         `toml:"rate_limit"`
	Logging            LoggingConfig     `toml:"logging"`
	Metrics            MetricsConfig     `toml:"metrics"`
	PrewarmPools       bool              `toml:"prewarm_pools"`

	// Upstreams is the shared internal representation used by runtime code.
	Upstreams []UpstreamConfig `toml:"-"`
}

// UpstreamGroups is the public TOML-facing upstream layout.
type UpstreamGroups struct {
	DNS []string `toml:"dns"`
	DoH []string `toml:"doh"`
	DoT []string `toml:"dot"`
	DoQ []string `toml:"doq"`
}

// BootstrapConfig configures startup bootstrap resolvers.
type BootstrapConfig struct {
	Servers []string `toml:"servers"`
}

// HostOverrides are static hostname to IP mappings.
type HostOverrides map[string]IPList

// UpstreamRefreshConfig controls background upstream hostname refresh.
type UpstreamRefreshConfig struct {
	Enabled          bool     `toml:"enabled"`
	RefreshThreshold Duration `toml:"refresh_threshold"`
	MinTTL           Duration `toml:"min_ttl"`
	FailureRetry     Duration `toml:"failure_retry"`
	JitterPercent    int      `toml:"jitter_percent"`
}

// UpstreamConfig is the normalized shared internal upstream shape.
type UpstreamConfig struct {
	URL           string
	Protocol      string
	Hostname      string
	Port          string
	LiteralIP     net.IP
	StaticHostIPs IPList
	MaxFailures   int
	Cooldown      Duration
	Weight        int
}

type HealthCheckConfig struct {
	Enabled  bool     `toml:"enabled"`
	Interval Duration `toml:"interval"`
	Query    string   `toml:"query"`
}

type CacheConfig struct {
	Enabled          bool     `toml:"enabled"`
	Capacity         int      `toml:"capacity"`
	DefaultTTL       Duration `toml:"default_ttl"`
	NegativeTTL      Duration `toml:"negative_ttl"`
	RespectRecordTTL bool     `toml:"respect_record_ttl"`
}

type PoolConfig struct {
	TLS           SizedPoolConfig     `toml:"tls"`
	QUIC          SizedPoolConfig     `toml:"quic"`
	HTTPTransport HTTPTransportConfig `toml:"http_transport"`
}

type SizedPoolConfig struct {
	Size        int      `toml:"size"`
	IdleTimeout Duration `toml:"idle_timeout"`
}

type HTTPTransportConfig struct {
	MaxIdleConns        int      `toml:"max_idle_conns"`
	MaxIdleConnsPerHost int      `toml:"max_idle_conns_per_host"`
	IdleConnTimeout     Duration `toml:"idle_conn_timeout"`
	TLSHandshakeTimeout Duration `toml:"tls_handshake_timeout"`
}

type TimeoutConfig struct {
	Upstream Duration `toml:"upstream"`
	Dial     Duration `toml:"dial"`
	Read     Duration `toml:"read"`
}

type RateLimit struct {
	MaxInFlight int `toml:"max_in_flight"`
}

type LoggingConfig struct {
	Level string `toml:"level"`
}

type MetricsConfig struct {
	Enabled bool `toml:"enabled"`
}

// Default returns a Config pre-populated with reasonable defaults.
func Default() Config {
	return Config{
		BindAddress:        "127.0.0.35",
		Port:               53,
		InsecureTLS:        false,
		UpstreamPolicy:     "round_robin",
		UpstreamRaceFanout: 2,
		Bootstrap: BootstrapConfig{
			Servers: []string{"1.1.1.1", "1.0.0.1"},
		},
		UpstreamRefresh: UpstreamRefreshConfig{
			Enabled:          true,
			RefreshThreshold: Duration(30 * time.Second),
			MinTTL:           Duration(30 * time.Second),
			FailureRetry:     Duration(30 * time.Second),
			JitterPercent:    20,
		},
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

// Load parses configuration from TOML file paths. First existing path wins.
func Load(paths ...string) (Config, error) {
	cfg := Default()
	if len(paths) == 0 {
		if err := cfg.Normalize(); err != nil {
			return cfg, err
		}
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
		if err := cfg.Normalize(); err != nil {
			return cfg, fmt.Errorf("validate config %s: %w", p, err)
		}
		return cfg, nil
	}

	return cfg, fmt.Errorf("no configuration file found in %v", paths)
}

// Normalize applies defaults, validates the public config, and builds the
// shared internal upstream representation.
func (c *Config) Normalize() error {
	if len(c.Bootstrap.Servers) == 0 {
		c.Bootstrap.Servers = []string{"1.1.1.1", "1.0.0.1"}
	}
	if err := validateBootstrapServers(c.Bootstrap.Servers); err != nil {
		return err
	}

	if c.UpstreamRefresh.RefreshThreshold.Duration() <= 0 {
		c.UpstreamRefresh.RefreshThreshold = Duration(30 * time.Second)
	}
	if c.UpstreamRefresh.MinTTL.Duration() <= 0 {
		c.UpstreamRefresh.MinTTL = Duration(30 * time.Second)
	}
	if c.UpstreamRefresh.FailureRetry.Duration() <= 0 {
		c.UpstreamRefresh.FailureRetry = Duration(30 * time.Second)
	}
	if c.UpstreamRefresh.JitterPercent <= 0 {
		c.UpstreamRefresh.JitterPercent = 20
	}
	if c.UpstreamRefresh.JitterPercent > 95 {
		return fmt.Errorf("upstream_refresh.jitter_percent must be between 1 and 95")
	}

	if err := validateHostOverrides(c.Hosts); err != nil {
		return err
	}

	if len(c.Upstreams) == 0 {
		normalized, err := normalizeUpstreams(c.UpstreamGroups, c.Hosts)
		if err != nil {
			return err
		}
		c.Upstreams = normalized
	} else {
		for i := range c.Upstreams {
			if c.Upstreams[i].Protocol == "" {
				return fmt.Errorf("upstreams[%d] is missing protocol in normalized config", i)
			}
		}
	}
	return nil
}

func normalizeUpstreams(groups UpstreamGroups, hosts HostOverrides) ([]UpstreamConfig, error) {
	type group struct {
		key      string
		protocol string
		values   []string
	}
	all := []group{
		{key: "upstreams.dns", protocol: "dns", values: groups.DNS},
		{key: "upstreams.doh", protocol: "https", values: groups.DoH},
		{key: "upstreams.dot", protocol: "tls", values: groups.DoT},
		{key: "upstreams.doq", protocol: "quic", values: groups.DoQ},
	}

	var normalized []UpstreamConfig
	for _, grp := range all {
		for _, raw := range grp.values {
			up, err := normalizeUpstreamEntry(grp.key, grp.protocol, raw, hosts)
			if err != nil {
				return nil, err
			}
			normalized = append(normalized, up)
		}
	}
	if len(normalized) == 0 {
		return nil, fmt.Errorf("at least one upstream must be configured in [upstreams]")
	}
	return normalized, nil
}

func normalizeUpstreamEntry(key, protocol, raw string, hosts HostOverrides) (UpstreamConfig, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: empty value", key, raw)
	}

	switch protocol {
	case "dns":
		return normalizeDNSUpstream(key, trimmed, hosts)
	case "https", "tls", "quic":
		return normalizeSecureUpstream(key, protocol, trimmed, hosts)
	default:
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: unsupported protocol %s", key, raw, protocol)
	}
}

func normalizeDNSUpstream(key, raw string, hosts HostOverrides) (UpstreamConfig, error) {
	host, port, err := splitHostPortDefault(raw, "53")
	if err != nil {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: %w", key, raw, err)
	}
	cfg := UpstreamConfig{
		URL:      net.JoinHostPort(host, port),
		Protocol: "dns",
		Hostname: host,
		Port:     port,
	}
	if ip := net.ParseIP(host); ip != nil {
		cfg.LiteralIP = append(net.IP(nil), ip...)
		return cfg, nil
	}
	cfg.StaticHostIPs = cloneIPList(hosts[host])
	return cfg, nil
}

func normalizeSecureUpstream(key, protocol, raw string, hosts HostOverrides) (UpstreamConfig, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: %w", key, raw, err)
	}
	if parsed.Scheme != protocol {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: missing %s:// scheme", key, raw, protocol)
	}
	if parsed.Host == "" {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: missing host", key, raw)
	}

	defaultPort := map[string]string{"https": "443", "tls": "853", "quic": "784"}[protocol]
	host, port, err := splitHostPortDefault(parsed.Host, defaultPort)
	if err != nil {
		return UpstreamConfig{}, fmt.Errorf("invalid %s entry %q: %w", key, raw, err)
	}

	cfg := UpstreamConfig{
		URL:      raw,
		Protocol: protocol,
		Hostname: host,
		Port:     port,
	}
	if ip := net.ParseIP(host); ip != nil {
		cfg.LiteralIP = append(net.IP(nil), ip...)
		return cfg, nil
	}
	cfg.StaticHostIPs = cloneIPList(hosts[host])
	return cfg, nil
}

func validateBootstrapServers(values []string) error {
	if len(values) == 0 {
		return fmt.Errorf("bootstrap.servers must contain at least one IP")
	}
	for _, raw := range values {
		if net.ParseIP(strings.TrimSpace(raw)) == nil {
			return fmt.Errorf("invalid bootstrap.servers entry %q: not an IP address", raw)
		}
	}
	return nil
}

func validateHostOverrides(hosts HostOverrides) error {
	for hostname, ips := range hosts {
		if hostname == "" {
			return fmt.Errorf("invalid hosts entry %q: empty hostname", hostname)
		}
		if strings.Contains(hostname, "://") {
			return fmt.Errorf("invalid hosts entry %q: must be a hostname, not a URL", hostname)
		}
		if net.ParseIP(hostname) != nil {
			return fmt.Errorf("invalid hosts entry %q: host override keys must be hostnames", hostname)
		}
		if len(ips) == 0 {
			return fmt.Errorf("invalid hosts entry %q: must contain at least one IP", hostname)
		}
		for _, ip := range ips {
			if ip == nil {
				return fmt.Errorf("invalid hosts entry %q: contains invalid IP", hostname)
			}
		}
	}
	return nil
}

func splitHostPortDefault(hostport, defaultPort string) (string, string, error) {
	if strings.Contains(hostport, ":") {
		if host, port, err := net.SplitHostPort(hostport); err == nil {
			if host == "" {
				return "", "", fmt.Errorf("missing host")
			}
			if port == "" {
				return "", "", fmt.Errorf("missing port")
			}
			return host, port, nil
		}
		if strings.Count(hostport, ":") > 1 && !strings.HasPrefix(hostport, "[") {
			return hostport, defaultPort, nil
		}
	}
	if hostport == "" {
		return "", "", fmt.Errorf("missing host")
	}
	return hostport, defaultPort, nil
}

func parseIPList(values []string) (IPList, error) {
	ips := make(IPList, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			return nil, fmt.Errorf("empty ip value")
		}
		ip := net.ParseIP(value)
		if ip == nil {
			return nil, fmt.Errorf("value %q is not an IP address", raw)
		}
		ips = append(ips, append(net.IP(nil), ip...))
	}
	return ips, nil
}

func coerceStringList(v any) ([]string, error) {
	switch value := v.(type) {
	case string:
		return []string{value}, nil
	case []string:
		return value, nil
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("not a string")
			}
			out = append(out, s)
		}
		return out, nil
	default:
		return nil, fmt.Errorf("unsupported type %T", v)
	}
}

func cloneIPList(in IPList) IPList {
	if len(in) == 0 {
		return nil
	}
	out := make(IPList, 0, len(in))
	for _, ip := range in {
		out = append(out, append(net.IP(nil), ip...))
	}
	return out
}
