// Package main wires together configuration, caching, upstream management,
// metrics, and the DNS ingress server into a runnable binary.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"archuser.org/secure-dns-proxy/internal/cache"
	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/ingress"
	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/resolver"
	"archuser.org/secure-dns-proxy/internal/upstream"
)

// serverInstance captures the live components that make up a running proxy.
// It lets us hot-reload configuration by swapping in a freshly built instance.
type serverInstance struct {
	// cfg is the full resolved runtime configuration.
	cfg config.Config
	// cache is shared across reloads so cached DNS answers survive config tweaks.
	cache *cache.Cache
	// mgr owns upstream resolvers and health checks.
	mgr *upstream.Manager
	// metrics is optional; when nil instrumentation is disabled.
	metrics *metrics.Metrics
	// srv listens for incoming DNS queries.
	srv *ingress.Server
	// log is the structured logger used by all components.
	log logging.Logger
	// healthCancel stops background health checks on shutdown/reload.
	healthCancel context.CancelFunc
}

// newServerInstance builds a complete proxy instance from configuration, wiring
// together cache, upstreams, resolver, and ingress server.
func newServerInstance(cfgPath string, existingCache *cache.Cache) (*serverInstance, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	// Configure logging early so subsequent initialization has a logger.
	log := logging.New(logging.Level(cfg.Logging.Level))
	var metricsSink *metrics.Metrics
	if cfg.Metrics.Enabled {
		metricsSink = &metrics.Metrics{}
	}

	// Build upstream manager and apply policy/health-check settings.
	mgr, _, err := upstream.BuildManager(cfg, log, metricsSink)
	if err != nil {
		return nil, fmt.Errorf("failed to build upstream manager: %w", err)
	}

	// Reuse an existing cache when reloading to preserve hit ratios.
	var cacheInstance *cache.Cache
	if existingCache != nil {
		existingCache.UpdateConfig(cfg.Cache)
		cacheInstance = existingCache
	} else {
		cacheInstance = cache.New(cfg.Cache)
	}

	// Resolver handles cache lookup and upstream forwarding.
	res := resolver.New(cfg, cacheInstance, mgr, log, metricsSink)
	// Ingress server speaks DNS to clients.
	srv := ingress.New(cfg.BindAddress, cfg.Port, res, log, metricsSink)

	healthCtx, cancel := context.WithCancel(context.Background())
	if cfg.HealthChecks.Enabled {
		// Kick off health probes in the background.
		mgr.StartHealthChecks(healthCtx)
	}

	return &serverInstance{cfg: cfg, cache: cacheInstance, mgr: mgr, metrics: metricsSink, srv: srv, log: log, healthCancel: cancel}, nil
}

// shutdown stops background work and the DNS listener.
func (s *serverInstance) shutdown(ctx context.Context) {
	if s.healthCancel != nil {
		s.healthCancel()
	}
	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Warn("shutdown incomplete", "error", err)
	}
}

func main() {
	// Parse CLI flags; config path can be empty for defaults.
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to JSON config")
	flag.Parse()

	// Build the initial instance.
	inst, err := newServerInstance(cfgPath, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	// Start DNS ingress.
	if err := inst.srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}
	inst.log.Info("secure-dns-proxy started", "addr", fmt.Sprintf("%s:%d", inst.cfg.BindAddress, inst.cfg.Port), "policy", inst.cfg.UpstreamPolicy)

	// Listen for termination signals and SIGHUP for config reloads.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			// Graceful shutdown with a timeout.
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			inst.shutdown(shutdownCtx)
			return
		case <-reloadCh:
			// Rebuild everything, keeping the cache, then swap in the new instance.
			inst.log.Info("reloading configuration")
			newInst, err := newServerInstance(cfgPath, inst.cache)
			if err != nil {
				inst.log.Warn("reload failed", "error", err)
				continue
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			inst.shutdown(shutdownCtx)
			cancel()

			inst = newInst
			// Start new server and log the updated configuration.
			if err := inst.srv.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to restart server after reload: %v\n", err)
				os.Exit(1)
			}
			inst.log.Info("reload complete", "addr", fmt.Sprintf("%s:%d", inst.cfg.BindAddress, inst.cfg.Port), "policy", inst.cfg.UpstreamPolicy)
		}
	}
}
