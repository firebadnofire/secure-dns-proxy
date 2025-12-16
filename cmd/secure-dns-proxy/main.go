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

type serverInstance struct {
	cfg          config.Config
	cache        *cache.Cache
	mgr          *upstream.Manager
	metrics      *metrics.Metrics
	srv          *ingress.Server
	log          logging.Logger
	healthCancel context.CancelFunc
}

func newServerInstance(cfgPath string, existingCache *cache.Cache, logLevel string) (*serverInstance, error) {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	if logLevel != "" {
		cfg.Logging.Level = logLevel
	}

	log := logging.New(logging.ParseLevel(cfg.Logging.Level))
	var metricsSink *metrics.Metrics
	if cfg.Metrics.Enabled {
		metricsSink = &metrics.Metrics{}
	}

	mgr, _, err := upstream.BuildManager(cfg, log, metricsSink)
	if err != nil {
		return nil, fmt.Errorf("failed to build upstream manager: %w", err)
	}

	var cacheInstance *cache.Cache
	if existingCache != nil {
		existingCache.UpdateConfig(cfg.Cache)
		cacheInstance = existingCache
	} else {
		cacheInstance = cache.New(cfg.Cache)
	}

	res := resolver.New(cfg, cacheInstance, mgr, log, metricsSink)
	srv := ingress.New(cfg.BindAddress, cfg.Port, res, log, metricsSink)

	healthCtx, cancel := context.WithCancel(context.Background())
	if cfg.HealthChecks.Enabled {
		mgr.StartHealthChecks(healthCtx)
	}

	return &serverInstance{cfg: cfg, cache: cacheInstance, mgr: mgr, metrics: metricsSink, srv: srv, log: log, healthCancel: cancel}, nil
}

func (s *serverInstance) shutdown(ctx context.Context) {
	if s.healthCancel != nil {
		s.healthCancel()
	}
	if err := s.srv.Shutdown(ctx); err != nil {
		s.log.Warn("shutdown incomplete", "error", err)
	}
}

func main() {
	var cfgPath string
	var logLevel string
	flag.StringVar(&cfgPath, "config", "", "path to JSON config")
	flag.StringVar(&logLevel, "log-level", "", "override log level (debug, info, warn, error)")
	flag.Parse()

	inst, err := newServerInstance(cfgPath, nil, logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	if err := inst.srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}
	inst.log.Info("secure-dns-proxy started", "addr", fmt.Sprintf("%s:%d", inst.cfg.BindAddress, inst.cfg.Port), "policy", inst.cfg.UpstreamPolicy)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reloadCh := make(chan os.Signal, 1)
	signal.Notify(reloadCh, syscall.SIGHUP)

	for {
		select {
		case <-ctx.Done():
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			inst.shutdown(shutdownCtx)
			return
		case <-reloadCh:
			inst.log.Info("reloading configuration")
			newInst, err := newServerInstance(cfgPath, inst.cache, logLevel)
			if err != nil {
				inst.log.Warn("reload failed", "error", err)
				continue
			}
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			inst.shutdown(shutdownCtx)
			cancel()

			inst = newInst
			if err := inst.srv.Start(); err != nil {
				fmt.Fprintf(os.Stderr, "failed to restart server after reload: %v\n", err)
				os.Exit(1)
			}
			inst.log.Info("reload complete", "addr", fmt.Sprintf("%s:%d", inst.cfg.BindAddress, inst.cfg.Port), "policy", inst.cfg.UpstreamPolicy)
		}
	}
}
