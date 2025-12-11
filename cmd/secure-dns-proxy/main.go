package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"archuser.org/secure-dns-proxy/internal/config"
	"archuser.org/secure-dns-proxy/internal/ingress"
	"archuser.org/secure-dns-proxy/internal/logging"
	"archuser.org/secure-dns-proxy/internal/metrics"
	"archuser.org/secure-dns-proxy/internal/resolver"
	"archuser.org/secure-dns-proxy/internal/upstream"
)

func main() {
	var cfgPath string
	flag.StringVar(&cfgPath, "config", "", "path to JSON config")
	flag.Parse()

	cfg, err := config.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load config: %v\n", err)
		os.Exit(1)
	}

	log := logging.New(logging.Level(cfg.Logging.Level))
	var metricsSink *metrics.Metrics
	if cfg.Metrics.Enabled {
		metricsSink = &metrics.Metrics{}
	}

	mgr, _, err := upstream.BuildManager(cfg, log, metricsSink)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build upstream manager: %v\n", err)
		os.Exit(1)
	}

	res := resolver.New(cfg, mgr, log, metricsSink)
	srv := ingress.New(cfg.BindAddress, cfg.Port, res, log, metricsSink)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if cfg.HealthChecks.Enabled {
		mgr.StartHealthChecks(ctx)
	}

	if err := srv.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to start server: %v\n", err)
		os.Exit(1)
	}
	log.Info("secure-dns-proxy started", "addr", fmt.Sprintf("%s:%d", cfg.BindAddress, cfg.Port), "policy", cfg.UpstreamPolicy)

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Warn("shutdown incomplete", "error", err)
	}
}
