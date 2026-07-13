// Command gateway is the secure service gateway.
//
// It exposes a client-facing listener (HTTP or HTTPS depending on config)
// and dials backends over mTLS. See internal/proxy for the request lifecycle.
package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/nibhat/secure-svc-gw/internal/auth"
	"github.com/nibhat/secure-svc-gw/internal/config"
	"github.com/nibhat/secure-svc-gw/internal/health"
	"github.com/nibhat/secure-svc-gw/internal/lb"
	"github.com/nibhat/secure-svc-gw/internal/logging"
	"github.com/nibhat/secure-svc-gw/internal/metrics"
	"github.com/nibhat/secure-svc-gw/internal/proxy"
)

func main() {
	slog.SetDefault(logging.New())

	cfgPath := envOr("GATEWAY_CONFIG", "/etc/gateway/config.yaml")
	cfg, err := config.Load(cfgPath)
	if err != nil {
		slog.Error("config load failed", "err", err, "path", cfgPath)
		os.Exit(1)
	}
	slog.Info("config loaded",
		"path", cfgPath,
		"services", len(cfg.Services),
		"routes", len(cfg.Routes),
		"client_keys", len(cfg.ClientKeys),
	)

	regs := make([]auth.KeyRegistration, 0, len(cfg.ClientKeys))
	for _, k := range cfg.ClientKeys {
		regs = append(regs, auth.KeyRegistration{
			Kid: k.Kid, PubBase64: k.PubBase64, Subject: k.Subject, Scopes: k.Scopes,
		})
	}

	var nonceStore auth.NonceStore
	if cfg.RedisURL != "" {
		var rs *auth.RedisNonceStore
		for attempt := 1; attempt <= 10; attempt++ {
			rs, err = auth.NewRedisNonceStore(cfg.RedisURL)
			if err == nil {
				break
			}
			slog.Warn("redis not ready, retrying", "attempt", attempt, "err", err)
			time.Sleep(time.Duration(attempt) * time.Second)
		}
		if err != nil {
			slog.Error("redis nonce store init failed after retries", "err", err)
			os.Exit(1)
		}
		nonceStore = rs
		slog.Info("nonce store", "backend", "redis", "url", cfg.RedisURL)
	} else {
		nonceStore = auth.NewInMemoryNonceStore(cfg.NonceTTL)
		slog.Info("nonce store", "backend", "in-memory", "ttl", cfg.NonceTTL)
	}

	verifier, err := auth.NewVerifierWithStore(regs, cfg.Issuer, cfg.Audience, nonceStore)
	if err != nil {
		slog.Error("auth init failed", "err", err)
		os.Exit(1)
	}

	pools := make(map[string]*lb.Pool, len(cfg.Services))
	clients := make(map[string]*http.Client, len(cfg.Services))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, svc := range cfg.Services {
		tlsCfg, err := proxy.BackendTLS(cfg.CACertPath, cfg.GatewayCertPath, cfg.GatewayKeyPath, svc.Name)
		if err != nil {
			slog.Error("backend tls init failed", "svc", svc.Name, "err", err)
			os.Exit(1)
		}
		pool := lb.NewPool(svc.Name, svc.Backends)
		pools[svc.Name] = pool
		clients[svc.Name] = proxy.NewBackendClient(tlsCfg)

		hp := svc.HealthPath
		if hp == "" {
			hp = "/healthz"
		}
		checker := health.NewChecker(pool, tlsCfg, hp, 2*time.Second)
		go checker.Run(ctx)

		slog.Info("service registered",
			"service", svc.Name, "backends", len(svc.Backends), "health_path", hp,
		)
	}

	handler := proxy.NewHandler(cfg, pools, clients, verifier)

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
	}
	metricsSrv := &http.Server{
		Addr:              cfg.MetricsAddr,
		Handler:           metrics.Handler(),
		ReadHeaderTimeout: 5 * time.Second,
	}

	go serve(metricsSrv, "metrics", "", "")
	go serve(srv, "gateway", cfg.ListenCertPath, cfg.ListenKeyPath)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	sig := <-stop
	slog.Info("shutting down", "signal", sig.String())

	shCtx, shCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shCancel()
	_ = srv.Shutdown(shCtx)
	_ = metricsSrv.Shutdown(shCtx)
}

func serve(s *http.Server, name, certFile, keyFile string) {
	if certFile != "" && keyFile != "" {
		slog.Info("listening", "server", name, "addr", s.Addr, "tls", true)
		if err := s.ListenAndServeTLS(certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("server exited", "server", name, "err", err)
			os.Exit(1)
		}
		return
	}
	slog.Info("listening", "server", name, "addr", s.Addr, "tls", false)
	if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("server exited", "server", name, "err", err)
		os.Exit(1)
	}
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
