package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/didlawowo/proton-mcp-service/pkg/api"
	"github.com/didlawowo/proton-mcp-service/pkg/config"
	"github.com/didlawowo/proton-mcp-service/pkg/proton"
	"github.com/didlawowo/proton-mcp-service/pkg/session"
)

// maxRequestBody bounds JSON bodies. Proton caps a message at 25 MB of
// attachments, which base64 inflates to about 34 MB.
const maxRequestBody = 40 << 20

func main() {
	cfg := config.Load()

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: parseLevel(cfg.LogLevel),
	}))
	slog.SetDefault(logger)

	if cfg.APIKey == "" && !cfg.AllowUnauthenticated {
		logger.Error("set PROTON_API_KEY or explicitly set PROTON_ALLOW_UNAUTHENTICATED=true")
		os.Exit(1)
	}
	if cfg.AllowUnauthenticated {
		logger.Warn("API authentication disabled")
	}

	store := session.NewStore(cfg.SessionPath())
	client := proton.NewClient(store, cfg.ProtonPassword, cfg.AppVersion, logger)

	// Try to resume a previous session; otherwise authentication happens
	// through the API (POST /api/v1/auth/login + /2fa).
	if err := client.Restore(context.Background()); err != nil {
		logger.Info("no session to restore, waiting for API login", "error", err)
	} else {
		logger.Info("session restored")
	}

	if cfg.AllowWritesWithoutKey {
		logger.Warn("write operations allowed without X-Write-Key (PROTON_ALLOW_WRITES_WITHOUT_KEY=true)")
	}
	router := api.NewRouter(client, api.WriteGate{
		Secret:          cfg.WriteSecret,
		AllowWithoutKey: cfg.AllowWritesWithoutKey,
	}, cfg.APIKey, cfg.AllowUnauthenticated, logger)

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           http.MaxBytesHandler(router, maxRequestBody),
		ReadHeaderTimeout: 10 * time.Second,
	}

	go func() {
		stop := make(chan os.Signal, 1)
		signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
		<-stop
		logger.Info("shutting down")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}()

	logger.Info("proton-service listening", "port", cfg.Port, "dataDir", cfg.DataDir)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server error", "error", err)
		client.Close()
		os.Exit(1)
	}

	client.Close()
}

func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
