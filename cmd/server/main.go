package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/gin-gonic/gin"
)

func main() {
	gin.SetMode(gin.ReleaseMode)
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := start(logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func start(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	config, err := LoadConfig()
	if err != nil {
		return err
	}

	db, pool, err := SetupDatabase(ctx, config)
	if err != nil {
		return err
	}
	defer pool.Close()

	services, err := SetupServices(ctx, db, config, logger)
	if err != nil {
		return err
	}

	router, closeRelay := RegisterRoutes(config, services, pool, logger)
	defer closeRelay()

	return Run(ctx, config, router, logger)
}
