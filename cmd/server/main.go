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

	databases, err := SetupDatabase(ctx, config)
	if err != nil {
		return err
	}
	defer databases.Close()

	services, err := SetupServices(ctx, databases, config, logger)
	if err != nil {
		return err
	}

	router, closeRelay := RegisterRoutes(config, services, databases.Health, logger)
	defer closeRelay()

	return Run(ctx, config, router, logger)
}
