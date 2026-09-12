package main

import (
	"context"
	"crypto/tls"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"
)

const shutdownTimeout = 10 * time.Second

func Run(ctx context.Context, config Config, handler http.Handler, logger *slog.Logger) error {
	server := &http.Server{
		Addr:              config.HTTPAddress,
		TLSConfig:         config.TLS,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	listener, err := net.Listen("tcp", config.HTTPAddress)
	if err != nil {
		return err
	}
	// Shutdown only drains HTTP connections. The caller separately closes relay sockets.
	defer server.Close()
	serverErrors := make(chan error, 1)
	go func() {
		logger.Info("API server starting", "address", listener.Addr().String(), "tls", config.TLS != nil)
		serverErrors <- serveAPI(server, listener)
	}()
	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down HTTP server")
	}
	shutdownContext, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()
	return server.Shutdown(shutdownContext)
}

// Validate and load certificates before opening the database or an API listener.
func loadTransportTLS(development bool, certFile, keyFile string) (*tls.Config, error) {
	certFile, keyFile = strings.TrimSpace(certFile), strings.TrimSpace(keyFile)
	if certFile == "" && keyFile == "" {
		if development {
			return nil, nil
		}
		return nil, errors.New("production requires TLS_CERT_FILE and TLS_KEY_FILE")
	}
	if certFile == "" || keyFile == "" {
		return nil, errors.New("TLS_CERT_FILE and TLS_KEY_FILE must be configured together")
	}
	certificate, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, errors.New("TLS certificate and private key could not be loaded")
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
	}, nil
}

func serveAPI(server *http.Server, listener net.Listener) error {
	if server.TLSConfig != nil {
		return server.ServeTLS(listener, "", "")
	}
	return server.Serve(listener)
}
