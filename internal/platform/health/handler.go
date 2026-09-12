package health

import (
	"context"
	"database/sql"
	"net"
	"net/http"
	"time"

	"opencode-remote/server/internal/platform/httpserver"

	"github.com/gin-gonic/gin"
)

type ReadinessCheck func(context.Context) error

func NewHandler(readiness ReadinessCheck) http.Handler {
	router := httpserver.NewRouter(nil)
	RegisterRoutes(router, readiness)
	return router
}

// Module adapts the health routes to the shared module registration used by the server,
// so every feature package mounts itself the same way.
type Module struct{ readiness ReadinessCheck }

func NewModule(readiness ReadinessCheck) *Module {
	return &Module{readiness: readiness}
}

func (module *Module) RegisterRoutes(router gin.IRouter) {
	RegisterRoutes(router, module.readiness)
}

func RegisterRoutes(router gin.IRouter, readiness ReadinessCheck) {
	live := gin.WrapF(func(response http.ResponseWriter, _ *http.Request) {
		writeStatus(response, http.StatusOK, "ok")
	})
	ready := gin.WrapF(func(response http.ResponseWriter, request *http.Request) {
		if err := readiness(request.Context()); err != nil {
			writeStatus(response, http.StatusServiceUnavailable, "unavailable")
			return
		}
		writeStatus(response, http.StatusOK, "ready")
	})
	router.GET("/health/live", live)
	router.HEAD("/health/live", live)
	router.GET("/health/ready", ready)
	router.HEAD("/health/ready", ready)
}

func DatabaseCheck(database *sql.DB, timeout time.Duration) ReadinessCheck {
	return func(ctx context.Context) error {
		checkContext, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		return database.PingContext(checkContext)
	}
}

func TCPCheck(address string, timeout time.Duration) ReadinessCheck {
	return func(ctx context.Context) error {
		connection, err := (&net.Dialer{Timeout: timeout}).DialContext(
			ctx,
			"tcp",
			address,
		)
		if err != nil {
			return err
		}
		return connection.Close()
	}
}

func writeStatus(response http.ResponseWriter, statusCode int, status string) {
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(statusCode)
	_, _ = response.Write([]byte(`{"status":"` + status + `"}` + "\n"))
}
