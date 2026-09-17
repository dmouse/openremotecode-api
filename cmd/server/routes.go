package main

import (
	"database/sql"
	"log/slog"
	"time"

	connectorshttp "opencode-remote/server/internal/connectors/httpapi"
	identityhttp "opencode-remote/server/internal/identity/httpapi"
	"opencode-remote/server/internal/platform/health"
	"opencode-remote/server/internal/platform/httpserver"
	"opencode-remote/server/internal/relay"

	"github.com/gin-gonic/gin"
)

const readinessTimeout = time.Second

// httpModule is a feature package that mounts its own routes into the shared router.
// A module that owns background resources also implements Close() and is torn down
// in reverse registration order.
type httpModule interface {
	RegisterRoutes(gin.IRouter)
}

func RegisterRoutes(config Config, services Services, pool *sql.DB, logger *slog.Logger) (*gin.Engine, func()) {
	router := httpserver.NewRouter(logger)
	router.Use(httpserver.RequireAccessTag(config.ClientAccessTag))

	origins := config.AllowedOrigins
	proxies := config.TrustedProxies
	cookieSecure := !config.InsecureDevelopmentCookies

	modules := []httpModule{
		health.NewModule(health.DatabaseCheck(pool, readinessTimeout)),
		identityhttp.NewHandler(services.Identity, identityhttp.Config{
			AllowedOrigins:      origins,
			TrustedProxies:      proxies,
			CookieSecure:        cookieSecure,
			Logger:              logger,
			RegistrationEnabled: config.RegistrationEnabled,
		}),
		connectorshttp.NewHandler(services.Identity, services.Connectors, connectorshttp.Config{
			AllowedOrigins: origins,
			TrustedProxies: proxies,
			CookieSecure:   cookieSecure,
			Logger:         logger,
		}),
		relay.NewHandler(services.Connectors, relay.HandlerConfig{
			AllowedOrigins:  origins,
			Logger:          logger,
			DevelopmentEcho: config.DevelopmentRelayEnabled,
		}),
	}

	var closers []func()
	for _, module := range modules {
		module.RegisterRoutes(router)
		if closable, ok := module.(interface{ Close() }); ok {
			closers = append(closers, closable.Close)
		}
	}

	return router, func() {
		for index := len(closers) - 1; index >= 0; index-- {
			closers[index]()
		}
	}
}
