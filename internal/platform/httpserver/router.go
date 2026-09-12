package httpserver

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// NewRouter centralizes transport policy; feature services remain framework-independent.
func NewRouter(logger *slog.Logger) *gin.Engine {
	router := gin.New()
	router.RedirectTrailingSlash = false
	router.RedirectFixedPath = false
	router.HandleMethodNotAllowed = true
	// Rate limiters apply the configured proxy policy directly to the HTTP request.
	// Gin must never introduce its default trust-all interpretation alongside it.
	_ = router.SetTrustedProxies(nil)
	router.Use(func(c *gin.Context) {
		c.Header("Cache-Control", "no-store")
		c.Header("X-Content-Type-Options", "nosniff")
		defer func() {
			if recovered := recover(); recovered != nil {
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}
				// Never log the recovered value, request, headers, or a stack dump.
				if logger != nil {
					logger.Error("HTTP handler panic")
				}
				if c.Writer.Written() {
					panic(http.ErrAbortHandler)
				}
				c.AbortWithStatus(http.StatusInternalServerError)
			}
		}()
		c.Next()
	})
	return router
}

// WrapHandler preserves the net/http transport helpers, including named path values.
func WrapHandler(handler http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		for _, param := range c.Params {
			c.Request.SetPathValue(param.Key, param.Value)
		}
		handler.ServeHTTP(c.Writer, c.Request)
	}
}
