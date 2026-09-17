package httpserver

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

// AccessTagHeader is the header RequireAccessTag checks. The plugin and mobile client
// send the same published, non-secret value on every request — see
// packages/agents/opencode/src/access-tag.ts and mobile/lib/platform/access_tag.dart.
const AccessTagHeader = "X-Orc-Access"

// RequireAccessTag rejects requests that do not carry the configured access tag.
//
// This is not an authentication or authorization control: the expected value ships in
// this project's open-source plugin source and in the compiled mobile app, so it is
// trivially readable by anyone. Its only purpose is to cut automated-scanner and bot
// noise on public endpoints before a request reaches real auth logic. Every actual
// security decision (account, device, connector, session) is made downstream of this
// check, unaffected by it.
//
// An empty expected value disables the check entirely (the default; set
// CLIENT_ACCESS_TAG to turn it on). "/health/" paths are always exempt — container and
// edge health probes call them directly and do not carry application headers.
func RequireAccessTag(expected string) gin.HandlerFunc {
	expectedHash := sha256.Sum256([]byte(expected))
	return func(c *gin.Context) {
		if expected == "" || strings.HasPrefix(c.Request.URL.Path, "/health/") {
			c.Next()
			return
		}
		gotHash := sha256.Sum256([]byte(c.GetHeader(AccessTagHeader)))
		if subtle.ConstantTimeCompare(expectedHash[:], gotHash[:]) != 1 {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.Next()
	}
}
