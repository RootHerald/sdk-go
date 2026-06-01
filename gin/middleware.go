// Package rhgin provides a Gin middleware that enforces RootHerald attestation.
package rhgin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	rh "github.com/rootherald/rootherald-go"
)

// GuardConfig customises the middleware.
type GuardConfig struct {
	Verifier    *rh.Verifier
	Action      string
	Verdicts    []string
	TokenHeader string
}

const claimsKey = "rootherald.claims"

// Guard returns a Gin middleware that requires a verified attestation token.
//
// Status codes:
//   - 401 missing / malformed / expired / wrong-signature
//   - 503 JWKS unreachable
//   - 200 verified — claims available via c.MustGet("rootherald.claims") or Claims(c)
func Guard(cfg GuardConfig) gin.HandlerFunc {
	if cfg.Verifier == nil {
		panic("rhgin.Guard: Verifier is required")
	}
	if len(cfg.Verdicts) == 0 {
		cfg.Verdicts = []string{string(rh.VerdictAllow)}
	}
	if cfg.TokenHeader == "" {
		cfg.TokenHeader = "X-RootHerald-Token"
	}
	return func(c *gin.Context) {
		token := extractToken(c.Request, cfg.TokenHeader)
		if token == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "rootherald: missing token"})
			return
		}
		claims, err := cfg.Verifier.Verify(token)
		if err != nil {
			if errors.Is(err, rh.ErrJwksUnavailable) {
				c.AbortWithStatusJSON(http.StatusServiceUnavailable,
					gin.H{"error": "rootherald: verifier unavailable"})
				return
			}
			c.AbortWithStatusJSON(http.StatusUnauthorized,
				gin.H{"error": "rootherald: " + err.Error()})
			return
		}
		c.Set(claimsKey, claims)
		c.Next()
	}
}

// Claims pulls the decoded claims off a Gin context. Returns ok=false when
// Guard did not run for this request.
func Claims(c *gin.Context) (rh.AttestationClaims, bool) {
	v, ok := c.Get(claimsKey)
	if !ok {
		return rh.AttestationClaims{}, false
	}
	out, ok := v.(rh.AttestationClaims)
	return out, ok
}

func extractToken(r *http.Request, header string) string {
	if v := r.Header.Get(header); v != "" {
		return strings.TrimSpace(v)
	}
	auth := r.Header.Get("Authorization")
	switch {
	case strings.HasPrefix(auth, "RootHerald "):
		return strings.TrimSpace(auth[len("RootHerald "):])
	case strings.HasPrefix(auth, "Bearer "):
		return strings.TrimSpace(auth[len("Bearer "):])
	}
	return ""
}
