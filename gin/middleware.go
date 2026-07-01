// Package rhgin provides a Gin middleware that enforces RootHerald attestation.
package rhgin

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	rh "github.com/RootHerald/sdk-go"
)

// GuardConfig customises the middleware.
type GuardConfig struct {
	Verifier *rh.Verifier
	Action   string
	// Verdicts is the set of accepted verdicts (default: ["allow"]). A verified
	// token whose verdict is not in this set is rejected with 403. Values are the
	// SDK verdict strings: "allow", "deny", "review".
	Verdicts    []string
	TokenHeader string
}

const claimsKey = "rootherald.claims"

// Guard returns a Gin middleware that requires a verified attestation token.
//
// Status codes:
//   - 401 missing / malformed / expired / wrong-signature
//   - 403 verified but verdict not in cfg.Verdicts
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
		if !verdictAccepted(cfg.Verdicts, claims.Verdict) {
			c.AbortWithStatusJSON(http.StatusForbidden,
				gin.H{"error": "rootherald: verdict not accepted: " + string(claims.Verdict)})
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

func verdictAccepted(accepted []string, v rh.Verdict) bool {
	for _, a := range accepted {
		if a == string(v) {
			return true
		}
	}
	return false
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
