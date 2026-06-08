// Package rhchi provides a go-chi middleware that enforces RootHerald attestation.
package rhchi

import (
	"context"
	"errors"
	"net/http"
	"strings"

	rh "github.com/RootHerald/sdk-go"
)

type ctxKey int

const claimsCtxKey ctxKey = 0

// GuardConfig customises the middleware.
type GuardConfig struct {
	// Verifier performs the JWT check. Required.
	Verifier *rh.Verifier
	// Action label forwarded to logs/metrics. Optional.
	Action string
	// Accepted verdicts (default: ["allow"]).
	Verdicts []string
	// TokenHeader overrides X-RootHerald-Token.
	TokenHeader string
}

// Guard returns a chi-compatible middleware that requires a verified token.
//
// Behaviour:
//   - 401 if the token is missing, malformed, expired, or signature-invalid.
//   - 503 if the JWKS endpoint is unreachable (so callers can retry).
//   - 200 (pass-through) on success; the decoded claims are placed on the
//     request context via Claims(ctx).
func Guard(cfg GuardConfig) func(http.Handler) http.Handler {
	if cfg.Verifier == nil {
		panic("rhchi.Guard: Verifier is required")
	}
	if len(cfg.Verdicts) == 0 {
		cfg.Verdicts = []string{string(rh.VerdictAllow)}
	}
	if cfg.TokenHeader == "" {
		cfg.TokenHeader = "X-RootHerald-Token"
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractToken(r, cfg.TokenHeader)
			if token == "" {
				http.Error(w, "rootherald: missing token", http.StatusUnauthorized)
				return
			}
			claims, err := cfg.Verifier.Verify(token)
			if err != nil {
				if errors.Is(err, rh.ErrJwksUnavailable) {
					http.Error(w, "rootherald: verifier unavailable", http.StatusServiceUnavailable)
					return
				}
				http.Error(w, "rootherald: "+err.Error(), http.StatusUnauthorized)
				return
			}
			ctx := context.WithValue(r.Context(), claimsCtxKey, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// Claims retrieves the decoded attestation claims from the request context.
// Returns ok=false when Guard did not run for this request.
func Claims(ctx context.Context) (rh.AttestationClaims, bool) {
	c, ok := ctx.Value(claimsCtxKey).(rh.AttestationClaims)
	return c, ok
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
