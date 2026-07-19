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
	// Accepted verdicts (default: ["allow"]). A verified token whose verdict is
	// not in this set is rejected with 403. Values are the SDK verdict strings:
	// "allow", "deny", "review".
	Verdicts []string
	// TokenHeader overrides X-RootHerald-Token.
	TokenHeader string
}

// Guard returns a chi-compatible middleware that requires a verified token.
//
// Behaviour:
//   - 401 if the token is missing, malformed, expired, or signature-invalid.
//   - 403 if the token verifies but its verdict is not in cfg.Verdicts.
//   - 503 if the JWKS endpoint is unreachable (so callers can retry).
//   - 200 (pass-through) on success; the decoded claims are placed on the
//     request context via Claims(ctx).
func Guard(cfg GuardConfig) func(http.Handler) http.Handler {
	if cfg.Verifier == nil {
		panic("rhchi.Guard: Verifier is required")
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
			if !verdictAccepted(cfg.Verdicts, claims.Verdict) {
				http.Error(w, "rootherald: verdict not accepted: "+string(claims.Verdict),
					http.StatusForbidden)
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
