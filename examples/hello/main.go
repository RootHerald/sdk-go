// Runnable sample: a tiny HTTP server that requires a verified RootHerald
// attestation on POST /signup.
package main

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/go-chi/chi/v5"
	rh "github.com/RootHerald/sdk-go"
	rhchi "github.com/RootHerald/sdk-go/chi"
)

func main() {
	issuer := envOr("ROOTHERALD_ISSUER", "https://rootherald.io/myorg")
	audience := envOr("ROOTHERALD_AUDIENCE", "hello-rp")
	jwksURI := envOr("ROOTHERALD_JWKS_URI", "https://rootherald.io/.well-known/jwks.json")

	client := rh.NewClient("https://rootherald.io",
		rh.WithIssuer(issuer), rh.WithAudience(audience), rh.WithJwksURI(jwksURI))

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})
	r.With(rhchi.Guard(rhchi.GuardConfig{
		Verifier: client.Verifier(), Action: "signup",
	})).Post("/signup", func(w http.ResponseWriter, req *http.Request) {
		c, _ := rhchi.Claims(req.Context())
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status": "ok",
			"device": c.Subject,
		})
	})

	addr := envOr("ADDR", ":8080")
	log.Printf("listening on %s (issuer=%s)", addr, issuer)
	if err := http.ListenAndServe(addr, r); err != nil {
		log.Fatal(err)
	}
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
