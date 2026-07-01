// Runnable sample: a tiny HTTP server showing both RootHerald paths.
//
//   POST /attest  — the Background-Check (server -> server) flow. The dumb
//                   client POSTs its opaque evidence blob here; this server
//                   appraises it with RootHerald using its rh_sk_ secret key.
//                   The client never holds a key or talks to RootHerald.
//   POST /signup  — the badge-tier offline-verify flow. The request carries a
//                   RootHerald-issued EAT (JWT); the chi middleware verifies it
//                   against the issuer's JWKS with no per-request network call.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	rh "github.com/RootHerald/sdk-go"
	rhchi "github.com/RootHerald/sdk-go/chi"
	"github.com/go-chi/chi/v5"
)

func main() {
	issuer := envOr("ROOTHERALD_ISSUER", "https://rootherald.io/myorg")
	audience := envOr("ROOTHERALD_AUDIENCE", "hello-rp")
	jwksURI := envOr("ROOTHERALD_JWKS_URI", "https://rootherald.io/.well-known/jwks.json")
	secretKey := os.Getenv("ROOTHERALD_SECRET_KEY") // rh_sk_…

	// Badge-tier verifier (offline JWKS verification).
	client := rh.NewClient("https://rootherald.io",
		rh.WithIssuer(issuer), rh.WithAudience(audience), rh.WithJwksURI(jwksURI))

	// Background-Check client (server -> server). Optional: only wired if a
	// secret key is configured.
	var attest *rh.AttestClient
	if secretKey != "" {
		var err error
		if attest, err = rh.NewAttestClient(secretKey); err != nil {
			log.Fatalf("attest client: %v", err)
		}
	}

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Background-Check: dumb client -> this server -> RootHerald.
	r.Post("/attest", func(w http.ResponseWriter, req *http.Request) {
		if attest == nil {
			http.Error(w, "set ROOTHERALD_SECRET_KEY to enable /attest", http.StatusNotImplemented)
			return
		}
		// 1) mint a nonce; in a real app you'd hand chal.Nonce to the client
		//    first, then receive the evidence it produced. Compressed here.
		chal, err := attest.CreateChallenge(req.Context(), "")
		if err != nil {
			http.Error(w, "challenge failed", http.StatusBadGateway)
			return
		}
		// 2) the dumb client posted its opaque evidence blob as the body.
		evidence, _ := io.ReadAll(req.Body)
		res, err := attest.Attest(req.Context(), evidence, rh.AttestOptions{
			ChallengeID: chal.ChallengeID,
		})
		if err != nil {
			http.Error(w, "attestation error", http.StatusBadGateway)
			return
		}
		if res.Verdict != rh.VerdictAllow {
			// An un-enrolled / failing device is a verdict, not an error.
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"verdict": string(res.Verdict),
		})
	})

	// Badge tier: request carries a RootHerald EAT; verify it offline.
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
