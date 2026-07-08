// Runnable sample: a tiny HTTP server showing the RootHerald Background-Check
// (server -> server) flow.
//
//   POST /attest  — the dumb client POSTs its opaque evidence blob here; this
//                   server appraises it with RootHerald using its rh_sk_ secret
//                   key. The client never holds a key or talks to RootHerald.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	rh "github.com/RootHerald/sdk-go"
	"github.com/go-chi/chi/v5"
)

func main() {
	secretKey := os.Getenv("ROOTHERALD_SECRET_KEY") // rh_sk_…

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
		chal, err := attest.IssueChallenge(req.Context(), "")
		if err != nil {
			http.Error(w, "challenge failed", http.StatusBadGateway)
			return
		}
		// 2) the dumb client posted its opaque evidence blob as the body.
		evidence, _ := io.ReadAll(req.Body)
		res, err := attest.Verify(req.Context(), evidence, rh.AttestOptions{
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

	addr := envOr("ADDR", ":8080")
	log.Printf("listening on %s", addr)
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
