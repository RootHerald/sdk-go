// Runnable sample: a tiny HTTP server showing the RootHerald Background-Check
// (server -> server) flow, including a device-bound signing key.
//
//	POST /attest  — the dumb client POSTs its opaque evidence blob here; this
//	                server appraises it with RootHerald using its rh_sk_ secret
//	                key and keeps the certified key's public half. The client
//	                never holds a key or talks to RootHerald.
//	POST /action  — a later request the device signed with that key; checked
//	                locally against the stored public key, with no call to
//	                RootHerald.
package main

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"
	"sync"

	rh "github.com/RootHerald/sdk-go"
	"github.com/go-chi/chi/v5"
)

// keys stands in for the customer's user store: the public key RootHerald
// certified, kept against the key id the device presents later.
var keys = struct {
	sync.Mutex
	byID map[string]rh.JWK
}{byID: map[string]rh.JWK{}}

func main() {
	secretKey := os.Getenv("ROOTHERALD_SECRET_KEY") // rh_sk_…

	// Background-Check client (server -> server). Optional: only wired if a
	// secret key is configured.
	var attest *rh.Client
	if secretKey != "" {
		var err error
		if attest, err = rh.NewClient(secretKey); err != nil {
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
		// 1) mint a challenge asking for identity plus a signing key; in a real
		//    app you'd relay chal.Challenge to the client first, then receive
		//    the evidence it produced. Compressed here.
		chal, err := attest.IssueChallengeWithOptions(req.Context(), rh.ChallengeOptions{
			Ask:        []rh.Ask{rh.AskIdentity, rh.AskKey},
			KeyPurpose: "sign",
		})
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
		if res.Verdict != rh.VerdictAllow || res.Key == nil {
			// An un-enrolled / failing device is a verdict, not an error. A
			// passing verdict with a key ask always carries the key.
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		// 3) keep the public half; the private half never left the TPM.
		keys.Lock()
		keys.byID[res.Key.KeyID] = res.Key.JWK
		keys.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"verdict": string(res.Verdict),
			"keyId":   res.Key.KeyID,
		})
	})

	// A follow-up request the device signed with its certified key. The
	// signature covers the raw message bytes; nothing here calls RootHerald.
	r.Post("/action", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			KeyID     string `json:"keyId"`
			Message   string `json:"message"`   // the signed bytes, verbatim
			Signature string `json:"signature"` // base64; raw r||s or DER
		}
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		keys.Lock()
		jwk, known := keys.byID[body.KeyID]
		keys.Unlock()
		sig, err := base64.StdEncoding.DecodeString(body.Signature)
		if !known || err != nil || !rh.VerifyKeySignature(jwk, []byte(body.Message), sig) {
			http.Error(w, "signature rejected", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
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
