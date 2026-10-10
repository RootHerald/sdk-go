// Runnable sample: a tiny HTTP server showing the RootHerald Background-Check
// (server -> server) flow, including a device-bound signing key.
//
//	POST /attest  — the client POSTs its opaque evidence blob here; this
//	                server appraises it with RootHerald using its rh_sk_ secret
//	                key and answers with the device's alias. The client never
//	                holds a key or talks to RootHerald.
//	POST /mint    — the client POSTs its MintKey certification for a key
//	                challenge minted for the device that just passed; this
//	                server keeps the certified key's public half.
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
	var client *rh.Client
	if secretKey != "" {
		var err error
		if client, err = rh.NewClient(secretKey); err != nil {
			log.Fatalf("rootherald client: %v", err)
		}
	}
	requireClient := func(w http.ResponseWriter) bool {
		if client == nil {
			http.Error(w, "set ROOTHERALD_SECRET_KEY to enable this route", http.StatusNotImplemented)
			return false
		}
		return true
	}

	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	// Attest: client -> this server -> RootHerald.
	r.Post("/attest", func(w http.ResponseWriter, req *http.Request) {
		if !requireClient(w) {
			return
		}
		// 1) mint a challenge asking for identity; in a real app you'd relay
		//    chal.Challenge to the client first, then receive the evidence it
		//    produced. Compressed here.
		chal, err := client.IssueChallengeWithOptions(req.Context(), rh.ChallengeOptions{
			Ask: []rh.Ask{rh.AskIdentity},
		})
		if err != nil {
			http.Error(w, "challenge failed", http.StatusBadGateway)
			return
		}
		// 2) the client posted its opaque evidence blob as the body.
		evidence, _ := io.ReadAll(req.Body)
		res, err := client.Verify(req.Context(), evidence, rh.AttestOptions{Nonce: chal.Nonce})
		if err != nil {
			http.Error(w, "attestation error", http.StatusBadGateway)
			return
		}
		if res.Verdict != rh.VerdictPass || res.Device == nil || res.Device.UEID == "" {
			// An un-enrolled / failing device is a verdict, not an error.
			http.Error(w, "denied", http.StatusForbidden)
			return
		}
		// 3) the alias is this tenant's name for the device; bind the session
		//    to it here. It never goes back to the client.
		_ = json.NewEncoder(w).Encode(map[string]string{
			"status":  "ok",
			"verdict": string(res.Verdict),
		})
	})

	// Mint: a key challenge for the device that passed, then the client's
	// certification relayed under its nonce.
	r.Post("/mint", func(w http.ResponseWriter, req *http.Request) {
		if !requireClient(w) {
			return
		}
		alias := req.Header.Get("X-Device-Alias") // from the session bound at /attest
		// 1) mint a key challenge naming the device; relay kc.KeyChallenge to
		//    the client, whose MintKey answers with a certification. Compressed
		//    here.
		kc, err := client.IssueKeyChallenge(req.Context(), rh.KeyChallengeOptions{
			Purpose:         rh.KeyPurposeSign,
			ExpectedDevices: []string{alias},
		})
		if err != nil {
			http.Error(w, "key challenge failed", http.StatusBadGateway)
			return
		}
		// 2) the client posted its certification as the body; relay it verbatim.
		certification, _ := io.ReadAll(req.Body)
		key, err := client.CertifyKey(req.Context(), kc.Nonce, certification)
		if err != nil {
			http.Error(w, "certify failed", http.StatusBadGateway)
			return
		}
		// 3) keep the public half; the private half never left the TPM.
		keys.Lock()
		keys.byID[key.KeyID] = key.JWK
		keys.Unlock()

		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":        "ok",
			"keyId":         key.KeyID,
			"alg":           key.Alg,
			"hardwareBound": key.HardwareBound,
		})
	})

	// A follow-up request the device signed with its certified key. The
	// signature covers the raw message bytes; nothing here calls RootHerald.
	r.Post("/action", func(w http.ResponseWriter, req *http.Request) {
		var body struct {
			KeyID     string `json:"keyId"`
			Message   string `json:"message"`   // the signed bytes, verbatim
			Signature string `json:"signature"` // base64; ES256 raw r||s or DER, RS256 PKCS#1 v1.5
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
