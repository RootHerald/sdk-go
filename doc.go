// Package rootherald is the server-side SDK for verifying RootHerald attestation tokens
// and CAEP webhook Security Event Tokens.
//
// RootHerald uses a server -> server Background-Check model: the customer's dumb
// client collects an opaque evidence blob (TPM quote, Secure Enclave
// attestation, …) and hands it to the customer's own server. The server, using
// its rh_sk_ secret key, mints a nonce and submits the evidence to RootHerald
// for appraisal — the client never holds a key or talks to RootHerald directly.
//
// Background-Check (server -> server) quick start:
//
//	rh, _ := rootherald.NewAttestClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
//	chal, _ := rh.CreateChallenge(ctx, "" /* optional deviceHint */)
//	// relay chal.Nonce to the client; it quotes over it and returns `evidence`
//	res, err := rh.Attest(ctx, evidence, rootherald.AttestOptions{ChallengeID: chal.ChallengeID})
//	if err != nil || res.Verdict != rootherald.VerdictAllow {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//
// Offline badge-tier verification of a RootHerald-issued EAT (e.g. the optional
// token from Attest with ReturnToken) uses the Verifier / Client.Verify path:
//
//	client := rootherald.NewClient("https://rootherald.io",
//	    rootherald.WithIssuer("rootherald.io/myorg"),
//	    rootherald.WithAudience("my-app"),
//	)
//	verdict, claims, err := client.Verify(ctx, token)
//	if err != nil || verdict != rootherald.VerdictAllow {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//	log.Printf("device %s allowed", claims.Subject)
package rootherald
