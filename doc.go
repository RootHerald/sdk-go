// Package rootherald is the server-side SDK for the RootHerald server -> server
// Background-Check flow.
//
// RootHerald uses a server -> server Background-Check model: the customer's dumb
// client collects an opaque evidence blob (TPM quote, Secure Enclave
// attestation, …) and hands it to the customer's own server. The server, using
// its rh_sk_ secret key, mints a challenge and submits the evidence to
// RootHerald for appraisal — the client never holds a key or talks to
// RootHerald directly.
//
// Background-Check (server -> server) quick start:
//
//	rh, _ := rootherald.NewClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
//	chal, _ := rh.IssueChallenge(ctx, "" /* optional deviceHint */)
//	// relay chal.Challenge to the client verbatim; it quotes over the nonce
//	// inside it and returns `evidence`
//	res, err := rh.Verify(ctx, evidence, rootherald.AttestOptions{ChallengeID: chal.ChallengeID})
//	if err != nil || res.Verdict != rootherald.VerdictAllow {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//
// The challenge carries the ask. IssueChallenge asks for identity and posture;
// IssueChallengeWithOptions can add AskKey, which has the device create a
// TPM-resident signing key and returns its public half on a passing verdict:
//
//	chal, _ := rh.IssueChallengeWithOptions(ctx, rootherald.ChallengeOptions{
//	    Ask: []rootherald.Ask{rootherald.AskIdentity, rootherald.AskKey},
//	})
//	res, _ := rh.Verify(ctx, evidence, rootherald.AttestOptions{ChallengeID: chal.ChallengeID})
//	if res.Verdict == rootherald.VerdictAllow && res.Key != nil {
//	    store(userID, res.Key.KeyID, res.Key.JWK)
//	}
//	// later, on a request the device signed with that key — no RootHerald call:
//	if !rootherald.VerifyKeySignature(jwk, message, signature) {
//	    http.Error(w, "signature rejected", http.StatusForbidden)
//	}
//
// One-time device enroll is relayed the same way — the client emits opaque
// EnrollBegin()/EnrollComplete() blobs and this backend helper relays them with
// the rh_sk_ secret. Enrollment always issues a challenge, so every RelayEnroll
// is followed by RelayActivate:
//
//	er, _ := rh.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/attest/enroll
//	// hand er.Challenge to the client's EnrollComplete, then relay the result
//	act, _ := rh.RelayActivate(ctx, activationResponse) // POST /api/v1/attest/activate
//	_ = act.DeviceID
package rootherald
