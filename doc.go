// Package rootherald is the server-side SDK for the RootHerald server -> server
// Background-Check flow.
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
//	chal, _ := rh.IssueChallenge(ctx, "" /* optional deviceHint */)
//	// relay chal.Nonce to the client; it quotes over it and returns `evidence`
//	res, err := rh.Verify(ctx, evidence, rootherald.AttestOptions{ChallengeID: chal.ChallengeID})
//	if err != nil || res.Verdict != rootherald.VerdictAllow {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//
// One-time device enroll is relayed the same way — the client emits opaque
// EnrollBegin()/EnrollComplete() blobs and this backend helper relays them with
// the rh_sk_ secret:
//
//	er, _ := rh.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/devices/enroll
//	if er.AlreadyEnrolled {
//	    // device already bound; skip activate, just use er.DeviceID
//	} else {
//	    // hand er.Challenge to the client's EnrollComplete, then relay the result
//	    act, _ := rh.RelayActivate(ctx, activationResponse) // POST /api/v1/devices/activate
//	    _ = act.DeviceID
//	}
package rootherald
