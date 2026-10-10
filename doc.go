// Package rootherald is the server-side SDK for the RootHerald server -> server
// Background-Check flow, wire 8.0.
//
// The customer's client does local TPM work and hands the customer's own
// server opaque blobs: it holds no RootHerald key and never talks to
// RootHerald. The server relays those blobs with this client, authenticated
// with its rh_sk_ secret key, in three ceremonies of two calls each:
//
//	enroll      RelayEnroll / RelayActivate         the installation's AK is bound to its EK
//	mint a key  IssueKeyChallenge / CertifyKey      the AK certifies a new sign or decrypt key
//	attest      IssueChallenge / Verify             the AK quotes what the challenge asked
//
// Attest:
//
//	rh, _ := rootherald.NewClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
//	chal, _ := rh.IssueChallenge(ctx)
//	// relay chal.Challenge to the client verbatim; its Attest answers with `evidence`
//	res, err := rh.Verify(ctx, evidence, rootherald.AttestOptions{Nonce: chal.Nonce})
//	if err != nil || res.Verdict != rootherald.VerdictPass {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//	alias := res.Device.UEID // this tenant's alias for the device; never relayed to it
//
// Mint a device-bound signing key for the device that just passed, then check
// its signatures locally with no call to RootHerald:
//
//	kc, _ := rh.IssueKeyChallenge(ctx, rootherald.KeyChallengeOptions{
//	    Purpose:         rootherald.KeyPurposeSign,
//	    ExpectedDevices: []string{alias},
//	})
//	// relay kc.KeyChallenge to the client verbatim; its MintKey answers with `certification`
//	key, _ := rh.CertifyKey(ctx, kc.Nonce, certification)
//	store(key.DeviceID, key.KeyID, key.JWK)
//	// later, on a request the device signed with that key:
//	if !rootherald.VerifyKeySignature(jwk, message, signature) {
//	    http.Error(w, "signature rejected", http.StatusForbidden)
//	}
//
// Enroll an installation. Every enroll is followed by activate; the client
// keeps the AK blob EnrollBegin returned and passes it to every later attest
// and mint:
//
//	er, _ := rh.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/attest/enroll
//	// hand er.Challenge to the client's EnrollComplete, then relay the result
//	act, _ := rh.RelayActivate(ctx, activationResponse) // POST /api/v1/attest/activate
//	_ = act.DeviceID // this tenant's alias for the device; never relayed to it
package rootherald
