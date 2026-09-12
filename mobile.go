package rootherald

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// IOSAttestation is the App Attest proof inside a mobile evidence blob: an
// assertion over the challenge nonce under the key enrolled for this device.
// An attestation object is not accepted here; enrollment is the one place it
// is read.
type IOSAttestation struct {
	// Assertion is the base64 CBOR App Attest assertion.
	Assertion string `json:"assertion"`
	// KeyID is the base64 App Attest key id the server locates the device by.
	KeyID string `json:"keyId"`
}

// MobileAppEnrollRequest is the body the RootHerald bridge forwards to the
// customer's registered appEnrollUrl. Hand Enrollment to RelayEnroll.
type MobileAppEnrollRequest struct {
	// Nonce is the challenge handle the app attested over.
	Nonce string `json:"nonce"`
	// Enrollment is the iOS EnrollBegin body (Platform "ios").
	Enrollment EnrollRequestBlob `json:"enrollment"`
}

// MobileAppVerifyRequest is the body the RootHerald bridge forwards to the
// customer's registered appVerifyUrl. Hand it to VerifyMobileEvidence.
type MobileAppVerifyRequest struct {
	// Nonce is the challenge handle the app asserted over.
	Nonce string `json:"nonce"`
	// Evidence is the opaque blob, carrying {"iosAttestation": {assertion, keyId}}.
	Evidence Evidence `json:"evidence"`
}

// VerifyMobileEvidence handles the POST the RootHerald bridge makes to the
// backend's registered appVerifyUrl: it checks the body carries a nonce and an
// App Attest assertion with its key id, then brokers Verify under that nonce
// exactly as for a desktop client. Store the verdict keyed by Nonce so the
// page the app reopens (returnUrl?nonce=<handle>) can fetch it.
//
// A body without a nonce is ErrChallenge; one whose evidence lacks
// iosAttestation.assertion or iosAttestation.keyId is ErrInvalidEvidence.
// Neither makes a network call.
func (c *Client) VerifyMobileEvidence(ctx context.Context, body MobileAppVerifyRequest) (AttestResult, error) {
	if body.Nonce == "" {
		return AttestResult{}, fmt.Errorf("%w: VerifyMobileEvidence requires a body with nonce", ErrChallenge)
	}
	var evidence struct {
		IOSAttestation *IOSAttestation `json:"iosAttestation"`
	}
	if err := json.Unmarshal(body.Evidence, &evidence); err != nil ||
		evidence.IOSAttestation == nil ||
		evidence.IOSAttestation.Assertion == "" ||
		evidence.IOSAttestation.KeyID == "" {
		return AttestResult{}, fmt.Errorf("%w: VerifyMobileEvidence body is missing evidence.iosAttestation.{assertion,keyId}", ErrInvalidEvidence)
	}
	return c.Verify(ctx, body.Evidence, AttestOptions{Nonce: body.Nonce})
}

// BuildMobileAttestLink builds the Universal Link that opens the RootHerald
// companion app: <bridgeBaseURL>/try/attest?challenge=<challenge>. It carries
// only the challenge; the bridge finds the tenant by the nonce inside it and
// forwards the app's evidence to the backend URL registered for that tenant,
// so a page cannot redirect the evidence elsewhere.
//
// bridgeBaseURL must be a different host from the page (iOS does not hand a
// same-host link to an app), and the page must render the link in a real
// <a href> the user taps: iOS fires a Universal Link only on a tap, never on a
// redirect or script navigation.
func BuildMobileAttestLink(bridgeBaseURL, challenge string) string {
	return strings.TrimRight(bridgeBaseURL, "/") + "/try/attest?challenge=" + url.QueryEscape(challenge)
}
