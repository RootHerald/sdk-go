package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// Backend-relay enroll sentinel errors (Client ABI 2.0). Use errors.Is to switch
// on them. They flag malformed input passed to the relay helpers before any
// network call is made; HTTP-status problems still surface as *APIError wrapping
// the attest sentinels (ErrInvalidSecretKey, ErrChallenge, …).
var (
	// ErrInvalidEnrollBlob is returned by RelayEnroll when the supplied
	// EnrollRequestBlob is missing its load-bearing EkPublicKey/AkPublicArea.
	ErrInvalidEnrollBlob = errors.New("rootherald: invalid enroll request blob")
	// ErrInvalidActivation is returned by RelayActivate when the supplied
	// EnrollActivationResponse is missing its DeviceID/DecryptedSecret.
	ErrInvalidActivation = errors.New("rootherald: invalid activation response")
)

// Platform is the reporting platform an enroll blob was produced on. The enroll
// endpoint accepts the desktop TPM platforms for v1; the wider EAT platform
// union is a superset.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
)

// EnrollRequestBlob is the client's EnrollBegin() output — the body of
// POST /api/v1/attest/enroll. The dumb client gathers the EK material and the
// freshly created AK public area; this backend helper relays it verbatim to
// RootHerald, which validates the EK chain, template-checks the AK, and returns
// an EnrollActivationChallenge. The SDK passes these fields through without
// inspecting them.
type EnrollRequestBlob struct {
	// EkPublicKey is the base64 platform-native EK public blob (Windows: NCrypt
	// PCP_EKPUB). The stable hardware anchor the deterministic deviceId derives
	// from. Required.
	EkPublicKey string `json:"ekPublicKey"`
	// AkPublicArea is the base64 TPM2B_PUBLIC of the AK (length-prefixed
	// TPMT_PUBLIC) the server hashes into the AK Name for TPM2_MakeCredential.
	// Required.
	AkPublicArea string `json:"akPublicArea"`
	// Platform is the reporting platform ("windows" | "linux" | "macos").
	Platform Platform `json:"platform"`
	// EkCertPem is the optional PEM-encoded EK certificate. Firmware TPMs (e.g.
	// Intel PTT) ship no NV-stored EK cert, so this may be empty.
	EkCertPem string `json:"ekCertPem,omitempty"`
	// EkCertificateChain holds optional PEM-encoded intermediate CA certs the
	// client recovered from local sources. Order is not significant.
	EkCertificateChain []string `json:"ekCertificateChain,omitempty"`
}

// EnrollActivationChallenge is the MakeCredential challenge — the 201 response
// body of POST /api/v1/attest/enroll and the input to the client's
// EnrollComplete(). credentialBlob and encryptedSecret are the
// TPM2_MakeCredential outputs (already TPM2B-framed); the client feeds them into
// TPM2_ActivateCredential.
type EnrollActivationChallenge struct {
	// DeviceID is the deterministic device id (UUID) derived server-side from the EK.
	DeviceID string `json:"deviceId"`
	// ChallengeID is the attestation challenge this enrollment was admitted
	// against, echoed when RelayEnrollWithChallenge supplied one.
	ChallengeID string `json:"challengeId,omitempty"`
	// CredentialBlob is the base64 TPM2_MakeCredential credential blob (id-object).
	CredentialBlob string `json:"credentialBlob"`
	// EncryptedSecret is the base64 TPM2_MakeCredential encrypted secret.
	EncryptedSecret string `json:"encryptedSecret"`
}

// EnrollActivationResponse is the client's EnrollComplete() output — the body of
// POST /api/v1/attest/activate. The client decrypts the challenge inside the
// TPM and returns the released secret to prove EK->AK binding.
type EnrollActivationResponse struct {
	// DeviceID is the deviceId from the EnrollActivationChallenge. Required.
	DeviceID string `json:"deviceId"`
	// DecryptedSecret is the base64 32-byte secret released by
	// TPM2_ActivateCredential — proof the AK is bound to the attested EK. Required.
	DecryptedSecret string `json:"decryptedSecret"`
	// AkPublicKey is the optional base64 AK public area re-sent for the server's
	// anti key-substitution check. The current Windows client omits it.
	AkPublicKey string `json:"akPublicKey,omitempty"`
}

// RelayEnrollResult is the outcome of the enroll relay leg.
//
// Enrollment always issues a challenge, including for a device already known —
// re-enrollment is how a device rotates its attestation key, so short-circuiting
// it would make rotation impossible. Hand Challenge to the client's
// EnrollComplete, then pass the result to RelayActivate.
type RelayEnrollResult struct {
	// DeviceID is this tenant's alias for the device, not a global identifier.
	// Another tenant enrolling the same silicon is told a different one.
	DeviceID string
	// Challenge is the MakeCredential challenge to relay to the client.
	Challenge *EnrollActivationChallenge
}

// RelayActivateResponse is the terminal body of POST /api/v1/attest/activate.
// DeviceID is the load-bearing field the backend maps to its user.
type RelayActivateResponse struct {
	// DeviceID is the enrolled device id (UUID).
	DeviceID string `json:"deviceId"`
	// Status is the optional lifecycle status, e.g. "enrolled".
	Status string `json:"status,omitempty"`
	// EnrolledAt is the optional ISO 8601 timestamp the device was enrolled.
	EnrolledAt string `json:"enrolledAt,omitempty"`
}

// RelayEnroll relays the client's EnrollBegin() blob to RootHerald via
// POST {baseURL}/api/v1/attest/enroll, authenticated with the rh_sk_ secret,
// and returns the challenge to hand back to the client's EnrollComplete.
// Admission runs under the identity policy bound to the API key; see
// RelayEnrollWithChallenge to pin it to a live challenge.
//
// The client never holds the rh_sk_ key and never talks to RootHerald; this
// backend helper is the only thing that does.
func (c *Client) RelayEnroll(ctx context.Context, blob EnrollRequestBlob) (RelayEnrollResult, error) {
	return c.RelayEnrollWithChallenge(ctx, blob, "")
}

// RelayEnrollWithChallenge is RelayEnroll scoped to a live challenge from
// IssueChallenge: the request goes to
// POST {baseURL}/api/v1/attest/enroll?challengeId=<id>. Admission runs under
// the identity policy bound to the API key, pinned on that challenge when it
// was minted, so a device whose TPM class can never satisfy that policy is
// refused before it gets an attestation key, as ErrAdmissionRefused with the
// class in APIError.Message. An empty challengeID behaves like RelayEnroll.
func (c *Client) RelayEnrollWithChallenge(ctx context.Context, blob EnrollRequestBlob, challengeID string) (RelayEnrollResult, error) {
	if blob.EkPublicKey == "" || blob.AkPublicArea == "" {
		return RelayEnrollResult{}, fmt.Errorf("%w: RelayEnroll requires EkPublicKey and AkPublicArea", ErrInvalidEnrollBlob)
	}

	path := "/api/v1/attest/enroll"
	if challengeID != "" {
		path += "?challengeId=" + url.QueryEscape(challengeID)
	}
	resp, err := c.rawPost(ctx, path, blob)
	if err != nil {
		return RelayEnrollResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return RelayEnrollResult{}, toAPIError(resp)
	}

	var ch EnrollActivationChallenge
	if err := json.NewDecoder(resp.Body).Decode(&ch); err != nil {
		return RelayEnrollResult{}, fmt.Errorf("%w: malformed response: %v", ErrAttestHTTP, err)
	}
	if ch.DeviceID == "" || ch.CredentialBlob == "" || ch.EncryptedSecret == "" {
		return RelayEnrollResult{}, fmt.Errorf("%w: enroll response missing deviceId/credentialBlob/encryptedSecret", ErrAttestHTTP)
	}
	return RelayEnrollResult{DeviceID: ch.DeviceID, Challenge: &ch}, nil
}

// RelayActivate relays the client's EnrollComplete() blob (the decrypted
// credential secret) to RootHerald via POST {baseURL}/api/v1/attest/activate,
// completing the EK->AK credential-activation handshake. Every RelayEnroll
// leads here: enrollment always issues a challenge, including for a known
// device, because re-enrollment is how a device rotates its attestation key.
//
// It returns the terminal {DeviceID, Status, EnrolledAt} body; DeviceID is the
// load-bearing field the backend maps to its user.
func (c *Client) RelayActivate(ctx context.Context, activation EnrollActivationResponse) (RelayActivateResponse, error) {
	if activation.DeviceID == "" || activation.DecryptedSecret == "" {
		return RelayActivateResponse{}, fmt.Errorf("%w: RelayActivate requires DeviceID and DecryptedSecret", ErrInvalidActivation)
	}

	var out RelayActivateResponse
	if err := c.post(ctx, "/api/v1/attest/activate", activation, &out); err != nil {
		return RelayActivateResponse{}, err
	}
	if out.DeviceID == "" {
		return RelayActivateResponse{}, fmt.Errorf("%w: activate response missing deviceId", ErrAttestHTTP)
	}
	return out, nil
}
