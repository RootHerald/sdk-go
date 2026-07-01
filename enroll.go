package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
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
// POST /api/v1/devices/enroll. The dumb client gathers the EK material and the
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
// body of POST /api/v1/devices/enroll and the input to the client's
// EnrollComplete(). credentialBlob and encryptedSecret are the
// TPM2_MakeCredential outputs (already TPM2B-framed); the client feeds them into
// TPM2_ActivateCredential.
type EnrollActivationChallenge struct {
	// DeviceID is the deterministic device id (UUID) derived server-side from the EK.
	DeviceID string `json:"deviceId"`
	// CredentialBlob is the base64 TPM2_MakeCredential credential blob (id-object).
	CredentialBlob string `json:"credentialBlob"`
	// EncryptedSecret is the base64 TPM2_MakeCredential encrypted secret.
	EncryptedSecret string `json:"encryptedSecret"`
}

// EnrollActivationResponse is the client's EnrollComplete() output — the body of
// POST /api/v1/devices/activate. The client decrypts the challenge inside the
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

// RelayEnrollResult normalizes the asymmetric 201/409 outcome of the enroll
// relay leg into one value so callers branch on AlreadyEnrolled instead of
// re-parsing HTTP status. DeviceID is always resolved.
//
//   - AlreadyEnrolled == false: a fresh 201 enroll. Challenge is non-nil; relay
//     it to the client's EnrollComplete, then call RelayActivate.
//   - AlreadyEnrolled == true: a 409 short-circuit. The device is already bound,
//     so SKIP RelayActivate and just use DeviceID. Challenge is nil.
type RelayEnrollResult struct {
	// AlreadyEnrolled reports whether the device was already bound (409).
	AlreadyEnrolled bool
	// DeviceID is the resolved device id (UUID), present in both outcomes.
	DeviceID string
	// Challenge is the MakeCredential challenge for a fresh enroll; nil when
	// AlreadyEnrolled is true.
	Challenge *EnrollActivationChallenge
}

// RelayActivateResponse is the terminal body of POST /api/v1/devices/activate.
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
// POST {baseURL}/api/v1/devices/enroll, authenticated with the rh_sk_ secret,
// and resolves the asymmetric response (see RelayEnrollResult):
//
//   - 201 — a fresh enroll: returns {DeviceID, Challenge, AlreadyEnrolled:false}.
//     Hand Challenge to the client's EnrollComplete, then pass the result to
//     RelayActivate.
//   - 409 — the device is already enrolled: returns {DeviceID, AlreadyEnrolled:
//     true} with no error and no Challenge. SKIP RelayActivate — the device is
//     already bound; just use DeviceID.
//
// The client never holds the rh_sk_ key and never talks to RootHerald; this
// backend helper is the only thing that does.
func (c *AttestClient) RelayEnroll(ctx context.Context, blob EnrollRequestBlob) (RelayEnrollResult, error) {
	if blob.EkPublicKey == "" || blob.AkPublicArea == "" {
		return RelayEnrollResult{}, fmt.Errorf("%w: RelayEnroll requires EkPublicKey and AkPublicArea", ErrInvalidEnrollBlob)
	}

	resp, err := c.rawPost(ctx, "/api/v1/devices/enroll", blob)
	if err != nil {
		return RelayEnrollResult{}, err
	}
	defer resp.Body.Close()

	// 409 already-enrolled: the body carries only deviceId. Resolve it and signal
	// "skip activate" rather than treating it as an error.
	if resp.StatusCode == http.StatusConflict {
		var body struct {
			DeviceID string `json:"deviceId"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&body)
		if body.DeviceID == "" {
			return RelayEnrollResult{}, &APIError{
				StatusCode: http.StatusConflict,
				Message:    "already-enrolled (409) response missing deviceId",
				sentinel:   ErrAttestHTTP,
			}
		}
		return RelayEnrollResult{AlreadyEnrolled: true, DeviceID: body.DeviceID}, nil
	}

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
	return RelayEnrollResult{AlreadyEnrolled: false, DeviceID: ch.DeviceID, Challenge: &ch}, nil
}

// RelayActivate relays the client's EnrollComplete() blob (the decrypted
// credential secret) to RootHerald via POST {baseURL}/api/v1/devices/activate,
// completing the EK->AK credential-activation handshake. Call this only when
// RelayEnroll returned AlreadyEnrolled == false.
//
// It returns the terminal {DeviceID, Status, EnrolledAt} body; DeviceID is the
// load-bearing field the backend maps to its user.
func (c *AttestClient) RelayActivate(ctx context.Context, activation EnrollActivationResponse) (RelayActivateResponse, error) {
	if activation.DeviceID == "" || activation.DecryptedSecret == "" {
		return RelayActivateResponse{}, fmt.Errorf("%w: RelayActivate requires DeviceID and DecryptedSecret", ErrInvalidActivation)
	}

	var out RelayActivateResponse
	if err := c.post(ctx, "/api/v1/devices/activate", activation, &out); err != nil {
		return RelayActivateResponse{}, err
	}
	if out.DeviceID == "" {
		return RelayActivateResponse{}, fmt.Errorf("%w: activate response missing deviceId", ErrAttestHTTP)
	}
	return out, nil
}
