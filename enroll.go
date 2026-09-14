package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// Backend-relay enroll sentinel errors. Use errors.Is to switch on them. They
// flag malformed input passed to the relay helpers before any network call is
// made; HTTP-status problems still surface as *APIError wrapping the attest
// sentinels (ErrInvalidSecretKey, ErrChallenge, …).
var (
	// ErrInvalidEnrollBlob is returned by RelayEnroll when the supplied
	// EnrollRequestBlob is missing the fields its platform requires.
	ErrInvalidEnrollBlob = errors.New("rootherald: invalid enroll request blob")
	// ErrInvalidActivation is returned by RelayActivate when the supplied
	// EnrollActivationResponse is missing its EnrollmentID or its proof.
	ErrInvalidActivation = errors.New("rootherald: invalid activation response")
)

// Platform is the platform an enroll blob was produced on. The server records
// it on the device and later demands the activation proof of the RECORDED
// platform, so reshaping a blob cannot move a TPM device onto a weaker
// ceremony.
type Platform string

const (
	PlatformWindows Platform = "windows"
	PlatformLinux   Platform = "linux"
	PlatformMacOS   Platform = "macos"
	PlatformIOS     Platform = "ios"
)

// TpmSelfReport is the TPM's own, unsigned answer to TPM2_GetCapability. The
// server reads it only downward: it can recognise a software TPM that
// presents no EK certificate, never promote a device.
type TpmSelfReport struct {
	Manufacturer string `json:"manufacturer"`
	VendorString string `json:"vendorString"`
}

// EnrollRequestBlob is the client's EnrollBegin() output — the body of
// POST /api/v1/attest/enroll. This backend helper relays it verbatim to
// RootHerald, which validates it and returns an EnrollActivationChallenge.
// Which fields are set depends on Platform:
//
//	windows | linux   EkPublicKey, AkPublicArea, and optionally EkCertPem,
//	                  EkCertificateChain, TpmSelfReport
//	macos             EkPublicKey and AkPublicArea, both the enclave key
//	ios               IOSKeyID, IOSAttestationObject, Nonce
//
// No device identifier travels in this body: the server derives the device
// from the key material itself.
type EnrollRequestBlob struct {
	// EkPublicKey is the base64 platform-native EK public blob (Windows: NCrypt
	// PCP_EKPUB; macOS: the enclave key, X9.63 uncompressed).
	EkPublicKey string `json:"ekPublicKey,omitempty"`
	// AkPublicArea is the base64 TPM2B_PUBLIC of the AK (length-prefixed
	// TPMT_PUBLIC) the server hashes into the AK Name for TPM2_MakeCredential.
	// On macOS it is the same key as EkPublicKey.
	AkPublicArea string `json:"akPublicArea,omitempty"`
	// Platform is the reporting platform. Required.
	Platform Platform `json:"platform"`
	// EkCertPem is the optional PEM-encoded EK certificate. Firmware TPMs (e.g.
	// Intel PTT) ship no NV-stored EK cert, so this may be empty.
	EkCertPem string `json:"ekCertPem,omitempty"`
	// EkCertificateChain holds optional PEM-encoded intermediate CA certs the
	// client recovered from local sources. Order is not significant.
	EkCertificateChain []string `json:"ekCertificateChain,omitempty"`
	// TpmSelfReport is the optional unsigned self-report of a TPM platform.
	TpmSelfReport *TpmSelfReport `json:"tpmSelfReport,omitempty"`
	// IOSKeyID is the base64 App Attest key id.
	IOSKeyID string `json:"iosKeyId,omitempty"`
	// IOSAttestationObject is the base64 CBOR App Attest attestation object.
	IOSAttestationObject string `json:"iosAttestationObject,omitempty"`
	// Nonce is the base64url challenge handle the App Attest attestation was
	// made over, which the iOS SDK derives from the challenge string.
	Nonce string `json:"nonce,omitempty"`
}

// EnrollActivationChallenge is the 201 response body of
// POST /api/v1/attest/enroll and the input to the client's EnrollComplete().
// Relay it to the client verbatim. For a TPM platform CredentialBlob and
// EncryptedSecret are the TPM2_MakeCredential outputs (already TPM2B-framed),
// fed straight into TPM2_ActivateCredential; for macOS ChallengeNonce is the
// nonce the enclave key signs. An iOS enrollment has no activation leg and
// gets an empty body, which marshals back to {}.
type EnrollActivationChallenge struct {
	// EnrollmentID is the server's handle for this open enrollment. The client
	// echoes it in EnrollActivationResponse.
	EnrollmentID string `json:"enrollmentId,omitempty"`
	// CredentialBlob is the base64 TPM2_MakeCredential credential blob (id-object).
	CredentialBlob string `json:"credentialBlob,omitempty"`
	// EncryptedSecret is the base64 TPM2_MakeCredential encrypted secret.
	EncryptedSecret string `json:"encryptedSecret,omitempty"`
	// ChallengeNonce is the base64 nonce a macOS enclave key signs to prove
	// residency.
	ChallengeNonce string `json:"challengeNonce,omitempty"`
}

// EnrollActivationResponse is the client's EnrollComplete() output — the body of
// POST /api/v1/attest/activate. A TPM returns the secret it released inside
// TPM2_ActivateCredential, proving EK->AK binding; a macOS enclave key returns
// its signature over ChallengeNonce.
type EnrollActivationResponse struct {
	// EnrollmentID is the EnrollmentID from the EnrollActivationChallenge. Required.
	EnrollmentID string `json:"enrollmentId"`
	// DecryptedSecret is the base64 32-byte secret released by
	// TPM2_ActivateCredential. Set for windows | linux.
	DecryptedSecret string `json:"decryptedSecret,omitempty"`
	// Signature is the base64 ECDSA-P256-SHA256 signature over ChallengeNonce,
	// DER or IEEE-P1363. Set for macos.
	Signature string `json:"signature,omitempty"`
}

// RelayEnrollResult is the outcome of the enroll relay leg.
//
// Enrollment always issues a challenge, including for a device already known —
// re-enrollment is how a device rotates its attestation key, so short-circuiting
// it would make rotation impossible. Hand Challenge to the client's
// EnrollComplete, then pass the result to RelayActivate.
type RelayEnrollResult struct {
	// Challenge is the 201 body to relay to the client.
	Challenge *EnrollActivationChallenge
}

// RelayActivateResponse is the terminal body of POST /api/v1/attest/activate.
// DeviceID is the load-bearing field the backend maps to its user.
type RelayActivateResponse struct {
	// DeviceID is this tenant's alias for the device, not a global identifier:
	// another tenant enrolling the same silicon is told a different one. It is
	// for the backend only and must not be relayed to the device.
	DeviceID string `json:"deviceId"`
	// Status is the optional lifecycle status, e.g. "enrolled".
	Status string `json:"status,omitempty"`
	// EnrolledAt is the optional ISO 8601 timestamp the device was enrolled.
	EnrolledAt string `json:"enrolledAt,omitempty"`
}

// RelayEnroll relays the client's EnrollBegin() blob to RootHerald via
// POST {baseURL}/api/v1/attest/enroll, authenticated with the rh_sk_ secret,
// and returns the challenge to hand back to the client's EnrollComplete.
// Admission runs under the identity policy bound to the API key; a device
// whose TPM class can never satisfy it is refused before it gets an
// attestation key, as ErrAdmissionRefused with the class in APIError.Message.
//
// The client never holds the rh_sk_ key and never talks to RootHerald; this
// backend helper is the only thing that does.
func (c *Client) RelayEnroll(ctx context.Context, blob EnrollRequestBlob) (RelayEnrollResult, error) {
	if err := validateEnrollBlob(blob); err != nil {
		return RelayEnrollResult{}, err
	}

	resp, err := c.rawPost(ctx, "/api/v1/attest/enroll", blob)
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
	if blob.Platform != PlatformIOS {
		if ch.EnrollmentID == "" {
			return RelayEnrollResult{}, fmt.Errorf("%w: enroll response missing enrollmentId", ErrAttestHTTP)
		}
		if (ch.CredentialBlob == "" || ch.EncryptedSecret == "") && ch.ChallengeNonce == "" {
			return RelayEnrollResult{}, fmt.Errorf("%w: enroll response missing credentialBlob/encryptedSecret or challengeNonce", ErrAttestHTTP)
		}
	}
	return RelayEnrollResult{Challenge: &ch}, nil
}

func validateEnrollBlob(blob EnrollRequestBlob) error {
	if blob.Platform == PlatformIOS {
		if blob.IOSKeyID == "" || blob.IOSAttestationObject == "" || blob.Nonce == "" {
			return fmt.Errorf("%w: RelayEnroll requires IOSKeyID, IOSAttestationObject and Nonce for platform ios", ErrInvalidEnrollBlob)
		}
		return nil
	}
	if blob.EkPublicKey == "" || blob.AkPublicArea == "" {
		return fmt.Errorf("%w: RelayEnroll requires EkPublicKey and AkPublicArea", ErrInvalidEnrollBlob)
	}
	return nil
}

// RelayActivate relays the client's EnrollComplete() blob to RootHerald via
// POST {baseURL}/api/v1/attest/activate, completing the enrollment. Every
// RelayEnroll of a TPM or macOS device leads here: enrollment always issues a
// challenge, including for a known device, because re-enrollment is how a
// device rotates its attestation key.
//
// It returns the terminal {DeviceID, Status, EnrolledAt} body; DeviceID is the
// load-bearing field the backend maps to its user. An unknown, spent or
// foreign EnrollmentID and a wrong proof are refused alike, as
// ErrInvalidSecretKey (401) with one message.
func (c *Client) RelayActivate(ctx context.Context, activation EnrollActivationResponse) (RelayActivateResponse, error) {
	if activation.EnrollmentID == "" || (activation.DecryptedSecret == "" && activation.Signature == "") {
		return RelayActivateResponse{}, fmt.Errorf("%w: RelayActivate requires EnrollmentID and DecryptedSecret or Signature", ErrInvalidActivation)
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
