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
	// ErrInvalidEnrollBlob is returned by RelayEnroll and RelayEnrollJSON
	// when the supplied enroll body is missing the fields its platform
	// requires, or is the flat wire 7.0 TPM shape.
	ErrInvalidEnrollBlob = errors.New("rootherald: invalid enroll request blob")
	// ErrInvalidActivation is returned by RelayActivate when the supplied
	// EnrollActivationResponse is missing its EnrollmentID or its proof.
	ErrInvalidActivation = errors.New("rootherald: invalid activation response")
)

// Platform is the platform an enroll blob was produced on. The server records
// it on the installation and later demands the activation proof of the
// RECORDED platform, so reshaping a blob cannot move a TPM device onto a
// weaker ceremony.
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

// AttestationKeyPublic is the per-installation attestation key, as
// EnrollBegin() describes it to the server. All three fields are base64.
//
// The server recomputes the qualified name from the two public areas and
// refuses the enrollment (400 invalid_enroll_shape) when it differs from
// QualifiedName, so a key created under the wrong parent fails before any
// elevation prompt and before any row is written.
type AttestationKeyPublic struct {
	// PublicArea is the TPM2B_PUBLIC of the AK, as TPM2_Create emitted it.
	PublicArea string `json:"publicArea"`
	// ParentPublicArea is the TPM2B_PUBLIC of the storage parent the AK was
	// created under.
	ParentPublicArea string `json:"parentPublicArea"`
	// QualifiedName is the TPM2B_NAME qualified name of the AK, as
	// TPM2_ReadPublic returned it.
	QualifiedName string `json:"qualifiedName"`
}

// EnrollRequestBlob is the client's EnrollBegin() output — the body of
// POST /api/v1/attest/enroll. This backend helper relays it to RootHerald,
// which validates it and returns an EnrollActivationChallenge. Which fields
// are set depends on Platform:
//
//	windows | linux   EkPublicKey and AttestationKey, and optionally
//	                  EkCertPem, EkCertificateChain, TpmSelfReport
//	macos             EkPublicKey and AkPublicArea, both the enclave key
//	ios               IOSKeyID, IOSAttestationObject, Nonce
//
// The nested AttestationKey is what tells a wire 8.0 TPM body from a 7.0
// one; a TPM body with a top-level AkPublicArea is refused locally
// (ErrInvalidEnrollBlob). The macOS body stays flat and is never refused for
// its shape.
//
// No device identifier travels in this body: the server derives the device
// from the key material itself.
type EnrollRequestBlob struct {
	// EkPublicKey is the base64 TPM2B_PUBLIC of the endorsement key on a TPM
	// platform; on macOS it is the enclave key, X9.63 uncompressed.
	EkPublicKey string `json:"ekPublicKey,omitempty"`
	// AttestationKey is this installation's attestation key and its parent.
	// Set for windows | linux.
	AttestationKey *AttestationKeyPublic `json:"attestationKey,omitempty"`
	// AkPublicArea is the enclave key again, the same as EkPublicKey. Set for
	// macos only: a TPM body carrying it is the wire 7.0 shape.
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
// Enrollment always issues a challenge, including for a device already known:
// each activation creates a new installation of the device with its own AK
// blob, which the client keeps. Hand Challenge to the client's EnrollComplete,
// then pass the result to RelayActivate. The device's alias is returned by
// RelayActivate, not here, and does not change across installations.
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
// The typed blob carries the fields this SDK models; when the backend holds
// the client's JSON, RelayEnrollJSON relays it byte-for-byte instead.
//
// The client never holds the rh_sk_ key and never talks to RootHerald; this
// backend helper is the only thing that does.
func (c *Client) RelayEnroll(ctx context.Context, blob EnrollRequestBlob) (RelayEnrollResult, error) {
	if err := validateEnrollBlob(blob); err != nil {
		return RelayEnrollResult{}, err
	}
	body, err := json.Marshal(blob)
	if err != nil {
		return RelayEnrollResult{}, fmt.Errorf("%w: %v", ErrInvalidEnrollBlob, err)
	}
	return c.relayEnroll(ctx, blob.Platform, body)
}

// RelayEnrollJSON relays the client's EnrollBegin() output byte-for-byte.
// Prefer it when the backend holds the device's JSON: fields this SDK does
// not model reach RootHerald unchanged. The body is validated the same way
// as RelayEnroll before any request is made.
func (c *Client) RelayEnrollJSON(ctx context.Context, body json.RawMessage) (RelayEnrollResult, error) {
	var probe EnrollRequestBlob
	if err := json.Unmarshal(body, &probe); err != nil {
		return RelayEnrollResult{}, fmt.Errorf("%w: %v", ErrInvalidEnrollBlob, err)
	}
	if err := validateEnrollBlob(probe); err != nil {
		return RelayEnrollResult{}, err
	}
	return c.relayEnroll(ctx, probe.Platform, body)
}

func (c *Client) relayEnroll(ctx context.Context, platform Platform, body json.RawMessage) (RelayEnrollResult, error) {
	resp, err := c.rawPost(ctx, "/api/v1/attest/enroll", body)
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
	if platform != PlatformIOS {
		if ch.EnrollmentID == "" {
			return RelayEnrollResult{}, fmt.Errorf("%w: enroll response missing enrollmentId", ErrAttestHTTP)
		}
		if (ch.CredentialBlob == "" || ch.EncryptedSecret == "") && ch.ChallengeNonce == "" {
			return RelayEnrollResult{}, fmt.Errorf("%w: enroll response missing credentialBlob/encryptedSecret or challengeNonce", ErrAttestHTTP)
		}
	}
	return RelayEnrollResult{Challenge: &ch}, nil
}

// validateEnrollBlob accepts the three shapes the server does. A flat TPM
// body is the 7.0 shape and is refused here rather than relayed: the server
// would answer wire_version_unsupported anyway, and refusing locally keeps
// the message specific.
func validateEnrollBlob(blob EnrollRequestBlob) error {
	switch blob.Platform {
	case PlatformIOS:
		if blob.IOSKeyID == "" || blob.IOSAttestationObject == "" || blob.Nonce == "" {
			return fmt.Errorf("%w: RelayEnroll requires IOSKeyID, IOSAttestationObject and Nonce for platform ios", ErrInvalidEnrollBlob)
		}
	case PlatformMacOS:
		if blob.EkPublicKey == "" || blob.AkPublicArea == "" || blob.AttestationKey != nil {
			return fmt.Errorf("%w: RelayEnroll requires EkPublicKey and AkPublicArea, and no AttestationKey, for platform macos", ErrInvalidEnrollBlob)
		}
	case PlatformWindows, PlatformLinux:
		ak := blob.AttestationKey
		if blob.EkPublicKey == "" || ak == nil || ak.PublicArea == "" || ak.ParentPublicArea == "" || ak.QualifiedName == "" {
			return fmt.Errorf("%w: RelayEnroll requires EkPublicKey and AttestationKey{PublicArea, ParentPublicArea, QualifiedName} for platform %s", ErrInvalidEnrollBlob, blob.Platform)
		}
		if blob.AkPublicArea != "" {
			return fmt.Errorf("%w: a TPM enroll body with a top-level akPublicArea is the wire 7.0 shape; wire 8.0 nests the AK under attestationKey", ErrInvalidEnrollBlob)
		}
	default:
		return fmt.Errorf("%w: RelayEnroll requires Platform windows, linux, macos or ios (got %q)", ErrInvalidEnrollBlob, blob.Platform)
	}
	return nil
}

// RelayActivate relays the client's EnrollComplete() blob to RootHerald via
// POST {baseURL}/api/v1/attest/activate, completing the enrollment. Every
// RelayEnroll of a TPM or macOS device leads here: enrollment always issues a
// challenge, including for a known device, because each activation creates a
// new installation.
//
// It returns the terminal {DeviceID, Status, EnrolledAt} body; DeviceID is the
// load-bearing field the backend maps to its user. An unknown, spent or
// foreign EnrollmentID, a wrong proof and a cross-tenant AK collision are
// refused alike, as ErrActivationRefused (401) with one message.
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
