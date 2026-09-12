package rootherald

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultBaseURL is the production RootHerald API base URL used by Client
// when no base URL is supplied.
const DefaultBaseURL = "https://rootherald.io"

// secretKeyPrefix marks a RootHerald secret key, used server-side as a Bearer
// token. Any key without this prefix is rejected by NewClient.
const secretKeyPrefix = "rh_sk_"

// Background-Check sentinel errors. Use errors.Is to switch on them. They mirror
// the HTTP status mapping of the @rootherald/node SDK:
//
//	401 -> ErrInvalidSecretKey   (bad/absent secret key)
//	422 -> ErrUnknownPolicy      (a policy bound to the API key no longer
//	                              exists; nothing is substituted)
//	422 -> ErrAdmissionRefused   (error code admission_refused: the device's TPM
//	                              class can never satisfy the identity policy
//	                              bound to the key)
//	409 -> ErrChallenge          (nonce unknown/expired/already used)
//	400 -> ErrInvalidEvidence    (evidence malformed/unparseable)
//	429 -> ErrQuotaExceeded      (rate/quota limit hit)
//
// A 422 is told apart by the server's error code; one without a recognised
// code is ErrUnknownPolicy. The refused TPM class travels in APIError.Message.
//
// An un-enrolled or failing device is NOT an error: Attest returns a normal
// verdict carrying VerdictDeny/VerdictReview. Only protocol/auth/quota problems
// surface as one of these errors.
var (
	ErrInvalidSecretKey = errors.New("rootherald: invalid secret key")
	ErrInvalidBaseURL   = errors.New("rootherald: invalid base URL")
	ErrUnknownPolicy    = errors.New("rootherald: unknown policy")
	ErrAdmissionRefused = errors.New("rootherald: enrollment refused for this device class")
	ErrChallenge        = errors.New("rootherald: challenge invalid or expired")
	ErrInvalidEvidence  = errors.New("rootherald: invalid evidence")
	ErrQuotaExceeded    = errors.New("rootherald: quota exceeded")
	ErrAttestHTTP       = errors.New("rootherald: attestation http error")
)

// Server error code that refines a 422 beyond "unknown policy".
const codeAdmissionRefused = "admission_refused"

// APIError carries the HTTP status and server-provided error detail for a
// failed Background-Check call. It wraps one of the sentinel errors above so
// callers can either errors.Is(err, ErrUnknownPolicy) or inspect StatusCode.
type APIError struct {
	StatusCode int
	Code       string // server "error" code, if any
	Message    string // server "message"/"error_description", if any
	sentinel   error
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("rootherald: api error (http %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("rootherald: api error (http %d)", e.StatusCode)
}

// Unwrap returns the matching sentinel so errors.Is works.
func (e *APIError) Unwrap() error { return e.sentinel }

// Ask names one thing a challenge asks the device to produce.
type Ask string

const (
	// AskIdentity asks for proof the evidence comes from the enrolled TPM.
	AskIdentity Ask = "identity"
	// AskPosture asks for the measured-boot event log alongside the quote.
	AskPosture Ask = "posture"
	// AskKey asks the device to create a TPM-resident signing key and certify it
	// with its attestation key. The verdict then carries the key's public half as
	// AttestResult.Key.
	AskKey Ask = "key"
)

// ChallengeOptions configures IssueChallengeWithOptions. The zero value asks
// for identity and posture, which is what IssueChallenge sends.
//
// There is no policy option. Policies bind to the API key: the key carries
// an identity policy and, on Pro, a posture policy, and the server resolves
// the one that applies from the key that mints the challenge.
type ChallengeOptions struct {
	// Ask lists what the device must produce. Empty means identity + posture.
	Ask []Ask
	// KeyPurpose is what a certified key will be used for. Read only when Ask
	// contains AskKey; "sign" is the only purpose today.
	KeyPurpose string
	// DeviceHint is an optional advisory hint identifying the device.
	DeviceHint string
}

// Challenge is minted by IssueChallenge. Relay the Challenge string to the
// dumb client verbatim; the client parses it to learn the nonce and the ask,
// quotes over the nonce, and returns an opaque evidence blob, which the server
// submits with Verify using Nonce.
type Challenge struct {
	// Nonce is the backend's handle for this challenge: 32 random bytes,
	// base64url without padding. The server finds the challenge by it at
	// Verify. It is the second segment of Challenge.
	Nonce string `json:"nonce"`
	// Challenge is the string to relay to the client:
	// "rhc1.<base64url nonce>.<base64url ask-json>".
	Challenge string `json:"challenge"`
	ExpiresAt string `json:"expiresAt"`
}

// JWK is the public half of a certified key, as the server returns it.
type JWK struct {
	// Kty is the key type; "EC" is the only one today.
	Kty string `json:"kty"`
	// Crv is the curve: "P-256" or "P-384".
	Crv string `json:"crv"`
	// X and Y are the base64url-encoded affine coordinates.
	X string `json:"x"`
	Y string `json:"y"`
}

// CertifiedKey is a TPM-resident signing key the appraisal certified. Store
// JWK against the user; a later request signed by the device is checked
// locally with VerifyKeySignature, with no call to RootHerald.
//
// KeyID identifies the key, not the device, and a fresh key is certified per
// ask.
type CertifiedKey struct {
	// KeyID is RootHerald's id for this key, stable for the key's lifetime.
	KeyID string `json:"keyId"`
	// JWK is the public key.
	JWK JWK `json:"jwk"`
	// Purpose echoes the challenge's KeyPurpose; "sign" today.
	Purpose string `json:"purpose"`
	// AuthPolicy is the base64 authPolicy digest from the key's public area,
	// when the key was created with one.
	AuthPolicy string `json:"authPolicy,omitempty"`
	// CertifiedAt is when the certification was appraised.
	CertifiedAt time.Time `json:"certifiedAt"`
}

// Evidence is the opaque, client-collected attestation blob. The SDK passes it
// through verbatim — it is never interpreted client-side.
type Evidence = json.RawMessage

// AttestOptions configures a single Verify call.
type AttestOptions struct {
	// Nonce is the single-use challenge handle from IssueChallenge. Required.
	// The evidence is appraised under the policy pinned on that challenge.
	Nonce string
	// RequestedDisclosureClass optionally requests how much device detail the
	// verdict should disclose: "verdict" | "pseudonymous" | "derived" | "full".
	// Empty omits the request and lets the server apply its default.
	RequestedDisclosureClass string
}

// AttestResult is the verdict returned by Attest. Verdict is mapped to the SDK
// enum from the raw "pass"/"fail"/"warn" the server emits.
type AttestResult struct {
	Verdict Verdict
	// Device is the typed view of the server's verdict.device object, including
	// the additive, advisory-only cohort fields. It is nil if the response
	// carried no device object.
	Device *DeviceVerdict
	// AssuranceClaimsMet lists the assurance claim URNs the device satisfied
	// (top-level "assuranceClaimsMet"), mirroring @rootherald/node.
	AssuranceClaimsMet []string
	// EnrollmentRequired is the top-level "enrollmentRequired" attest-first /
	// enroll-on-miss signal: true when the device must enroll before a verdict
	// can be issued.
	EnrollmentRequired bool
	// Key is the signing key the appraisal certified (top-level "key"). Present
	// only when the challenge asked for AskKey and the verdict passed; nil
	// otherwise, whatever the evidence carried.
	Key *CertifiedKey
	// Raw is the full decoded verdict object as returned by the server, for
	// callers that need fields the typed surface does not expose yet.
	Raw map[string]any
}

// Client is the server -> server Background-Check client. The customer's
// dumb client collects an opaque evidence blob (no keys, no RootHerald contact)
// and hands it to the customer's own server; the server uses this client,
// authenticated with its rh_sk_ secret key, to mint a nonce (IssueChallenge)
// and submit the evidence for appraisal (Attest).
//
// Construct with NewClient; instances are safe for concurrent use.
type Client struct {
	secretKey string
	baseURL   string
	http      *http.Client
}

// ClientOption customises an Client.
type ClientOption func(*Client)

// WithBaseURL overrides the default production base URL.
func WithBaseURL(baseURL string) ClientOption {
	return func(c *Client) { c.baseURL = strings.TrimRight(baseURL, "/") }
}

// WithHTTPClient swaps the underlying *http.Client (timeouts, proxies,
// tests).
func WithHTTPClient(h *http.Client) ClientOption {
	return func(c *Client) { c.http = h }
}

// NewClient builds a Background-Check client. secretKey is required and
// must start with rh_sk_; any other value is rejected.
func NewClient(secretKey string, opts ...ClientOption) (*Client, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("%w: a secret key (rh_sk_…) is required", ErrInvalidSecretKey)
	}
	if !strings.HasPrefix(secretKey, secretKeyPrefix) {
		return nil, fmt.Errorf("%w: RootHerald secret key must start with rh_sk_", ErrInvalidSecretKey)
	}
	c := &Client{
		secretKey: secretKey,
		baseURL:   DefaultBaseURL,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	if err := requireSecureBaseURL(c.baseURL); err != nil {
		return nil, err
	}
	return c, nil
}

// requireSecureBaseURL rejects a base URL that would put the rh_sk_ secret on the
// wire in the clear.
//
// Every request carries the secret in an Authorization header, and the secret is
// full-privilege, so a base URL that is http:// or is missing its scheme entirely
// leaks it to anyone on the path. A typo is enough; nothing else in the SDK would
// notice, because the request itself succeeds.
//
// Loopback is exempt so the local docker stack still works over http.
func requireSecureBaseURL(baseURL string) error {
	u, err := url.Parse(baseURL)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("%w: base URL must be an absolute https URL (got %q)",
			ErrInvalidBaseURL, baseURL)
	}
	if u.Scheme == "https" {
		return nil
	}
	if isLoopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("%w: base URL must use https (got %q)", ErrInvalidBaseURL, baseURL)
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// IssueChallenge mints a challenge asking for identity and posture via
// POST {baseURL}/api/v1/attest/challenge. deviceHint is optional and may
// be "" to omit it. Relay the returned Challenge string to the client; the
// client quotes over the nonce inside it, then submit the resulting evidence
// with Verify using Nonce. Use IssueChallengeWithOptions to change the ask.
func (c *Client) IssueChallenge(ctx context.Context, deviceHint string) (Challenge, error) {
	return c.IssueChallengeWithOptions(ctx, ChallengeOptions{DeviceHint: deviceHint})
}

// IssueChallengeWithOptions mints a challenge carrying the given ask via
// POST {baseURL}/api/v1/attest/challenge. Relay the returned Challenge string
// to the client verbatim; it parses the ask from it and produces matching
// evidence, which the server submits with Verify using Nonce.
//
// The policy the challenge will be appraised under is resolved from the API
// key and pinned on the challenge at mint. The SDK never sends a policy field;
// a hand-built body that carries one is refused with 400 policy_bound_to_key.
// Change what a key enforces from the dashboard or
// PUT /api/v1/admin/api-keys/{id}/policies.
func (c *Client) IssueChallengeWithOptions(ctx context.Context, opts ChallengeOptions) (Challenge, error) {
	body := map[string]any{}
	if opts.DeviceHint != "" {
		body["deviceHint"] = opts.DeviceHint
	}
	if len(opts.Ask) > 0 {
		body["ask"] = opts.Ask
	}
	if opts.KeyPurpose != "" {
		body["keyPurpose"] = opts.KeyPurpose
	}
	var out Challenge
	if err := c.post(ctx, "/api/v1/attest/challenge", body, &out); err != nil {
		return Challenge{}, err
	}
	if out.Nonce == "" || out.Challenge == "" || out.ExpiresAt == "" {
		return Challenge{}, fmt.Errorf("%w: challenge response missing nonce/challenge/expiresAt", ErrAttestHTTP)
	}
	return out, nil
}

// verifyResponseBody is the wire shape of the verify endpoint. The pass/fail
// token lives at verdict.device.verdict; assuranceClaimsMet, enrollmentRequired
// and key are top-level siblings of verdict.
type verifyResponseBody struct {
	Verdict            map[string]any `json:"verdict"`
	AssuranceClaimsMet []string       `json:"assuranceClaimsMet"`
	EnrollmentRequired bool           `json:"enrollmentRequired"`
	Key                *CertifiedKey  `json:"key"`
}

// Verify submits the opaque evidence blob for server-side appraisal via
// POST {baseURL}/api/v1/attest/verify and returns the verdict. The verdict
// is computed by RootHerald and returned here, to the customer's backend — it
// never travels through the client, which holds no key and gets no verdict.
//
// The server finds the challenge by the nonce and the device by the proof
// inside the evidence; nothing in the request names a device. A proof from a
// device that is not enrolled is a failing verdict with EnrollmentRequired
// set, not an error.
//
// The evidence is appraised under the policy pinned on the challenge at mint,
// which the server resolved from the API key. The SDK never sends a policy
// field; a hand-built body that carries one is refused with 400
// policy_bound_to_key.
//
// An un-enrolled / failing device is NOT an error — it returns a normal verdict
// carrying VerdictDeny/VerdictReview. Only protocol/auth/quota problems return
// a non-nil error (see the package sentinels). evidence is passed through
// verbatim.
func (c *Client) Verify(ctx context.Context, evidence Evidence, opts AttestOptions) (AttestResult, error) {
	if opts.Nonce == "" {
		return AttestResult{}, fmt.Errorf("%w: Verify requires Nonce (from IssueChallenge)", ErrChallenge)
	}
	body := map[string]any{
		"nonce":    opts.Nonce,
		"evidence": json.RawMessage(evidence),
	}
	if opts.RequestedDisclosureClass != "" {
		body["requestedDisclosureClass"] = opts.RequestedDisclosureClass
	}

	var resp verifyResponseBody
	if err := c.post(ctx, "/api/v1/attest/verify", body, &resp); err != nil {
		return AttestResult{}, err
	}
	if resp.Verdict == nil {
		return AttestResult{}, fmt.Errorf("%w: verify response missing verdict", ErrAttestHTTP)
	}
	// The pass/fail token lives at verdict.device.verdict, not top-level
	// verdict.verdict; read it from the parsed device so a passing device is not
	// silently downgraded to review/deny.
	device := parseDeviceVerdict(resp.Verdict["device"])
	var rawVerdict string
	if device != nil {
		rawVerdict = device.Verdict
	}
	verdict := mapVerdict(rawVerdict)
	key := resp.Key
	if key != nil && (key.KeyID == "" || key.JWK.Kty == "" || key.JWK.X == "" || key.JWK.Y == "") {
		return AttestResult{}, fmt.Errorf("%w: verify response key missing keyId/jwk", ErrAttestHTTP)
	}
	if verdict != VerdictAllow {
		// The contract certifies nothing on a failing verdict; do not let a
		// stray key on the wire outlive the verdict it came with.
		key = nil
	}
	return AttestResult{
		Verdict:            verdict,
		Device:             device,
		AssuranceClaimsMet: resp.AssuranceClaimsMet,
		EnrollmentRequired: resp.EnrollmentRequired,
		Key:                key,
		Raw:                resp.Verdict,
	}, nil
}

// parseDeviceVerdict decodes the verdict.device object (already an any from the
// generic JSON decode) into a typed *DeviceVerdict, carrying the additive cohort
// fields. Returns nil when no device object is present or it cannot be decoded;
// the raw verdict map remains available on AttestResult.Raw regardless.
func parseDeviceVerdict(device any) *DeviceVerdict {
	if device == nil {
		return nil
	}
	b, err := json.Marshal(device)
	if err != nil {
		return nil
	}
	var dv DeviceVerdict
	if err := json.Unmarshal(b, &dv); err != nil {
		return nil
	}
	return &dv
}

// rawPost issues an authenticated JSON POST and returns the raw *http.Response.
// It maps only transport failures to ErrAttestHTTP; status interpretation is
// left to the caller. The caller owns closing resp.Body.
func (c *Client) rawPost(ctx context.Context, path string, body any) (*http.Response, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("%w: marshal request: %v", ErrAttestHTTP, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestHTTP, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAttestHTTP, err)
	}
	return resp, nil
}

// post issues an authenticated JSON POST and decodes the 2xx body into out,
// mapping non-2xx responses to the matching typed error.
func (c *Client) post(ctx context.Context, path string, body any, out any) error {
	resp, err := c.rawPost(ctx, path, body)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode/100 != 2 {
		return toAPIError(resp)
	}
	if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
		return fmt.Errorf("%w: malformed response: %v", ErrAttestHTTP, err)
	}
	return nil
}

// toAPIError maps a non-2xx response to a typed *APIError wrapping the matching
// sentinel, mirroring the @rootherald/node status mapping.
func toAPIError(resp *http.Response) error {
	rawBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Error            string `json:"error"`
		Message          string `json:"message"`
		ErrorDescription string `json:"error_description"`
	}
	_ = json.Unmarshal(rawBody, &parsed)
	msg := parsed.Message
	if msg == "" {
		msg = parsed.ErrorDescription
	}

	var sentinel error
	switch resp.StatusCode {
	case http.StatusUnauthorized: // 401
		sentinel = ErrInvalidSecretKey
	case http.StatusUnprocessableEntity: // 422
		switch parsed.Error {
		case codeAdmissionRefused:
			sentinel = ErrAdmissionRefused
		default:
			sentinel = ErrUnknownPolicy
		}
	case http.StatusConflict: // 409
		sentinel = ErrChallenge
	case http.StatusBadRequest: // 400
		sentinel = ErrInvalidEvidence
	case http.StatusTooManyRequests: // 429
		sentinel = ErrQuotaExceeded
	default:
		sentinel = ErrAttestHTTP
		if msg == "" {
			msg = strings.TrimSpace(string(rawBody))
		}
	}
	return &APIError{
		StatusCode: resp.StatusCode,
		Code:       parsed.Error,
		Message:    msg,
		sentinel:   sentinel,
	}
}
