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
	"strconv"
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
//	401 -> ErrActivationRefused  (error code activation_refused: the
//	                              enrollmentId is unknown, spent or foreign, or
//	                              the proof did not match; the key was accepted)
//	401 -> ErrInvalidSecretKey   (any other 401: bad/absent secret key)
//	422 -> ErrUnknownPolicy      (error code unknown_policy, or none: a policy
//	                              bound to the API key no longer exists;
//	                              nothing is substituted)
//	422 -> ErrAdmissionRefused   (error code admission_refused: the device's TPM
//	                              class can never satisfy the identity policy
//	                              bound to the key)
//	409 -> ErrChallenge          (nonce unknown/expired/already used; a 409
//	                              key_rotation_conflict is ErrAttestHTTP)
//	400 -> ErrInvalidAsk         (error code invalid_ask: the challenge named
//	                              an ask the server does not know, such as the
//	                              retired "key"; the backend's code is wrong,
//	                              not the device)
//	400 -> ErrInvalidEvidence    (any other 400: a relayed blob was malformed
//	                              or could not be appraised, including
//	                              wire_version_unsupported and
//	                              invalid_enroll_shape on enroll)
//	429 -> ErrQuotaExceeded      (error code budget_exhausted or an
//	                              X-RootHerald-Quota header: the API key's
//	                              budget cannot pay for a device new to the
//	                              period; APIError.Budget names it)
//	429 -> ErrRateLimited        (any other 429: the request-rate limiter;
//	                              APIError.RetryAfterSeconds says how long)
//
// Where one status carries two refusals the server's error code (or a header)
// tells them apart. A status or code no sentinel covers — including 422
// expected_unknown, key_disclosure_too_low and posture_not_bound, 409
// key_rotation_conflict and 402 plan_lapsed — is ErrAttestHTTP with the code
// preserved in APIError.Code. The refused TPM class travels in APIError.Message.
//
// ErrInvalidArgument flags input the SDK refused locally, before any network
// call (an empty Nonce, for example). ErrExpectedNotEnforced is Verify refusing
// a verdict that does not echo the ExpectedKey / ExpectedDevices the caller
// passed: the binding was asked for and the server did not enforce it.
//
// An un-enrolled or failing device is NOT an error: Verify returns a normal
// verdict carrying VerdictFail/VerdictWarn. Only protocol/auth/quota problems
// surface as one of these errors.
var (
	ErrInvalidSecretKey    = errors.New("rootherald: invalid secret key")
	ErrActivationRefused   = errors.New("rootherald: activation refused")
	ErrInvalidBaseURL      = errors.New("rootherald: invalid base URL")
	ErrInvalidArgument     = errors.New("rootherald: invalid argument")
	ErrUnknownPolicy       = errors.New("rootherald: unknown policy")
	ErrAdmissionRefused    = errors.New("rootherald: enrollment refused for this device class")
	ErrChallenge           = errors.New("rootherald: challenge invalid or expired")
	ErrInvalidAsk          = errors.New("rootherald: invalid ask")
	ErrInvalidEvidence     = errors.New("rootherald: invalid evidence")
	ErrQuotaExceeded       = errors.New("rootherald: budget exhausted")
	ErrRateLimited         = errors.New("rootherald: rate limited")
	ErrExpectedNotEnforced = errors.New("rootherald: verdict does not echo the expected binding")
	ErrAttestHTTP          = errors.New("rootherald: attestation http error")
)

// Server error codes that tell apart the refusals sharing one status.
const (
	codeActivationRefused   = "activation_refused"
	codeAdmissionRefused    = "admission_refused"
	codeUnknownPolicy       = "unknown_policy"
	codeBudgetExhausted     = "budget_exhausted"
	codeInvalidAsk          = "invalid_ask"
	codeKeyRotationConflict = "key_rotation_conflict"
)

// quotaHeader marks a 429 as the budget ceiling, whatever the body says.
const quotaHeader = "X-RootHerald-Quota"

// DefaultTimeout is the per-request HTTP timeout of the http.Client NewClient
// builds when WithHTTPClient is not given. It is the same in every RootHerald
// server SDK.
const DefaultTimeout = 30 * time.Second

// Budget names the budget that refused a device, as the server sends it on a
// 429 budget_exhausted.
type Budget struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// APIError carries the HTTP status and server-provided error detail for a
// failed Background-Check call. It wraps one of the sentinel errors above so
// callers can either errors.Is(err, ErrUnknownPolicy) or inspect StatusCode.
type APIError struct {
	StatusCode int
	Code       string // server "error" code, if any
	Message    string // server "message"/"error_description", if any
	// RetryAfterSeconds is how long a rate-limited (ErrRateLimited) call should
	// wait before retrying: the Retry-After header, else the body's
	// retryAfterSeconds. 0 when the server gave neither.
	RetryAfterSeconds int
	// Budget is the budget that refused (ErrQuotaExceeded), when the server
	// named it.
	Budget   *Budget
	sentinel error
}

func (e *APIError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("rootherald: api error (http %d): %s", e.StatusCode, e.Message)
	}
	return fmt.Sprintf("rootherald: api error (http %d)", e.StatusCode)
}

// Unwrap returns the matching sentinel so errors.Is works.
func (e *APIError) Unwrap() error { return e.sentinel }

// Ask names one thing a challenge asks the device to prove. Keys are never
// asked for here; they have their own ceremony (IssueKeyChallenge /
// CertifyKey). A challenge that still asks for "key" is refused with
// 400 invalid_ask (ErrInvalidAsk).
type Ask string

const (
	// AskIdentity asks for proof the evidence comes from the enrolled
	// installation: a quote under its attestation key.
	AskIdentity Ask = "identity"
	// AskPosture asks for the measured-boot event log alongside the quote.
	AskPosture Ask = "posture"
)

// ChallengeOptions configures IssueChallengeWithOptions. The zero value asks
// for identity and posture, which is what IssueChallenge sends.
//
// There is no policy option. Policies bind to the API key: the key carries
// an identity policy and, on Pro, a posture policy, and the server resolves
// the one that applies from the key that mints the challenge.
type ChallengeOptions struct {
	// Ask lists what the device must prove. Empty means identity + posture.
	Ask []Ask
	// ExpectedKey is the KeyID of a key you certified. Only the installation
	// holding that key can pass; any other answers a failing verdict with
	// reason expected_device_mismatch. An unknown id is 422 expected_unknown.
	ExpectedKey string
	// ExpectedDevices lists aliases (DeviceVerdict.UEID) you enrolled. Only
	// one of them can pass; any other device answers a failing verdict with
	// reason expected_device_mismatch. An unknown alias is 422
	// expected_unknown. nil omits the field; an empty list or a blank entry
	// is ErrInvalidArgument.
	ExpectedDevices []string
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

// KeyPurpose is what a minted key is for. One live key per installation per
// purpose; minting again rotates it under the same KeyID.
type KeyPurpose string

const (
	// KeyPurposeSign is a signing key (ES256 or RS256).
	KeyPurposeSign KeyPurpose = "sign"
	// KeyPurposeDecrypt is a decrypt key (ECDH-ES or RSA-OAEP-256). The
	// server refuses the purpose before wire 8.1.
	KeyPurposeDecrypt KeyPurpose = "decrypt"
)

// KeyChallengeOptions configures IssueKeyChallenge.
type KeyChallengeOptions struct {
	// Purpose is what the key is for. Required.
	Purpose KeyPurpose
	// ExpectedDevices lists aliases (DeviceVerdict.UEID) you enrolled. The
	// certify leg is refused unless one of them certified the key. Pass the
	// alias of the device that just passed an attest challenge, so the key
	// provably comes from it. nil omits the field.
	ExpectedDevices []string
}

// KeyChallenge is minted by IssueKeyChallenge. Relay the KeyChallenge string
// to the client verbatim; its MintKey answers with a certification, which the
// server submits with CertifyKey using Nonce.
type KeyChallenge struct {
	// Nonce is the backend's handle for this key challenge, as
	// Challenge.Nonce.
	Nonce string `json:"nonce"`
	// KeyChallenge is the string to relay to the client:
	// "rhk1c.<base64url nonce>.<base64url purpose-json>".
	KeyChallenge string `json:"keyChallenge"`
	ExpiresAt    string `json:"expiresAt"`
}

// Certification is the device's MintKey output: on a TPM
// {publicArea, attest, signature}; on macOS {platform: "macos", publicKey,
// signature}; on iOS {platform: "ios", keyId, assertion}. The SDK relays it
// verbatim and checks only that outer shape.
type Certification = json.RawMessage

// JWK is the public half of a certified key, as the server returns it: an EC
// P-256 key (Crv, X, Y) or an RSA-2048 key (N, E). The device chooses the
// family; the server reads it from the certified public area.
type JWK struct {
	// Kty is the key type: "EC" or "RSA".
	Kty string `json:"kty"`
	// Crv is the curve of an EC key: "P-256".
	Crv string `json:"crv,omitempty"`
	// X and Y are the base64url-encoded affine coordinates of an EC key.
	X string `json:"x,omitempty"`
	Y string `json:"y,omitempty"`
	// N and E are the base64url-encoded modulus and exponent of an RSA key.
	N string `json:"n,omitempty"`
	E string `json:"e,omitempty"`
}

// CertifiedKey is the key RootHerald registered against the installation
// that certified it, as CertifyKey returns it. Store JWK against DeviceID; a
// later request signed by the device is checked locally with
// VerifyKeySignature, with no call to RootHerald.
//
// KeyID identifies an installation's credential, never a device: bind
// accounts to DeviceID (the alias). Minting again for the same purpose
// rotates the key under the same KeyID; a re-enrolled installation gets new
// key IDs.
type CertifiedKey struct {
	// DeviceID is this tenant's alias for the device that holds the key
	// (DeviceVerdict.UEID).
	DeviceID string `json:"deviceId"`
	// KeyID is RootHerald's id for this key, stable across rotations of the
	// same purpose.
	KeyID string `json:"keyId"`
	// Purpose is the key's purpose, as the key challenge named it.
	Purpose KeyPurpose `json:"purpose"`
	// Alg is the JOSE algorithm the key is used with: "ES256" / "RS256" for a
	// sign key, "ECDH-ES" / "RSA-OAEP-256" for a decrypt key.
	Alg string `json:"alg"`
	// Format is present for a decrypt key: "jwe" on TPM platforms,
	// "apple-ecies" on macOS.
	Format string `json:"format,omitempty"`
	// JWK is the public key.
	JWK JWK `json:"jwk"`
	// HardwareBound is true when the key lives in a TPM and was certified by
	// the installation's AK; false on macOS, where the certification proves
	// possession only.
	HardwareBound bool `json:"hardwareBound"`
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
	// ExpectedKey is the ExpectedKey the challenge was issued with. Verify
	// refuses a verdict that does not echo it (ErrExpectedNotEnforced), so a
	// server that ignored the binding cannot pass silently.
	ExpectedKey string
	// ExpectedDevices is the ExpectedDevices the challenge was issued with.
	// Verify refuses a verdict that does not echo them, and a non-failing
	// verdict naming a device outside them (ErrExpectedNotEnforced).
	ExpectedDevices []string
}

// AttestResult is the verdict returned by Verify. Verdict is the server's
// "pass"/"warn"/"fail" token from verdict.device.verdict.
type AttestResult struct {
	Verdict Verdict
	// Device is the typed view of the server's verdict.device object. It is
	// nil if the response carried no device object.
	Device *DeviceVerdict
	// Expected is what the challenge bound the verdict to, echoed by the
	// server after it enforced it (verdict.expected). nil when the challenge
	// named nothing.
	Expected *ExpectedBinding
	// AssuranceClaimsMet lists the assurance claim URNs the device satisfied
	// (top-level "assuranceClaimsMet"), mirroring @rootherald/node.
	AssuranceClaimsMet []string
	// EnrollmentRequired is the top-level "enrollmentRequired" attest-first /
	// enroll-on-miss signal: true when the quote did not resolve to a live
	// installation of yours. The client should enroll; do not trust the
	// verdict.
	EnrollmentRequired bool
	// Raw is the full decoded verdict object as returned by the server, for
	// callers that need fields the typed surface does not expose yet.
	Raw map[string]any
}

// Client is the server -> server Background-Check client. The customer's
// dumb client does local TPM work (no keys, no RootHerald contact) and hands
// the customer's own server opaque blobs; the server uses this client,
// authenticated with its rh_sk_ secret key, to drive three ceremonies of two
// legs each:
//
//	enroll      RelayEnroll / RelayActivate         the installation's AK is bound to its EK
//	mint a key  IssueKeyChallenge / CertifyKey      the AK certifies a new sign or decrypt key
//	attest      IssueChallenge / Verify             the AK quotes what the challenge asked
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
// tests). The caller's client is used as given, including its Timeout.
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
		http:      &http.Client{Timeout: DefaultTimeout},
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
// POST {baseURL}/api/v1/attest/challenge. Relay the returned Challenge string
// to the client; the client quotes over the nonce inside it, then submit the
// resulting evidence with Verify using Nonce. Use IssueChallengeWithOptions to
// change the ask or to name the device that must answer.
func (c *Client) IssueChallenge(ctx context.Context) (Challenge, error) {
	return c.IssueChallengeWithOptions(ctx, ChallengeOptions{})
}

// IssueChallengeWithOptions mints a challenge carrying the given ask via
// POST {baseURL}/api/v1/attest/challenge. Relay the returned Challenge string
// to the client verbatim; it parses the ask from it and produces matching
// evidence, which the server submits with Verify using Nonce.
//
// ExpectedKey and ExpectedDevices are resolved when the challenge is minted
// and enforced after the proof verifies; the client never sees them. Pass the
// same values to Verify, which refuses a verdict that does not echo them.
//
// The policy the challenge will be appraised under is resolved from the API
// key and pinned on the challenge at mint. The SDK never sends a policy field;
// a hand-built body that carries one is refused with 400 policy_bound_to_key.
// Change what a key enforces from the dashboard or
// PUT /api/v1/admin/api-keys/{id}/policies.
func (c *Client) IssueChallengeWithOptions(ctx context.Context, opts ChallengeOptions) (Challenge, error) {
	body := map[string]any{}
	if len(opts.Ask) > 0 {
		body["ask"] = opts.Ask
	}
	if opts.ExpectedKey != "" {
		body["expectedKey"] = opts.ExpectedKey
	}
	if opts.ExpectedDevices != nil {
		if err := requireAliasList(opts.ExpectedDevices, "ExpectedDevices"); err != nil {
			return Challenge{}, err
		}
		body["expectedDevices"] = opts.ExpectedDevices
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

// requireAliasList refuses an alias list the server would read as "no device
// may answer" or as a blank alias.
func requireAliasList(aliases []string, field string) error {
	if len(aliases) == 0 {
		return fmt.Errorf("%w: %s must name at least one alias", ErrInvalidArgument, field)
	}
	for _, a := range aliases {
		if a == "" {
			return fmt.Errorf("%w: %s must not contain an empty alias", ErrInvalidArgument, field)
		}
	}
	return nil
}

// verifyResponseBody is the wire shape of the verify endpoint. The pass/fail
// token lives at verdict.device.verdict; assuranceClaimsMet and
// enrollmentRequired are top-level siblings of verdict.
type verifyResponseBody struct {
	Verdict            map[string]any `json:"verdict"`
	AssuranceClaimsMet []string       `json:"assuranceClaimsMet"`
	EnrollmentRequired bool           `json:"enrollmentRequired"`
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
// When the challenge named ExpectedKey or ExpectedDevices, pass the same
// values here: the verdict must echo them under Expected, and a response
// that does not is refused with ErrExpectedNotEnforced. They are compared
// locally and never sent.
//
// An un-enrolled / failing device is NOT an error — it returns a normal verdict
// carrying VerdictFail/VerdictWarn. Only protocol/auth/quota problems return
// a non-nil error (see the package sentinels); an empty Nonce is
// ErrInvalidArgument before any request is made. evidence is passed through
// verbatim.
func (c *Client) Verify(ctx context.Context, evidence Evidence, opts AttestOptions) (AttestResult, error) {
	if opts.Nonce == "" {
		return AttestResult{}, fmt.Errorf("%w: Verify requires Nonce (from IssueChallenge)", ErrInvalidArgument)
	}
	if opts.ExpectedDevices != nil {
		if err := requireAliasList(opts.ExpectedDevices, "ExpectedDevices"); err != nil {
			return AttestResult{}, err
		}
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
	// verdict.verdict.
	device := decodeInto[DeviceVerdict](resp.Verdict["device"])
	var rawVerdict string
	if device != nil {
		rawVerdict = device.Verdict
	}
	verdict, ok := parseVerdict(rawVerdict)
	if !ok {
		return AttestResult{}, fmt.Errorf("%w: verify response verdict.device.verdict is not pass/warn/fail (got %q)", ErrAttestHTTP, rawVerdict)
	}
	result := AttestResult{
		Verdict:            verdict,
		Device:             device,
		Expected:           decodeInto[ExpectedBinding](resp.Verdict["expected"]),
		AssuranceClaimsMet: resp.AssuranceClaimsMet,
		EnrollmentRequired: resp.EnrollmentRequired,
		Raw:                resp.Verdict,
	}
	if opts.ExpectedKey != "" || opts.ExpectedDevices != nil {
		if err := requireExpectedEnforced(result, opts.ExpectedKey, opts.ExpectedDevices); err != nil {
			return AttestResult{}, err
		}
	}
	return result, nil
}

// requireExpectedEnforced refuses a verdict that is not as bound as the caller
// asked. The API ignores unknown JSON fields, so a server that predates the
// binding would accept any device and answer a verdict with no expected
// block; comparing the echo with what was asked turns that silence into a
// refusal.
func requireExpectedEnforced(result AttestResult, expectedKey string, expectedDevices []string) error {
	echoed := result.Expected
	if expectedKey != "" && (echoed == nil || echoed.Key != expectedKey) {
		return fmt.Errorf("%w: verify response did not echo the ExpectedKey the challenge named", ErrExpectedNotEnforced)
	}
	if expectedDevices != nil {
		if echoed == nil || !sameSet(echoed.Devices, expectedDevices) {
			return fmt.Errorf("%w: verify response did not echo the ExpectedDevices the challenge named", ErrExpectedNotEnforced)
		}
		if result.Verdict != VerdictFail && result.Device != nil && result.Device.UEID != "" && !contains(expectedDevices, result.Device.UEID) {
			return fmt.Errorf("%w: verify response names a device outside ExpectedDevices", ErrExpectedNotEnforced)
		}
	}
	return nil
}

func sameSet(a, b []string) bool {
	seen := make(map[string]struct{}, len(a))
	for _, v := range a {
		seen[v] = struct{}{}
	}
	want := make(map[string]struct{}, len(b))
	for _, v := range b {
		want[v] = struct{}{}
	}
	if len(seen) != len(want) {
		return false
	}
	for v := range want {
		if _, ok := seen[v]; !ok {
			return false
		}
	}
	return true
}

func contains(list []string, v string) bool {
	for _, item := range list {
		if item == v {
			return true
		}
	}
	return false
}

// decodeInto re-decodes one object of the generic verdict map into a typed
// view. nil when the object is absent or does not decode; the raw verdict map
// remains available on AttestResult.Raw regardless.
func decodeInto[T any](value any) *T {
	if value == nil {
		return nil
	}
	b, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	var out T
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return &out
}

// IssueKeyChallenge mints a single-use key challenge for a purpose via
// POST {baseURL}/api/v1/keys/challenge. Relay the returned KeyChallenge string
// to the client verbatim; its MintKey answers with a certification, which the
// server submits with CertifyKey using Nonce.
//
// Refused with 422 key_disclosure_too_low when the API key's disclosure
// ceiling is below pseudonymous: a key whose id could never be returned is
// never minted.
func (c *Client) IssueKeyChallenge(ctx context.Context, opts KeyChallengeOptions) (KeyChallenge, error) {
	if opts.Purpose != KeyPurposeSign && opts.Purpose != KeyPurposeDecrypt {
		return KeyChallenge{}, fmt.Errorf("%w: IssueKeyChallenge requires Purpose to be sign or decrypt", ErrInvalidArgument)
	}
	body := map[string]any{"purpose": opts.Purpose}
	if opts.ExpectedDevices != nil {
		if err := requireAliasList(opts.ExpectedDevices, "ExpectedDevices"); err != nil {
			return KeyChallenge{}, err
		}
		body["expectedDevices"] = opts.ExpectedDevices
	}
	var out KeyChallenge
	if err := c.post(ctx, "/api/v1/keys/challenge", body, &out); err != nil {
		return KeyChallenge{}, err
	}
	if out.Nonce == "" || out.KeyChallenge == "" || out.ExpiresAt == "" {
		return KeyChallenge{}, fmt.Errorf("%w: key challenge response missing nonce/keyChallenge/expiresAt", ErrAttestHTTP)
	}
	return out, nil
}

// CertifyKey relays the client's MintKey output under the key challenge's
// nonce via POST {baseURL}/api/v1/keys/certify and returns the key
// RootHerald registered: its KeyID, public JWK, Alg, and the DeviceID (alias)
// of the installation that certified it. Store KeyID and JWK against the
// alias; later signatures are checked locally with VerifyKeySignature.
//
// The certification is relayed verbatim, whichever platform shape it is; a
// body that is none of them is ErrInvalidArgument before any request. The key
// is the call's only output, so a malformed one is ErrAttestHTTP rather than
// returned half-parsed.
func (c *Client) CertifyKey(ctx context.Context, nonce string, certification Certification) (CertifiedKey, error) {
	if nonce == "" {
		return CertifiedKey{}, fmt.Errorf("%w: CertifyKey requires nonce (from IssueKeyChallenge)", ErrInvalidArgument)
	}
	if !isWellFormedCertification(certification) {
		return CertifiedKey{}, fmt.Errorf("%w: CertifyKey requires the client's certification: {publicArea, attest, signature} on a TPM, or the platform form from macOS / iOS", ErrInvalidArgument)
	}
	body := map[string]any{
		"nonce":         nonce,
		"certification": json.RawMessage(certification),
	}
	var raw map[string]any
	if err := c.post(ctx, "/api/v1/keys/certify", body, &raw); err != nil {
		return CertifiedKey{}, err
	}
	return requireCertifiedKey(raw)
}

// isWellFormedCertification checks only the outer shape: a TPM
// certification's three base64 strings, or a platform-tagged body from macOS
// or iOS.
func isWellFormedCertification(certification Certification) bool {
	var probe struct {
		Platform   *string `json:"platform"`
		PublicArea string  `json:"publicArea"`
		Attest     string  `json:"attest"`
		Signature  string  `json:"signature"`
	}
	if len(certification) == 0 || json.Unmarshal(certification, &probe) != nil {
		return false
	}
	if probe.Platform != nil {
		return *probe.Platform != ""
	}
	return probe.PublicArea != "" && probe.Attest != "" && probe.Signature != ""
}

// requireCertifiedKey reads a /keys/certify response. The JWK family must
// match Alg: an EC key signs ES256 or agrees ECDH-ES, an RSA key signs RS256
// or wraps RSA-OAEP-256. Anything else is refused rather than surfaced
// half-parsed: a caller that then called VerifyKeySignature with it would
// silently get false.
func requireCertifiedKey(raw map[string]any) (CertifiedKey, error) {
	refuse := func(why string) (CertifiedKey, error) {
		return CertifiedKey{}, fmt.Errorf("%w: certify response %s", ErrAttestHTTP, why)
	}
	var wire struct {
		DeviceID      string          `json:"deviceId"`
		KeyID         string          `json:"keyId"`
		Purpose       KeyPurpose      `json:"purpose"`
		Alg           string          `json:"alg"`
		Format        string          `json:"format"`
		JWK           JWK             `json:"jwk"`
		HardwareBound *bool           `json:"hardwareBound"`
		CertifiedAt   json.RawMessage `json:"certifiedAt"`
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return refuse("is not an object")
	}
	if err := json.Unmarshal(b, &wire); err != nil {
		return refuse("is malformed: " + err.Error())
	}
	if wire.DeviceID == "" {
		return refuse("missing deviceId")
	}
	if wire.KeyID == "" {
		return refuse("missing keyId")
	}
	if wire.Purpose != KeyPurposeSign && wire.Purpose != KeyPurposeDecrypt {
		return refuse("purpose is not sign/decrypt")
	}
	if wire.HardwareBound == nil {
		return refuse("missing hardwareBound")
	}
	var certifiedAt time.Time
	if len(wire.CertifiedAt) == 0 || json.Unmarshal(wire.CertifiedAt, &certifiedAt) != nil {
		return refuse("certifiedAt is not a timestamp")
	}
	jwk, ok := readJWK(wire.JWK)
	if !ok {
		return refuse("jwk is not an EC P-256 or RSA public key")
	}
	if !algFits(jwk.Kty, wire.Alg) {
		return refuse(fmt.Sprintf("alg %q does not fit a %s key", wire.Alg, jwk.Kty))
	}
	if wire.Format != "" && wire.Format != "jwe" && wire.Format != "apple-ecies" {
		return refuse("format is not jwe/apple-ecies")
	}
	return CertifiedKey{
		DeviceID:      wire.DeviceID,
		KeyID:         wire.KeyID,
		Purpose:       wire.Purpose,
		Alg:           wire.Alg,
		Format:        wire.Format,
		JWK:           jwk,
		HardwareBound: *wire.HardwareBound,
		CertifiedAt:   certifiedAt,
	}, nil
}

// readJWK keeps only the fields of the family the key belongs to.
func readJWK(in JWK) (JWK, bool) {
	switch {
	case in.Kty == "EC" && in.Crv == "P-256" && in.X != "" && in.Y != "":
		return JWK{Kty: "EC", Crv: "P-256", X: in.X, Y: in.Y}, true
	case in.Kty == "RSA" && in.N != "" && in.E != "":
		return JWK{Kty: "RSA", N: in.N, E: in.E}, true
	}
	return JWK{}, false
}

func algFits(kty, alg string) bool {
	switch kty {
	case "EC":
		return alg == "ES256" || alg == "ECDH-ES"
	case "RSA":
		return alg == "RS256" || alg == "RSA-OAEP-256"
	}
	return false
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
// sentinel, mirroring the @rootherald/node status mapping. Where one status
// carries two refusals the body's error code (or a header) tells them apart; a
// code no sentinel covers stays ErrAttestHTTP with the code preserved.
func toAPIError(resp *http.Response) error {
	rawBody, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Error             string  `json:"error"`
		Message           string  `json:"message"`
		ErrorDescription  string  `json:"error_description"`
		RetryAfterSeconds int     `json:"retryAfterSeconds"`
		Budget            *Budget `json:"budget"`
	}
	_ = json.Unmarshal(rawBody, &parsed)
	msg := parsed.Message
	if msg == "" {
		msg = parsed.ErrorDescription
	}

	sentinel := ErrAttestHTTP
	retryAfter := 0
	var budget *Budget
	switch resp.StatusCode {
	case http.StatusUnauthorized: // 401
		if parsed.Error == codeActivationRefused {
			sentinel = ErrActivationRefused
		} else {
			sentinel = ErrInvalidSecretKey
		}
	case http.StatusUnprocessableEntity: // 422
		switch parsed.Error {
		case codeAdmissionRefused:
			sentinel = ErrAdmissionRefused
		case codeUnknownPolicy, "":
			sentinel = ErrUnknownPolicy
		}
	case http.StatusConflict: // 409
		if parsed.Error != codeKeyRotationConflict {
			sentinel = ErrChallenge
		}
	case http.StatusBadRequest: // 400
		if parsed.Error == codeInvalidAsk {
			sentinel = ErrInvalidAsk
		} else {
			sentinel = ErrInvalidEvidence
		}
	case http.StatusTooManyRequests: // 429
		if parsed.Error == codeBudgetExhausted || resp.Header.Get(quotaHeader) != "" {
			sentinel = ErrQuotaExceeded
			if parsed.Budget != nil && parsed.Budget.ID != "" && parsed.Budget.Name != "" {
				budget = parsed.Budget
			}
		} else {
			sentinel = ErrRateLimited
			retryAfter = parsed.RetryAfterSeconds
			if secs, err := strconv.Atoi(strings.TrimSpace(resp.Header.Get("Retry-After"))); err == nil {
				retryAfter = secs
			}
		}
	}
	if sentinel == ErrAttestHTTP && msg == "" {
		msg = strings.TrimSpace(string(rawBody))
	}
	return &APIError{
		StatusCode:        resp.StatusCode,
		Code:              parsed.Error,
		Message:           msg,
		RetryAfterSeconds: retryAfter,
		Budget:            budget,
		sentinel:          sentinel,
	}
}
