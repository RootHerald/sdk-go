package rootherald

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultBaseURL is the production RootHerald API base URL used by AttestClient
// when no base URL is supplied.
const DefaultBaseURL = "https://api.rootherald.com"

// secretKeyPrefix marks a RootHerald secret key. Publishable keys (rh_pk_) must
// never be used server-side and are rejected by NewAttestClient.
const secretKeyPrefix = "rh_sk_"

// Background-Check sentinel errors. Use errors.Is to switch on them. They mirror
// the HTTP status mapping of the @rootherald/node SDK:
//
//	401 -> ErrInvalidSecretKey   (bad/absent secret key)
//	422 -> ErrUnknownPolicy      (unknown/foreign policy name)
//	409 -> ErrChallenge          (challenge unknown/expired/already used)
//	400 -> ErrInvalidEvidence    (evidence malformed/unparseable)
//	429 -> ErrQuotaExceeded      (rate/quota limit hit)
//
// An un-enrolled or failing device is NOT an error: Attest returns a normal
// verdict carrying VerdictDeny/VerdictReview. Only protocol/auth/quota problems
// surface as one of these errors.
var (
	ErrInvalidSecretKey = errors.New("rootherald: invalid secret key")
	ErrUnknownPolicy    = errors.New("rootherald: unknown policy")
	ErrChallenge        = errors.New("rootherald: challenge invalid or expired")
	ErrInvalidEvidence  = errors.New("rootherald: invalid evidence")
	ErrQuotaExceeded    = errors.New("rootherald: quota exceeded")
	ErrAttestHTTP       = errors.New("rootherald: attestation http error")
)

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

// Challenge is the relay-friendly nonce minted by CreateChallenge. Relay Nonce
// to the dumb client; the client quotes over it and returns an opaque evidence
// blob, which the server submits with Attest using ChallengeID.
type Challenge struct {
	ChallengeID string `json:"challengeId"`
	Nonce       string `json:"nonce"`
	ExpiresAt   string `json:"expiresAt"`
}

// Evidence is the opaque, client-collected attestation blob. The SDK passes it
// through verbatim — it is never interpreted client-side.
type Evidence = json.RawMessage

// AttestOptions configures a single Attest call.
type AttestOptions struct {
	// ChallengeID is the single-use challenge id from CreateChallenge. Required.
	ChallengeID string
	// Policy is a caller-named policy: a tenant-owned policy id/name or a
	// "rootherald:builtin:*" name. Unknown/foreign names fail closed (422).
	Policy string
	// ReturnToken opts in to a signed EAT (JWT) in the response, itself
	// verifiable offline with Verifier/Client.Verify.
	ReturnToken bool
}

// AttestResult is the verdict returned by Attest plus, when requested, the
// signed EAT token. Verdict is mapped to the SDK enum from the raw
// "pass"/"fail"/"warn" the server emits.
type AttestResult struct {
	Verdict Verdict
	Token   string // present only when AttestOptions.ReturnToken was true
	// Raw is the full decoded verdict object as returned by the server, for
	// callers that need fields the typed surface does not expose yet.
	Raw map[string]any
}

// AttestClient is the server -> server Background-Check client. The customer's
// dumb client collects an opaque evidence blob (no keys, no RootHerald contact)
// and hands it to the customer's own server; the server uses this client,
// authenticated with its rh_sk_ secret key, to mint a nonce (CreateChallenge)
// and submit the evidence for appraisal (Attest).
//
// This is ADDITIVE to the offline/badge-tier path: Client.Verify and the
// chi/gin middleware are unchanged, and the optional token from
// Attest(..., ReturnToken: true) is verifiable with them.
//
// Construct with NewAttestClient; instances are safe for concurrent use.
type AttestClient struct {
	secretKey string
	baseURL   string
	http      *http.Client
}

// AttestClientOption customises an AttestClient.
type AttestClientOption func(*AttestClient)

// WithBaseURL overrides the default production base URL.
func WithBaseURL(baseURL string) AttestClientOption {
	return func(c *AttestClient) { c.baseURL = strings.TrimRight(baseURL, "/") }
}

// WithHTTPClient swaps the underlying *http.Client (timeouts, proxies, tests).
func WithHTTPClient(h *http.Client) AttestClientOption {
	return func(c *AttestClient) { c.http = h }
}

// NewAttestClient builds a Background-Check client. secretKey is required and
// must be a secret key (rh_sk_…); a publishable key (rh_pk_…) is rejected
// because it must never be used server-side.
func NewAttestClient(secretKey string, opts ...AttestClientOption) (*AttestClient, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("%w: a secret key (rh_sk_…) is required", ErrInvalidSecretKey)
	}
	if !strings.HasPrefix(secretKey, secretKeyPrefix) {
		return nil, fmt.Errorf("%w: must be a secret key (rh_sk_…); a publishable key (rh_pk_…) must never be used server-side", ErrInvalidSecretKey)
	}
	c := &AttestClient{
		secretKey: secretKey,
		baseURL:   DefaultBaseURL,
		http:      &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

// CreateChallenge mints a relay-friendly nonce via
// POST {baseURL}/api/v1/attestations/challenge. deviceHint is optional and may
// be "" to omit it. Relay the returned Nonce to the client; the client quotes
// over it, then submit the resulting evidence with Attest using ChallengeID.
func (c *AttestClient) CreateChallenge(ctx context.Context, deviceHint string) (Challenge, error) {
	body := map[string]string{}
	if deviceHint != "" {
		body["deviceHint"] = deviceHint
	}
	var out Challenge
	if err := c.post(ctx, "/api/v1/attestations/challenge", body, &out); err != nil {
		return Challenge{}, err
	}
	if out.ChallengeID == "" || out.Nonce == "" || out.ExpiresAt == "" {
		return Challenge{}, fmt.Errorf("%w: challenge response missing challengeId/nonce/expiresAt", ErrAttestHTTP)
	}
	return out, nil
}

// verifyResponseBody is the wire shape of the verify endpoint.
type verifyResponseBody struct {
	Verdict map[string]any `json:"verdict"`
	Token   string         `json:"token,omitempty"`
}

// Attest submits the opaque evidence blob for server-side appraisal via
// POST {baseURL}/api/v1/attestations/verify and returns the verdict (plus an
// optional signed EAT when opts.ReturnToken is true).
//
// An un-enrolled / failing device is NOT an error — it returns a normal verdict
// carrying VerdictDeny/VerdictReview. Only protocol/auth/quota problems return
// a non-nil error (see the package sentinels). evidence is passed through
// verbatim.
func (c *AttestClient) Attest(ctx context.Context, evidence Evidence, opts AttestOptions) (AttestResult, error) {
	if opts.ChallengeID == "" {
		return AttestResult{}, fmt.Errorf("%w: Attest requires ChallengeID (from CreateChallenge)", ErrChallenge)
	}
	body := map[string]any{
		"challengeId": opts.ChallengeID,
		"evidence":    json.RawMessage(evidence),
	}
	if opts.Policy != "" {
		body["policy"] = opts.Policy
	}
	if opts.ReturnToken {
		body["returnToken"] = true
	}

	var resp verifyResponseBody
	if err := c.post(ctx, "/api/v1/attestations/verify", body, &resp); err != nil {
		return AttestResult{}, err
	}
	if resp.Verdict == nil {
		return AttestResult{}, fmt.Errorf("%w: verify response missing verdict", ErrAttestHTTP)
	}
	raw, _ := resp.Verdict["verdict"].(string)
	return AttestResult{
		Verdict: mapVerdict(raw),
		Token:   resp.Token,
		Raw:     resp.Verdict,
	}, nil
}

// post issues an authenticated JSON POST and decodes the 2xx body into out,
// mapping non-2xx responses to the matching typed error.
func (c *AttestClient) post(ctx context.Context, path string, body any, out any) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("%w: marshal request: %v", ErrAttestHTTP, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(raw))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestHTTP, err)
	}
	req.Header.Set("Authorization", "Bearer "+c.secretKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAttestHTTP, err)
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
		sentinel = ErrUnknownPolicy
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
