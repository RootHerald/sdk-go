package rootherald

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client is a high-level REST + verification wrapper around a RootHerald deployment.
//
// Construct with NewClient; instances are safe for concurrent use.
type Client struct {
	baseURL  string
	issuer   string
	audience string
	apiKey   string
	verifier *Verifier
	http     *http.Client
}

// ClientOption customises a Client.
type ClientOption func(*Client)

// WithIssuer sets the JWT issuer to verify against.
func WithIssuer(issuer string) ClientOption {
	return func(c *Client) { c.issuer = issuer }
}

// WithAudience sets the expected JWT audience.
func WithAudience(aud string) ClientOption {
	return func(c *Client) { c.audience = aud }
}

// WithAPIKey provides a bearer token for online verification calls.
func WithAPIKey(key string) ClientOption {
	return func(c *Client) { c.apiKey = key }
}

// WithClientHTTPClient swaps the underlying HTTP client (timeouts, proxies, tests).
func WithClientHTTPClient(h *http.Client) ClientOption {
	return func(c *Client) { c.http = h }
}

// WithJwksURI overrides the default {base}/.well-known/jwks.json location.
func WithJwksURI(uri string) ClientOption {
	return func(c *Client) {
		c.baseURL = strings.TrimRight(c.baseURL, "/")
		c.verifier = NewVerifier(c.issuer, c.audience, uri)
	}
}

// NewClient builds a Client. Issuer is required (via WithIssuer).
func NewClient(baseURL string, opts ...ClientOption) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	if c.verifier == nil {
		c.verifier = NewVerifier(c.issuer, c.audience, c.baseURL+"/.well-known/jwks.json")
	}
	return c
}

// Verify checks the token locally using the cached JWKS. On success it returns
// the verdict carried by the token (mapped from the platform's "verdict" claim:
// "pass" -> VerdictAllow, "fail" -> VerdictDeny, "warn" -> VerdictReview;
// missing/unknown -> VerdictReview). A signature/expiry/issuer/audience failure
// returns VerdictDeny plus an error. Note: a structurally valid token can still
// carry a non-allow verdict, so callers MUST check the returned Verdict, not
// just the error.
func (c *Client) Verify(ctx context.Context, token string) (Verdict, AttestationClaims, error) {
	claims, err := c.verifier.Verify(token)
	if err != nil {
		return VerdictDeny, AttestationClaims{}, err
	}
	return claims.Verdict, claims, nil
}

// VerifyOnline POSTs the token to a {base}/api/v1/verify endpoint and returns
// its verdict and risk score.
//
// DEPRECATED / NOT-YET-AVAILABLE: this targets a self-hosted {verdict, reason,
// risk_score} service and does not exist on the stock RootHerald deployment.
// For the server -> server appraisal path use AttestClient (NewAttestClient +
// CreateChallenge/Attest); for offline badge-tier checks use Verify. This
// method is retained only for callers fronting their own such service.
func (c *Client) VerifyOnline(ctx context.Context, token, action string) (VerifyResult, error) {
	body, err := json.Marshal(map[string]string{
		"token":  token,
		"action": action,
	})
	if err != nil {
		return VerifyResult{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.baseURL+"/api/v1/verify", bytes.NewReader(body))
	if err != nil {
		return VerifyResult{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return VerifyResult{}, fmt.Errorf("%w: %v", ErrVerifierHTTP, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == 401 || resp.StatusCode == 403 {
		return VerifyResult{Verdict: VerdictDeny, Reason: fmt.Sprintf("http-%d", resp.StatusCode)}, nil
	}
	if resp.StatusCode/100 != 2 {
		raw, _ := io.ReadAll(resp.Body)
		return VerifyResult{}, fmt.Errorf("%w: http %d: %s", ErrVerifierHTTP, resp.StatusCode, string(raw))
	}
	var out VerifyResult
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return VerifyResult{}, fmt.Errorf("%w: malformed response: %v", ErrVerifierHTTP, err)
	}
	if out.Verdict == "" {
		// Fail closed: a response with no verdict is not silently an allow.
		out.Verdict = VerdictReview
	}
	if out.Verdict != VerdictDeny {
		if c, err := c.verifier.Verify(token); err == nil {
			out.Claims = c
		}
	}
	return out, nil
}

// Verifier returns the embedded Verifier — useful for middleware that wants
// to verify on its own clock without re-doing the JWKS bookkeeping.
func (c *Client) Verifier() *Verifier {
	return c.verifier
}
