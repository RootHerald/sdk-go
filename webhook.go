package rootherald

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// WebhookEvent is a decoded CAEP Security Event Token (RFC 8417).
type WebhookEvent struct {
	JTI      string                            `json:"jti"`
	Issuer   string                            `json:"iss"`
	Audience []string                          `json:"aud"`
	IssuedAt time.Time                         `json:"iat"`
	Subject  string                            `json:"sub,omitempty"`
	Events   map[string]map[string]interface{} `json:"events"`
}

// WebhookVerifier verifies SETs delivered by the RootHerald CAEP webhook.
//
// The signing keys are sourced from the verifier's JWKS — typically the same
// JWKS used for attestation tokens but a Verifier with a different issuer can
// be supplied if your deployment splits them.
type WebhookVerifier struct {
	issuer    string
	audience  string
	jwks      *jwksCache
	algs      map[string]struct{}
	expectTyp string
}

// NewWebhookVerifier constructs a verifier bound to a specific issuer/audience
// and JWKS endpoint.
func NewWebhookVerifier(issuer, audience, jwksURI string) *WebhookVerifier {
	return &WebhookVerifier{
		issuer:    issuer,
		audience:  audience,
		jwks:      newJwksCache(jwksURI),
		expectTyp: "secevent+jwt",
		algs: map[string]struct{}{
			"RS256": {}, "ES256": {}, "PS256": {},
		},
	}
}

// Verify checks signature and claim shape of a SET, returning a decoded event.
func (w *WebhookVerifier) Verify(setJwt string) (WebhookEvent, error) {
	if setJwt == "" {
		return WebhookEvent{}, fmt.Errorf("%w: empty SET", ErrWebhookSig)
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(setJwt, func(t *jwt.Token) (interface{}, error) {
		alg, _ := t.Header["alg"].(string)
		if _, ok := w.algs[alg]; !ok {
			return nil, fmt.Errorf("%w: alg %s", ErrWebhookSig, alg)
		}
		typ, _ := t.Header["typ"].(string)
		if typ != w.expectTyp {
			return nil, fmt.Errorf("%w: typ %q != %q", ErrWebhookSig, typ, w.expectTyp)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrWebhookSig)
		}
		return w.jwks.key(kid)
	})
	if err != nil {
		if errors.Is(err, ErrWebhookSig) {
			return WebhookEvent{}, err
		}
		return WebhookEvent{}, fmt.Errorf("%w: %v", ErrWebhookSig, err)
	}
	if !parsed.Valid {
		return WebhookEvent{}, ErrWebhookSig
	}
	raw, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return WebhookEvent{}, fmt.Errorf("%w: unexpected claims type", ErrWebhookSig)
	}
	if iss, _ := raw["iss"].(string); iss != w.issuer {
		return WebhookEvent{}, fmt.Errorf("%w: issuer mismatch", ErrWebhookSig)
	}
	if w.audience != "" && !audienceMatches(raw["aud"], w.audience) {
		return WebhookEvent{}, fmt.Errorf("%w: audience mismatch", ErrWebhookSig)
	}
	events, ok := raw["events"].(map[string]interface{})
	if !ok || len(events) == 0 {
		return WebhookEvent{}, fmt.Errorf("%w: missing or empty events", ErrWebhookSig)
	}

	out := WebhookEvent{
		Events: make(map[string]map[string]interface{}, len(events)),
	}
	out.JTI, _ = raw["jti"].(string)
	out.Issuer, _ = raw["iss"].(string)
	switch a := raw["aud"].(type) {
	case string:
		out.Audience = []string{a}
	case []interface{}:
		for _, v := range a {
			if s, ok := v.(string); ok {
				out.Audience = append(out.Audience, s)
			}
		}
	}
	if t, ok := readUnix(raw, "iat"); ok {
		out.IssuedAt = t
	}
	out.Subject, _ = raw["sub"].(string)
	for k, v := range events {
		if m, ok := v.(map[string]interface{}); ok {
			out.Events[k] = m
		} else {
			// preserve under a synthetic key if unparseable
			b, _ := json.Marshal(v)
			out.Events[k] = map[string]interface{}{"_raw": string(b)}
		}
	}
	return out, nil
}
