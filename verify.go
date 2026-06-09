package rootherald

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verifier validates attestation tokens against a remote JWKS.
//
// Construct one with NewVerifier; instances are safe for concurrent use.
type Verifier struct {
	issuer     string
	audience   string
	jwks       *jwksCache
	clockSkew  time.Duration
	acceptAlgs map[string]struct{}
	now        func() time.Time
}

// VerifierOption customises a Verifier.
type VerifierOption func(*Verifier)

// WithClockSkew overrides the default 60s skew tolerance for exp/nbf checks.
func WithClockSkew(d time.Duration) VerifierOption {
	return func(v *Verifier) { v.clockSkew = d }
}

// WithAcceptedAlgorithms overrides the accepted JWS algorithm set
// (default: RS256, ES256, PS256).
func WithAcceptedAlgorithms(algs ...string) VerifierOption {
	return func(v *Verifier) {
		v.acceptAlgs = make(map[string]struct{}, len(algs))
		for _, a := range algs {
			v.acceptAlgs[a] = struct{}{}
		}
	}
}

// WithClock injects a custom time source (used by tests).
func WithClock(now func() time.Time) VerifierOption {
	return func(v *Verifier) { v.now = now }
}

// WithHTTPClient swaps the JWKS HTTP client (used by tests and proxies).
func WithHTTPClient(h *http.Client) VerifierOption {
	return func(v *Verifier) { v.jwks.http = h }
}

// NewVerifier constructs a verifier bound to a single issuer / JWKS endpoint.
func NewVerifier(issuer, audience, jwksURI string, opts ...VerifierOption) *Verifier {
	v := &Verifier{
		issuer:    issuer,
		audience:  audience,
		jwks:      newJwksCache(jwksURI),
		clockSkew: 60 * time.Second,
		acceptAlgs: map[string]struct{}{
			"RS256": {}, "ES256": {}, "PS256": {},
		},
		now: time.Now,
	}
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify parses, signature-checks and claim-checks the supplied JWT.
func (v *Verifier) Verify(token string) (AttestationClaims, error) {
	if token == "" {
		return AttestationClaims{}, fmt.Errorf("%w: empty token", ErrSignature)
	}
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	parsed, err := parser.Parse(token, func(t *jwt.Token) (interface{}, error) {
		alg, _ := t.Header["alg"].(string)
		if _, ok := v.acceptAlgs[alg]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnsupportedAlg, alg)
		}
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrSignature)
		}
		return v.jwks.key(kid)
	})
	if err != nil {
		// Distinguish signature failure from unknown-kid / network failure when possible
		if errors.Is(err, ErrUnknownKID) || errors.Is(err, ErrUnsupportedAlg) ||
			errors.Is(err, ErrJwksUnavailable) {
			return AttestationClaims{}, err
		}
		return AttestationClaims{}, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if !parsed.Valid {
		return AttestationClaims{}, ErrSignature
	}

	raw, ok := parsed.Claims.(jwt.MapClaims)
	if !ok {
		return AttestationClaims{}, fmt.Errorf("%w: unexpected claims type", ErrSignature)
	}

	now := v.now()
	exp, ok := readUnix(raw, "exp")
	if !ok {
		return AttestationClaims{}, fmt.Errorf("%w: missing exp", ErrSignature)
	}
	if exp.Add(v.clockSkew).Before(now) {
		return AttestationClaims{}, ErrTokenExpired
	}
	if nbf, ok := readUnix(raw, "nbf"); ok && nbf.Add(-v.clockSkew).After(now) {
		return AttestationClaims{}, fmt.Errorf("%w: token not yet valid", ErrSignature)
	}
	iss, _ := raw["iss"].(string)
	if iss != v.issuer {
		return AttestationClaims{}, fmt.Errorf("%w: got %q want %q", ErrIssuerMismatch, iss, v.issuer)
	}
	if v.audience != "" && !audienceMatches(raw["aud"], v.audience) {
		return AttestationClaims{}, ErrAudienceMismatch
	}

	return claimsFromMap(raw), nil
}

func audienceMatches(aud interface{}, want string) bool {
	switch a := aud.(type) {
	case string:
		return a == want
	case []interface{}:
		for _, v := range a {
			if s, _ := v.(string); s == want {
				return true
			}
		}
	}
	return false
}

// audienceStrings normalises a JWT "aud" claim (string or []interface{}) to a
// slice of strings, dropping non-string entries. Returns nil for other shapes.
func audienceStrings(aud interface{}) []string {
	switch a := aud.(type) {
	case string:
		return []string{a}
	case []interface{}:
		var out []string
		for _, v := range a {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func readUnix(c jwt.MapClaims, key string) (time.Time, bool) {
	switch v := c[key].(type) {
	case float64:
		return time.Unix(int64(v), 0).UTC(), true
	case int64:
		return time.Unix(v, 0).UTC(), true
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return time.Time{}, false
		}
		return time.Unix(i, 0).UTC(), true
	}
	return time.Time{}, false
}

func claimsFromMap(raw jwt.MapClaims) AttestationClaims {
	c := AttestationClaims{Raw: map[string]interface{}(raw)}
	if s, ok := raw["sub"].(string); ok {
		c.Subject = s
	}
	if s, ok := raw["iss"].(string); ok {
		c.Issuer = s
	}
	c.Audience = audienceStrings(raw["aud"])
	if t, ok := readUnix(raw, "exp"); ok {
		c.ExpiresAt = t
	}
	if t, ok := readUnix(raw, "iat"); ok {
		c.IssuedAt = t
	}
	if t, ok := readUnix(raw, "nbf"); ok {
		c.NotBefore = t
	}
	if s, ok := raw["eat_nonce"].(string); ok {
		c.Nonce = s
	}
	if s, ok := raw["eat_profile"].(string); ok {
		c.EATProfile = s
	}
	c.Device.UEID, _ = raw["ueid"].(string)
	c.Device.HWModel, _ = raw["hwmodel"].(string)
	c.Device.Dbgstat, _ = raw["dbgstat"].(string)
	switch e := raw["ear.status"].(type) {
	case float64:
		c.Device.EARState = int(e)
	case string:
		if i, err := strconv.Atoi(e); err == nil {
			c.Device.EARState = i
		}
	}
	return c
}

// ---------------------------------------------------------------------------
// JWKS cache
// ---------------------------------------------------------------------------

type jwksCache struct {
	url   string
	http  *http.Client
	mu    sync.RWMutex
	keys  map[string]interface{} // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	until time.Time
}

func newJwksCache(url string) *jwksCache {
	return &jwksCache{
		url:  url,
		http: &http.Client{Timeout: 10 * time.Second},
		keys: map[string]interface{}{},
	}
}

func (c *jwksCache) key(kid string) (interface{}, error) {
	c.mu.RLock()
	if time.Now().Before(c.until) {
		if k, ok := c.keys[kid]; ok {
			c.mu.RUnlock()
			return k, nil
		}
	}
	c.mu.RUnlock()
	if err := c.refresh(); err != nil {
		return nil, err
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	if k, ok := c.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownKID, kid)
}

func (c *jwksCache) refresh() error {
	req, err := http.NewRequest(http.MethodGet, c.url, nil)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJwksUnavailable, err)
	}
	req.Header.Set("Accept", "application/jwk-set+json")
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJwksUnavailable, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("%w: http %d", ErrJwksUnavailable, resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrJwksUnavailable, err)
	}
	var doc struct {
		Keys []jwksKeyRaw `json:"keys"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return fmt.Errorf("%w: malformed jwks: %v", ErrJwksUnavailable, err)
	}
	ttl := parseMaxAge(resp.Header.Get("Cache-Control"))
	keys := map[string]interface{}{}
	for _, raw := range doc.Keys {
		k, err := raw.toPublicKey()
		if err != nil {
			continue // skip unsupported entries
		}
		keys[raw.Kid] = k
	}
	c.mu.Lock()
	c.keys = keys
	c.until = time.Now().Add(ttl)
	c.mu.Unlock()
	return nil
}

type jwksKeyRaw struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	N   string `json:"n"`
	E   string `json:"e"`
	X   string `json:"x"`
	Y   string `json:"y"`
	Crv string `json:"crv"`
}

func (r jwksKeyRaw) toPublicKey() (interface{}, error) {
	switch r.Kty {
	case "RSA":
		n, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.N, "="))
		if err != nil {
			return nil, err
		}
		e, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.E, "="))
		if err != nil {
			return nil, err
		}
		return &rsa.PublicKey{
			N: new(big.Int).SetBytes(n),
			E: int(new(big.Int).SetBytes(e).Int64()),
		}, nil
	case "EC":
		x, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.X, "="))
		if err != nil {
			return nil, err
		}
		y, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(r.Y, "="))
		if err != nil {
			return nil, err
		}
		var pub ecdsa.PublicKey
		pub.X = new(big.Int).SetBytes(x)
		pub.Y = new(big.Int).SetBytes(y)
		// Curve resolution is left to the JWT library when verifying.
		return &pub, nil
	}
	return nil, fmt.Errorf("unsupported kty %q", r.Kty)
}

var maxAgeRe = regexp.MustCompile(`(?i)max-age\s*=\s*(\d+)`)

func parseMaxAge(h string) time.Duration {
	const defaultTTL = 15 * time.Minute
	if h == "" {
		return defaultTTL
	}
	m := maxAgeRe.FindStringSubmatch(h)
	if len(m) < 2 {
		return defaultTTL
	}
	n, err := strconv.Atoi(m[1])
	if err != nil || n < 0 {
		return defaultTTL
	}
	return time.Duration(n) * time.Second
}
