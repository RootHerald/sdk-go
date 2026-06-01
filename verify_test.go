package rootherald

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestVerifier_ValidToken(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(5*time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "device-1" {
		t.Errorf("sub = %q want device-1", c.Subject)
	}
	if c.Device.HWModel != "TestModel" {
		t.Errorf("hwmodel = %q", c.Device.HWModel)
	}
	if c.Device.EARState != 1 {
		t.Errorf("ear.status = %d", c.Device.EARState)
	}
}

func TestVerifier_RejectExpired(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(-5*time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expected ErrTokenExpired, got %v", err)
	}
}

func TestVerifier_WrongIssuer(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://other.example", "rp-1", "x", time.Now().Add(time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrIssuerMismatch) {
		t.Fatalf("expected ErrIssuerMismatch, got %v", err)
	}
}

func TestVerifier_WrongAudience(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-other", "x",
		time.Now().Add(time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrAudienceMismatch) {
		t.Fatalf("expected ErrAudienceMismatch, got %v", err)
	}
}

func TestVerifier_TamperedSignature(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	tampered := tok[:len(tok)-4] + "AAAA"
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tampered)
	if err == nil {
		t.Fatal("expected error for tampered signature")
	}
}

func TestVerifier_UnknownKid(t *testing.T) {
	known := newMockSigner(t, "k1")
	attacker := newMockSigner(t, "k2") // different key, different kid
	jwksURL, _, _ := startJwks(t, known, "")
	tok := attacker.sign(t, sampleClaims("https://issuer.example", "rp-1", "x",
		time.Now().Add(time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID, got %v", err)
	}
}

func TestVerifier_AcceptedAlgs(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	// Forge HS256 token with the same kid; verify should reject alg
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, sampleClaims(
		"https://issuer.example", "rp-1", "x", time.Now().Add(time.Minute)))
	tok.Header["kid"] = "k1"
	s, _ := tok.SignedString([]byte("super-secret"))
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(s)
	if !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg, got %v", err)
	}
}

func TestVerifier_MalformedToken(t *testing.T) {
	v := NewVerifier("https://issuer.example", "rp-1", "http://127.0.0.1:1/jwks")
	if _, err := v.Verify(""); err == nil {
		t.Fatal("expected error for empty token")
	}
	if _, err := v.Verify("not.a.jwt"); err == nil {
		t.Fatal("expected error for malformed token")
	}
}

func TestVerifier_JwksUnavailable(t *testing.T) {
	v := NewVerifier("https://issuer.example", "rp-1", "http://127.0.0.1:1/jwks")
	// Need a valid-shaped JWT or the parser short-circuits earlier
	m := newMockSigner(t, "k1")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "x",
		time.Now().Add(time.Minute)), "JWT")
	_, err := v.Verify(tok)
	if !errors.Is(err, ErrJwksUnavailable) {
		t.Fatalf("expected ErrJwksUnavailable, got %v", err)
	}
}

func TestVerifier_AcceptsAudienceArray(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	claims := sampleClaims("https://issuer.example", "", "device-1", time.Now().Add(time.Minute))
	claims["aud"] = []interface{}{"rp-a", "rp-1", "rp-b"}
	tok := m.sign(t, claims, "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("Verify with audience array: %v", err)
	}
}

func TestVerifier_NoAudienceConfigured(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "anything", "x",
		time.Now().Add(time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "", jwksURL)
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("expected pass with no audience configured: %v", err)
	}
}

func TestVerifier_JwksCachedViaCacheControl(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, hits, _ := startJwks(t, m, "max-age=3600")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "x",
		time.Now().Add(time.Minute)), "JWT")
	for i := 0; i < 3; i++ {
		if _, err := v.Verify(tok); err != nil {
			t.Fatalf("Verify iter %d: %v", i, err)
		}
	}
	if got := *hits; got != 1 {
		t.Errorf("jwks fetched %d times, want 1", got)
	}
}

func TestVerifier_ClockSkewAllowsNearExpiry(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "x",
		time.Now().Add(-10*time.Second)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL,
		WithClockSkew(30*time.Second))
	if _, err := v.Verify(tok); err != nil {
		t.Fatalf("clock skew should permit recent expiry: %v", err)
	}
}

func TestParseMaxAge(t *testing.T) {
	cases := map[string]time.Duration{
		"":                  15 * time.Minute,
		"no-cache":          15 * time.Minute,
		"max-age=60":        60 * time.Second,
		"public, max-age=30, must-revalidate": 30 * time.Second,
		"max-age=oops":      15 * time.Minute,
	}
	for in, want := range cases {
		if got := parseMaxAge(in); got != want {
			t.Errorf("parseMaxAge(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestAudienceMatchesScalarAndArray(t *testing.T) {
	if !audienceMatches("rp", "rp") {
		t.Error("scalar match")
	}
	if !audienceMatches([]interface{}{"a", "rp"}, "rp") {
		t.Error("array match")
	}
	if audienceMatches([]interface{}{"a", "b"}, "rp") {
		t.Error("array reject")
	}
	if audienceMatches(nil, "rp") {
		t.Error("nil reject")
	}
}

func TestVerifyErrorMessages(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://wrong.example", "rp-1", "x",
		time.Now().Add(time.Minute)), "JWT")
	v := NewVerifier("https://issuer.example", "rp-1", jwksURL)
	_, err := v.Verify(tok)
	if err == nil || !strings.Contains(err.Error(), "issuer mismatch") {
		t.Fatalf("expected issuer mismatch error, got %v", err)
	}
}
