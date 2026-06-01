package rootherald

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setClaims(issuer, aud, jti, eventType string, payload map[string]interface{}) jwt.MapClaims {
	return jwt.MapClaims{
		"iss": issuer,
		"aud": aud,
		"jti": jti,
		"iat": time.Now().Unix(),
		"events": map[string]interface{}{
			eventType: payload,
		},
	}
}

func TestWebhook_ValidSet(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	set := m.sign(t, setClaims("https://issuer.example", "tenant-1", "e1",
		"https://schemas.openid.net/secevent/caep/event-type/session-revoked",
		map[string]interface{}{"subject_id": "device-1", "reason": "compromised"},
	), "secevent+jwt")
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	evt, err := w.Verify(set)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if evt.JTI != "e1" {
		t.Errorf("jti = %s", evt.JTI)
	}
	if _, ok := evt.Events["https://schemas.openid.net/secevent/caep/event-type/session-revoked"]; !ok {
		t.Error("event type missing")
	}
}

func TestWebhook_Tampered(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	set := m.sign(t, setClaims("https://issuer.example", "tenant-1", "e1", "x", map[string]interface{}{}),
		"secevent+jwt")
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	_, err := w.Verify(set[:len(set)-4] + "ZZZZ")
	if err == nil {
		t.Fatal("expected error for tampered SET")
	}
}

func TestWebhook_MissingSig(t *testing.T) {
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", "http://127.0.0.1:1")
	_, err := w.Verify("eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJ4In0.")
	if err == nil {
		t.Fatal("expected error for missing signature")
	}
}

func TestWebhook_WrongTyp(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	set := m.sign(t, setClaims("https://issuer.example", "tenant-1", "e1", "x", map[string]interface{}{}),
		"JWT") // wrong typ
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	if _, err := w.Verify(set); err == nil {
		t.Fatal("expected error for wrong typ")
	}
}

func TestWebhook_WrongIssuer(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	set := m.sign(t, setClaims("https://other.example", "tenant-1", "e1", "x", map[string]interface{}{}),
		"secevent+jwt")
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	if _, err := w.Verify(set); err == nil {
		t.Fatal("expected issuer mismatch")
	}
}

func TestWebhook_WrongAlg(t *testing.T) {
	jwksURL, _, _ := startJwks(t, newMockSigner(t, "k1"), "")
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, setClaims("https://issuer.example", "tenant-1", "e1", "x", map[string]interface{}{}))
	tok.Header["kid"] = "k1"
	tok.Header["typ"] = "secevent+jwt"
	s, _ := tok.SignedString([]byte("secret"))
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	if _, err := w.Verify(s); err == nil {
		t.Fatal("expected error for HS256")
	}
}

func TestWebhook_EmptyEvents(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"iss": "https://issuer.example",
		"aud": "tenant-1",
		"jti": "e1",
		"iat": time.Now().Unix(),
	})
	tok.Header["kid"] = "k1"
	tok.Header["typ"] = "secevent+jwt"
	s, _ := tok.SignedString(m.key)
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	_, err := w.Verify(s)
	if !errors.Is(err, ErrWebhookSig) {
		t.Fatalf("expected ErrWebhookSig, got %v", err)
	}
}

func TestWebhook_AudienceMismatch(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	set := m.sign(t, setClaims("https://issuer.example", "wrong-tenant", "e1", "x",
		map[string]interface{}{"k": "v"}), "secevent+jwt")
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", jwksURL)
	if _, err := w.Verify(set); err == nil {
		t.Fatal("expected audience mismatch")
	}
}

func TestWebhook_EmptyToken(t *testing.T) {
	w := NewWebhookVerifier("https://issuer.example", "tenant-1", "http://127.0.0.1:1")
	if _, err := w.Verify(""); err == nil {
		t.Fatal("expected error for empty SET")
	}
}
