package rootherald

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClient_VerifyOffline(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	c := NewClient("http://unused", WithIssuer("https://issuer.example"),
		WithAudience("rp-1"), WithJwksURI(jwksURL))
	verdict, claims, err := c.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict != VerdictAllow {
		t.Errorf("verdict = %s", verdict)
	}
	if claims.Subject != "device-1" {
		t.Errorf("sub = %s", claims.Subject)
	}
}

// Client.Verify must return the token's actual verdict, not a hardcoded allow.
func TestClient_VerifyReturnsNonAllowVerdict(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	claims := sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute))
	claims["verdict"] = "fail"
	tok := m.sign(t, claims, "JWT")
	c := NewClient("http://unused", WithIssuer("https://issuer.example"),
		WithAudience("rp-1"), WithJwksURI(jwksURL))
	verdict, _, err := c.Verify(context.Background(), tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if verdict != VerdictDeny {
		t.Errorf("verdict = %s, want deny", verdict)
	}
}

func TestClient_VerifyOfflineRejectsExpired(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "x",
		time.Now().Add(-time.Minute)), "JWT")
	c := NewClient("http://unused", WithIssuer("https://issuer.example"),
		WithAudience("rp-1"), WithJwksURI(jwksURL))
	if _, _, err := c.Verify(context.Background(), tok); err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestClient_VerifyOnlineAllow(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	var receivedAuth string
	verifierServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedAuth = r.Header.Get("Authorization")
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"verdict":    "allow",
			"reason":     "ok",
			"risk_score": 0.07,
		})
		_ = body
	}))
	defer verifierServer.Close()

	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	c := NewClient(verifierServer.URL,
		WithIssuer("https://issuer.example"), WithAudience("rp-1"),
		WithJwksURI(jwksURL), WithAPIKey("secret-key"))
	res, err := c.VerifyOnline(context.Background(), tok, "signup")
	if err != nil {
		t.Fatalf("VerifyOnline: %v", err)
	}
	if res.Verdict != VerdictAllow {
		t.Errorf("verdict = %s", res.Verdict)
	}
	if res.Claims.Subject != "device-1" {
		t.Errorf("claims.sub = %s", res.Claims.Subject)
	}
	if !strings.HasPrefix(receivedAuth, "Bearer ") {
		t.Errorf("auth header = %q", receivedAuth)
	}
}

func TestClient_VerifyOnlineDeny(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	verifierServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"verdict": "deny", "reason": "policy",
		})
	}))
	defer verifierServer.Close()

	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	c := NewClient(verifierServer.URL,
		WithIssuer("https://issuer.example"), WithAudience("rp-1"),
		WithJwksURI(jwksURL))
	res, err := c.VerifyOnline(context.Background(), tok, "signup")
	if err != nil {
		t.Fatalf("VerifyOnline: %v", err)
	}
	if res.Verdict != VerdictDeny {
		t.Errorf("verdict = %s", res.Verdict)
	}
}

func TestClient_VerifyOnlineHttp401(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	verifierServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusUnauthorized)
	}))
	defer verifierServer.Close()
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	c := NewClient(verifierServer.URL, WithIssuer("https://issuer.example"),
		WithAudience("rp-1"), WithJwksURI(jwksURL))
	res, err := c.VerifyOnline(context.Background(), tok, "signup")
	if err != nil {
		t.Fatalf("VerifyOnline: %v", err)
	}
	if res.Verdict != VerdictDeny {
		t.Errorf("verdict = %s", res.Verdict)
	}
}

func TestClient_VerifyOnlineMalformedResponse(t *testing.T) {
	m := newMockSigner(t, "k1")
	jwksURL, _, _ := startJwks(t, m, "")
	verifierServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("not-json"))
	}))
	defer verifierServer.Close()
	tok := m.sign(t, sampleClaims("https://issuer.example", "rp-1", "device-1",
		time.Now().Add(time.Minute)), "JWT")
	c := NewClient(verifierServer.URL, WithIssuer("https://issuer.example"),
		WithAudience("rp-1"), WithJwksURI(jwksURL))
	if _, err := c.VerifyOnline(context.Background(), tok, "signup"); err == nil {
		t.Fatal("expected error for malformed JSON")
	}
}
