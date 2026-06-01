package rootherald

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// mockSigner holds an RSA key and the kid it advertises.
type mockSigner struct {
	kid string
	key *rsa.PrivateKey
}

func newMockSigner(t *testing.T, kid string) *mockSigner {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	return &mockSigner{kid: kid, key: k}
}

// sign produces a compact JWT with the given claims, RS256/JWT header.
func (m *mockSigner) sign(t *testing.T, claims jwt.MapClaims, typ string) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = m.kid
	if typ != "" {
		token.Header["typ"] = typ
	}
	s, err := token.SignedString(m.key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// jwks returns a JWKS document serialising the public half.
func (m *mockSigner) jwks(cacheControl string) (handler http.HandlerFunc, hits *int32) {
	var counter int32
	pub := m.key.PublicKey
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	doc := map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "RSA", "kid": m.kid, "alg": "RS256", "use": "sig",
			"n": n, "e": e,
		}},
	}
	body, _ := json.Marshal(doc)
	handler = func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&counter, 1)
		if cacheControl != "" {
			w.Header().Set("Cache-Control", cacheControl)
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_, _ = w.Write(body)
	}
	return handler, &counter
}

// startJwks runs an httptest.Server backed by the signer's JWKS handler.
func startJwks(t *testing.T, m *mockSigner, cacheControl string) (string, *int32, *httptest.Server) {
	t.Helper()
	h, hits := m.jwks(cacheControl)
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL, hits, srv
}

func sampleClaims(issuer, aud, sub string, exp time.Time) jwt.MapClaims {
	return jwt.MapClaims{
		"iss":         issuer,
		"aud":         aud,
		"sub":         sub,
		"exp":         exp.Unix(),
		"nbf":         time.Now().Add(-1 * time.Second).Unix(),
		"iat":         time.Now().Unix(),
		"eat_nonce":   "bm9uY2U",
		"eat_profile": "tag:rootherald.io,2026:tpm-passport",
		"ueid":        "ek-fingerprint",
		"hwmodel":     "TestModel",
		"dbgstat":     "3",
		"ear.status":  1,
	}
}
