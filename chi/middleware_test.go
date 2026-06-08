package rhchi

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/golang-jwt/jwt/v5"
	rh "github.com/RootHerald/sdk-go"
)

func newRSA(t *testing.T) *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func startJwks(t *testing.T, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	pub := key.PublicKey
	doc := map[string]interface{}{
		"keys": []map[string]interface{}{{
			"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig",
			"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		}},
	}
	body, _ := json.Marshal(doc)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func sign(t *testing.T, key *rsa.PrivateKey, kid string, claims jwt.MapClaims) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestGuard_Allow(t *testing.T) {
	key := newRSA(t)
	jwksURL := startJwks(t, key, "k1")
	verifier := rh.NewVerifier("iss", "aud", jwksURL)
	tok := sign(t, key, "k1", jwt.MapClaims{
		"iss": "iss", "aud": "aud", "sub": "device-1",
		"exp": time.Now().Add(time.Minute).Unix(),
	})

	r := chi.NewRouter()
	r.With(Guard(GuardConfig{Verifier: verifier})).Get("/ok", func(w http.ResponseWriter, req *http.Request) {
		c, ok := Claims(req.Context())
		if !ok || c.Subject != "device-1" {
			t.Errorf("claims missing in handler")
		}
		_, _ = io.WriteString(w, "ok")
	})

	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("X-RootHerald-Token", tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGuard_MissingToken(t *testing.T) {
	key := newRSA(t)
	jwksURL := startJwks(t, key, "k1")
	verifier := rh.NewVerifier("iss", "aud", jwksURL)
	r := chi.NewRouter()
	r.With(Guard(GuardConfig{Verifier: verifier})).Get("/ok", func(w http.ResponseWriter, req *http.Request) {})
	req := httptest.NewRequest("GET", "/ok", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGuard_BadToken(t *testing.T) {
	key := newRSA(t)
	jwksURL := startJwks(t, key, "k1")
	verifier := rh.NewVerifier("iss", "aud", jwksURL)
	r := chi.NewRouter()
	r.With(Guard(GuardConfig{Verifier: verifier})).Get("/ok", func(w http.ResponseWriter, req *http.Request) {})
	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("X-RootHerald-Token", "not-a-jwt")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGuard_AuthorizationHeader(t *testing.T) {
	key := newRSA(t)
	jwksURL := startJwks(t, key, "k1")
	verifier := rh.NewVerifier("iss", "aud", jwksURL)
	tok := sign(t, key, "k1", jwt.MapClaims{
		"iss": "iss", "aud": "aud", "sub": "device-1",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	r := chi.NewRouter()
	r.With(Guard(GuardConfig{Verifier: verifier})).Get("/ok", func(w http.ResponseWriter, req *http.Request) {})
	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("Authorization", "RootHerald "+tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 200 {
		t.Errorf("status = %d", w.Code)
	}
}

func TestGuard_503OnJwksDown(t *testing.T) {
	verifier := rh.NewVerifier("iss", "aud", "http://127.0.0.1:1")
	key := newRSA(t)
	tok := sign(t, key, "k1", jwt.MapClaims{
		"iss": "iss", "aud": "aud", "sub": "x",
		"exp": time.Now().Add(time.Minute).Unix(),
	})
	r := chi.NewRouter()
	r.With(Guard(GuardConfig{Verifier: verifier})).Get("/ok", func(w http.ResponseWriter, req *http.Request) {})
	req := httptest.NewRequest("GET", "/ok", nil)
	req.Header.Set("X-RootHerald-Token", tok)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Errorf("status = %d", w.Code)
	}
}
