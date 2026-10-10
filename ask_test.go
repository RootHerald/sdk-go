package rootherald

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// IssueChallengeWithOptions puts the ask and the expected binding on the wire
// and returns the relay string; IssueChallenge sends an empty body, which the
// server reads as identity + posture. Neither sends a policy, a keyPurpose or
// a deviceHint.
func TestClient_IssueChallengeWithOptions(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce":     "bm9uY2U",
			"challenge": "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0",
			"expiresAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	chal, err := c.IssueChallengeWithOptions(context.Background(), ChallengeOptions{
		Ask:             []Ask{AskIdentity},
		ExpectedKey:     "k-9f3a",
		ExpectedDevices: []string{"alias-1", "alias-2"},
	})
	if err != nil {
		t.Fatalf("IssueChallengeWithOptions: %v", err)
	}
	if chal.Challenge != "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0" || chal.Nonce != "bm9uY2U" {
		t.Errorf("challenge = %+v", chal)
	}
	ask, _ := gotBody["ask"].([]any)
	if len(ask) != 1 || ask[0] != "identity" {
		t.Errorf("ask sent = %v", gotBody["ask"])
	}
	if gotBody["expectedKey"] != "k-9f3a" {
		t.Errorf("expectedKey sent = %v", gotBody["expectedKey"])
	}
	devices, _ := gotBody["expectedDevices"].([]any)
	if len(devices) != 2 || devices[0] != "alias-1" || devices[1] != "alias-2" {
		t.Errorf("expectedDevices sent = %v", gotBody["expectedDevices"])
	}
	for _, k := range []string{"policy", "keyPurpose", "deviceHint"} {
		if _, present := gotBody[k]; present {
			t.Errorf("challenge body carried %q: %v", k, gotBody)
		}
	}

	if _, err := c.IssueChallenge(context.Background()); err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if len(gotBody) != 0 {
		t.Errorf("IssueChallenge sent %v; the default ask is the server's", gotBody)
	}
}

// An alias list the server would read as "no device may answer", or a blank
// alias, is refused before any request.
func TestClient_IssueChallengeRejectsBadExpectedDevices(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	for name, devices := range map[string][]string{
		"empty list":  {},
		"blank alias": {"alias-1", ""},
	} {
		_, err := c.IssueChallengeWithOptions(context.Background(), ChallengeOptions{ExpectedDevices: devices})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
		_, err = c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n", ExpectedDevices: devices})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("Verify %s: err = %v, want ErrInvalidArgument", name, err)
		}
		_, err = c.IssueKeyChallenge(context.Background(), KeyChallengeOptions{Purpose: KeyPurposeSign, ExpectedDevices: devices})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("IssueKeyChallenge %s: err = %v, want ErrInvalidArgument", name, err)
		}
	}
}

// A verdict carries no key: the key ceremony is IssueKeyChallenge / CertifyKey,
// and a response-root key is ignored rather than surfaced.
func TestClient_VerifyIgnoresResponseRootKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"device": map[string]any{"verdict": "pass", "ueid": "dev-9"}},
			"key":     map[string]any{"keyId": "key_1"},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if _, present := res.Raw["key"]; present {
		t.Error("key leaked into Raw, which is the verdict object only")
	}
}

// IssueKeyChallenge posts the purpose and the expected devices and returns
// the whole response.
func TestClient_IssueKeyChallenge(t *testing.T) {
	var gotBody map[string]any
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce":        "bm9uY2U",
			"keyChallenge": "rhk1c.bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9",
			"expiresAt":    "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	kc, err := c.IssueKeyChallenge(context.Background(), KeyChallengeOptions{
		Purpose:         KeyPurposeSign,
		ExpectedDevices: []string{"alias-1"},
	})
	if err != nil {
		t.Fatalf("IssueKeyChallenge: %v", err)
	}
	if gotPath != "/api/v1/keys/challenge" {
		t.Errorf("path = %q", gotPath)
	}
	if kc.Nonce != "bm9uY2U" || kc.KeyChallenge != "rhk1c.bm9uY2U.eyJwdXJwb3NlIjoic2lnbiJ9" || kc.ExpiresAt != "2030-01-01T00:00:00Z" {
		t.Errorf("key challenge = %+v", kc)
	}
	devices, _ := gotBody["expectedDevices"].([]any)
	if gotBody["purpose"] != "sign" || len(devices) != 1 || devices[0] != "alias-1" || len(gotBody) != 2 {
		t.Errorf("body = %v", gotBody)
	}

	if _, err := c.IssueKeyChallenge(context.Background(), KeyChallengeOptions{Purpose: KeyPurposeDecrypt}); err != nil {
		t.Fatalf("IssueKeyChallenge decrypt: %v", err)
	}
	if gotBody["purpose"] != "decrypt" || len(gotBody) != 1 {
		t.Errorf("body = %v", gotBody)
	}
}

// A purpose outside sign/decrypt is refused locally; a response missing its
// handle or relay string is malformed.
func TestClient_IssueKeyChallengeValidation(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	for _, purpose := range []KeyPurpose{"", "both", "SIGN"} {
		_, err := c.IssueKeyChallenge(context.Background(), KeyChallengeOptions{Purpose: purpose})
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("purpose %q: err = %v, want ErrInvalidArgument", purpose, err)
		}
	}

	bodies := []map[string]string{
		{"keyChallenge": "rhk1c.n.e30", "expiresAt": "2030-01-01T00:00:00Z"},
		{"nonce": "n", "expiresAt": "2030-01-01T00:00:00Z"},
		{"nonce": "n", "keyChallenge": "rhk1c.n.e30"},
	}
	for i, body := range bodies {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.IssueKeyChallenge(context.Background(), KeyChallengeOptions{Purpose: KeyPurposeSign})
		srv.Close()
		if !errors.Is(err, ErrAttestHTTP) {
			t.Errorf("case %d: err = %v, want ErrAttestHTTP", i, err)
		}
	}
}

const tpmCertification = `{"publicArea":"cHVi","attest":"YXR0","signature":"c2ln","futureField":{"a":[1]}}`

func certifyServer(t *testing.T, key map[string]any, gotBody *map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/keys/certify" {
			t.Errorf("path = %q", r.URL.Path)
		}
		if gotBody != nil {
			*gotBody = nil
			_ = json.NewDecoder(r.Body).Decode(gotBody)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(key)
	}))
}

func ecCertifiedKey() map[string]any {
	return map[string]any{
		"deviceId":      "dev-9",
		"keyId":         "key_1",
		"purpose":       "sign",
		"alg":           "ES256",
		"jwk":           map[string]string{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"},
		"hardwareBound": true,
		"certifiedAt":   "2026-09-07T10:00:00.1234567+00:00",
	}
}

// CertifyKey relays the certification verbatim under the nonce, unknown
// fields included, and returns the key the server registered.
func TestClient_CertifyKeyEC(t *testing.T) {
	var gotBody map[string]any
	srv := certifyServer(t, ecCertifiedKey(), &gotBody)
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	key, err := c.CertifyKey(context.Background(), "n_1", Certification(tpmCertification))
	if err != nil {
		t.Fatalf("CertifyKey: %v", err)
	}
	if gotBody["nonce"] != "n_1" {
		t.Errorf("nonce sent = %v", gotBody["nonce"])
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(tpmCertification), &want)
	if sent, _ := json.Marshal(gotBody["certification"]); string(sent) != mustJSON(want) {
		t.Errorf("certification sent = %s, want %s", sent, mustJSON(want))
	}
	if key.DeviceID != "dev-9" || key.KeyID != "key_1" || key.Purpose != KeyPurposeSign || key.Alg != "ES256" || key.Format != "" || !key.HardwareBound {
		t.Errorf("key = %+v", key)
	}
	if key.JWK != (JWK{Kty: "EC", Crv: "P-256", X: "eA", Y: "eQ"}) {
		t.Errorf("jwk = %+v", key.JWK)
	}
	if key.CertifiedAt.Year() != 2026 || key.CertifiedAt.Hour() != 10 {
		t.Errorf("certifiedAt = %v", key.CertifiedAt)
	}
}

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// An RSA-2048 key is read as {kty, n, e}; a decrypt key carries its format;
// macOS and iOS certifications are relayed as-is.
func TestClient_CertifyKeyRSAAndPlatformShapes(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	n := base64.RawURLEncoding.EncodeToString(priv.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	rsaKey := ecCertifiedKey()
	rsaKey["purpose"] = "decrypt"
	rsaKey["alg"] = "RSA-OAEP-256"
	rsaKey["format"] = "jwe"
	rsaKey["jwk"] = map[string]string{"kty": "RSA", "n": n, "e": e}

	var gotBody map[string]any
	srv := certifyServer(t, rsaKey, &gotBody)
	defer srv.Close()
	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))

	for _, cert := range []string{
		`{"platform":"macos","publicKey":"cGs","signature":"c2ln"}`,
		`{"platform":"ios","keyId":"a2V5","assertion":"YXNz"}`,
	} {
		key, err := c.CertifyKey(context.Background(), "n_1", Certification(cert))
		if err != nil {
			t.Fatalf("CertifyKey(%s): %v", cert, err)
		}
		var want map[string]any
		_ = json.Unmarshal([]byte(cert), &want)
		if sent := mustJSON(gotBody["certification"]); sent != mustJSON(want) {
			t.Errorf("certification sent = %s, want %s", sent, mustJSON(want))
		}
		if key.Purpose != KeyPurposeDecrypt || key.Alg != "RSA-OAEP-256" || key.Format != "jwe" {
			t.Errorf("key = %+v", key)
		}
		if key.JWK != (JWK{Kty: "RSA", N: n, E: e}) {
			t.Errorf("jwk = %+v", key.JWK)
		}
	}
}

// The key is the call's only output, so a malformed one is refused rather
// than returned half-parsed.
func TestClient_CertifyKeyRejectsMalformedKey(t *testing.T) {
	cases := map[string]func(k map[string]any){
		"missing deviceId":      func(k map[string]any) { delete(k, "deviceId") },
		"missing keyId":         func(k map[string]any) { k["keyId"] = "" },
		"bad purpose":           func(k map[string]any) { k["purpose"] = "both" },
		"missing hardwareBound": func(k map[string]any) { delete(k, "hardwareBound") },
		"bad certifiedAt":       func(k map[string]any) { k["certifiedAt"] = "yesterday" },
		"missing jwk":           func(k map[string]any) { delete(k, "jwk") },
		"P-384 jwk": func(k map[string]any) {
			k["jwk"] = map[string]string{"kty": "EC", "crv": "P-384", "x": "eA", "y": "eQ"}
		},
		"RSA without e":      func(k map[string]any) { k["jwk"] = map[string]string{"kty": "RSA", "n": "bg"} },
		"RS256 on an EC key": func(k map[string]any) { k["alg"] = "RS256" },
		"ES256 on an RSA key": func(k map[string]any) {
			k["jwk"] = map[string]string{"kty": "RSA", "n": "bg", "e": "AQAB"}
		},
		"unknown alg":    func(k map[string]any) { k["alg"] = "EdDSA" },
		"unknown format": func(k map[string]any) { k["format"] = "pem" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			key := ecCertifiedKey()
			mutate(key)
			srv := certifyServer(t, key, nil)
			defer srv.Close()
			c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
			_, err := c.CertifyKey(context.Background(), "n_1", Certification(tpmCertification))
			if !errors.Is(err, ErrAttestHTTP) {
				t.Errorf("err = %v, want ErrAttestHTTP", err)
			}
		})
	}
}

// A certification that is none of the three platform shapes, or a missing
// nonce, is refused before any request.
func TestClient_CertifyKeyValidatesInput(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	if _, err := c.CertifyKey(context.Background(), "", Certification(tpmCertification)); !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("empty nonce: err = %v, want ErrInvalidArgument", err)
	}
	for name, cert := range map[string]string{
		"nil":               "",
		"not json":          "garbage",
		"array":             "[1]",
		"empty object":      "{}",
		"missing signature": `{"publicArea":"p","attest":"a"}`,
		"blank platform":    `{"platform":"","publicKey":"p","signature":"s"}`,
		"platform not text": `{"platform":5}`,
	} {
		_, err := c.CertifyKey(context.Background(), "n_1", Certification(cert))
		if !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("%s: err = %v, want ErrInvalidArgument", name, err)
		}
	}
}

// A 422 is told apart by its error code; one without a recognised code stays
// ErrUnknownPolicy, and the expected-binding and key refusals keep their code
// on the generic error.
func TestClient_422CodeMapping(t *testing.T) {
	cases := []struct {
		code     string
		sentinel error
	}{
		{"admission_refused", ErrAdmissionRefused},
		{"unknown_policy", ErrUnknownPolicy},
		{"", ErrUnknownPolicy},
		{"expected_unknown", ErrAttestHTTP},
		{"key_disclosure_too_low", ErrAttestHTTP},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": tc.code, "message": "detail: " + tc.code})
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
		srv.Close()
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("code %q: err = %v, want %v", tc.code, err, tc.sentinel)
		}
		if tc.sentinel == ErrAttestHTTP && errors.Is(err, ErrUnknownPolicy) {
			t.Errorf("code %q must not read as ErrUnknownPolicy", tc.code)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 422 || apiErr.Code != tc.code || apiErr.Message != "detail: "+tc.code {
			t.Errorf("code %q: APIError = %+v", tc.code, apiErr)
		}
	}
}

// A 400 invalid_ask is the backend's code being wrong, not the device
// failing: it is ErrInvalidAsk, never ErrInvalidEvidence.
func TestClient_InvalidAskIsNotInvalidEvidence(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_ask", "message": "unknown ask: key"})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.IssueChallengeWithOptions(context.Background(), ChallengeOptions{Ask: []Ask{"key"}})
	if !errors.Is(err, ErrInvalidAsk) || errors.Is(err, ErrInvalidEvidence) {
		t.Errorf("err = %v, want ErrInvalidAsk", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "invalid_ask" {
		t.Errorf("APIError = %+v", apiErr)
	}
}

// A 409 key_rotation_conflict is the rotation colliding, not the challenge
// being spent; it stays a generic error with the code preserved.
func TestClient_KeyRotationConflictIsNotChallengeError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "key_rotation_conflict", "message": "rotation in progress"})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.CertifyKey(context.Background(), "n_1", Certification(tpmCertification))
	if !errors.Is(err, ErrAttestHTTP) || errors.Is(err, ErrChallenge) {
		t.Errorf("err = %v, want ErrAttestHTTP", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != 409 || apiErr.Code != "key_rotation_conflict" {
		t.Errorf("APIError = %+v", apiErr)
	}
}

// A 429 budget_exhausted is the budget ceiling, and names the budget that
// refused.
func TestClient_BudgetExhaustedNamesTheBudget(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":"budget_exhausted","message":"budget exhausted","budget":{"id":"bgt_1","name":"Production"}}`))
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if !errors.Is(err, ErrQuotaExceeded) || errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrQuotaExceeded", err)
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Budget == nil || apiErr.Budget.ID != "bgt_1" || apiErr.Budget.Name != "Production" {
		t.Errorf("APIError = %+v", apiErr)
	}
}

// A device whose TPM class can never satisfy the identity policy bound to the
// key is refused before it gets an AK, with the class in the message.
func TestRelayEnroll_AdmissionRefused(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error":   "admission_refused",
			"message": "policy requires a discrete TPM; device class is firmware-tpm",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
	if !errors.Is(err, ErrAdmissionRefused) {
		t.Fatalf("err = %v, want ErrAdmissionRefused", err)
	}
	if errors.Is(err, ErrUnknownPolicy) {
		t.Error("admission_refused must not also read as ErrUnknownPolicy")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.Code != "admission_refused" || apiErr.Message == "" {
		t.Errorf("APIError = %+v", apiErr)
	}
}
