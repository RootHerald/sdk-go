package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// IssueChallengeWithOptions puts the ask on the wire and returns the relay
// string; IssueChallenge sends no ask, which the server reads as identity +
// posture. Neither sends a policy: policies bind to the API key and the
// server refuses the field with 400 policy_bound_to_key.
func TestClient_IssueChallengeWithOptions(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody = nil
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce":     "bm9uY2U",
			"challenge": "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiLCJrZXkiXX0",
			"expiresAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	chal, err := c.IssueChallengeWithOptions(context.Background(), ChallengeOptions{
		Ask:        []Ask{AskIdentity, AskKey},
		KeyPurpose: "sign",
		DeviceHint: "laptop-7",
	})
	if err != nil {
		t.Fatalf("IssueChallengeWithOptions: %v", err)
	}
	if chal.Challenge != "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiLCJrZXkiXX0" || chal.Nonce != "bm9uY2U" {
		t.Errorf("challenge = %+v", chal)
	}
	ask, _ := gotBody["ask"].([]any)
	if len(ask) != 2 || ask[0] != "identity" || ask[1] != "key" {
		t.Errorf("ask sent = %v", gotBody["ask"])
	}
	if gotBody["keyPurpose"] != "sign" || gotBody["deviceHint"] != "laptop-7" {
		t.Errorf("body = %v", gotBody)
	}
	if _, present := gotBody["policy"]; present {
		t.Errorf("challenge body carried a policy; policies bind to the API key: %v", gotBody)
	}

	if _, err := c.IssueChallenge(context.Background(), ""); err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	for _, k := range []string{"ask", "policy", "keyPurpose", "deviceHint"} {
		if _, present := gotBody[k]; present {
			t.Errorf("IssueChallenge sent %q; the default ask is the server's", k)
		}
	}
}

// A passing verdict with a key ask carries the certified key at the response
// root, beside verdict / assuranceClaimsMet / enrollmentRequired.
func TestClient_VerifyParsesCertifiedKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict":            map[string]any{"device": map[string]any{"verdict": "pass", "ueid": "dev-9"}},
			"assuranceClaimsMet": []string{},
			"enrollmentRequired": false,
			"key": map[string]any{
				"keyId":       "key_1",
				"jwk":         map[string]string{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"},
				"purpose":     "sign",
				"authPolicy":  "cG9saWN5",
				"certifiedAt": "2026-09-07T10:00:00.1234567+00:00",
			},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if res.Key == nil {
		t.Fatal("Key is nil; want the certified key from the response root")
	}
	if res.Key.KeyID != "key_1" || res.Key.Purpose != "sign" || res.Key.AuthPolicy != "cG9saWN5" {
		t.Errorf("key = %+v", res.Key)
	}
	if res.Key.JWK != (JWK{Kty: "EC", Crv: "P-256", X: "eA", Y: "eQ"}) {
		t.Errorf("jwk = %+v", res.Key.JWK)
	}
	if res.Key.CertifiedAt.Year() != 2026 || res.Key.CertifiedAt.Hour() != 10 {
		t.Errorf("certifiedAt = %v", res.Key.CertifiedAt)
	}
	if _, present := res.Raw["key"]; present {
		t.Error("key leaked into Raw, which is the verdict object only")
	}
}

// No key on the wire means Key is nil, and a key beside a non-passing verdict
// is dropped: the contract certifies nothing on a failing verdict.
func TestClient_VerifyKeyAbsentOrDroppedOnFail(t *testing.T) {
	bodies := []map[string]any{
		{"verdict": map[string]any{"device": map[string]any{"verdict": "pass"}}},
		{
			"verdict": map[string]any{"device": map[string]any{"verdict": "fail"}},
			"key": map[string]any{
				"keyId": "key_1", "purpose": "sign", "certifiedAt": "2026-09-07T10:00:00Z",
				"jwk": map[string]string{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"},
			},
		},
	}
	for i, body := range bodies {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		res, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
		srv.Close()
		if err != nil {
			t.Fatalf("case %d: Verify: %v", i, err)
		}
		if res.Key != nil {
			t.Errorf("case %d: Key = %+v, want nil", i, res.Key)
		}
	}
}

// A key that arrives without its load-bearing fields is a malformed response,
// not a nil key the caller might misread as "no key asked".
func TestClient_VerifyRejectsIncompleteKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"device": map[string]any{"verdict": "pass"}},
			"key":     map[string]any{"keyId": "key_1", "purpose": "sign"},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if !errors.Is(err, ErrAttestHTTP) {
		t.Errorf("err = %v, want ErrAttestHTTP", err)
	}
}

// A 422 is told apart by its error code; one without a recognised code stays
// ErrUnknownPolicy.
func TestClient_422CodeMapping(t *testing.T) {
	cases := []struct {
		code     string
		sentinel error
	}{
		{"admission_refused", ErrAdmissionRefused},
		{"unknown_policy", ErrUnknownPolicy},
		{"", ErrUnknownPolicy},
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
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != 422 || apiErr.Code != tc.code || apiErr.Message != "detail: "+tc.code {
			t.Errorf("code %q: APIError = %+v", tc.code, apiErr)
		}
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
