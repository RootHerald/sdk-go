package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewAttestClient_RejectsBadKeys(t *testing.T) {
	if _, err := NewAttestClient(""); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("empty key err = %v, want ErrInvalidSecretKey", err)
	}
	if _, err := NewAttestClient("rh_pk_live_abc"); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("publishable key err = %v, want ErrInvalidSecretKey", err)
	}
	if _, err := NewAttestClient("rh_sk_live_abc"); err != nil {
		t.Errorf("valid secret key err = %v, want nil", err)
	}
}

func TestAttestClient_CreateChallenge(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challengeId": "ch_1", "nonce": "n_1", "expiresAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	chal, err := c.CreateChallenge(context.Background(), "device-hint")
	if err != nil {
		t.Fatalf("CreateChallenge: %v", err)
	}
	if chal.ChallengeID != "ch_1" || chal.Nonce != "n_1" {
		t.Errorf("challenge = %+v", chal)
	}
	if gotAuth != "Bearer rh_sk_test_key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/api/v1/attestations/challenge" {
		t.Errorf("path = %q", gotPath)
	}
}

func TestAttestClient_AttestPassVerdict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["challengeId"] != "ch_1" {
			t.Errorf("challengeId = %v", body["challengeId"])
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"verdict": "pass", "ueid": "dev-9"},
			"token":   "eyJ.signed.eat",
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Attest(context.Background(), json.RawMessage(`{"quote":"..."}`),
		AttestOptions{ChallengeID: "ch_1", ReturnToken: true})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Verdict != VerdictAllow {
		t.Errorf("verdict = %s, want allow", res.Verdict)
	}
	if res.Token != "eyJ.signed.eat" {
		t.Errorf("token = %q", res.Token)
	}
}

// An un-enrolled / failing device is a verdict, not an error.
func TestAttestClient_AttestFailVerdictNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"verdict": "fail"},
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Attest(context.Background(), json.RawMessage(`{}`),
		AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Attest returned error for fail verdict: %v", err)
	}
	if res.Verdict != VerdictDeny {
		t.Errorf("verdict = %s, want deny", res.Verdict)
	}
}

func TestAttestClient_ErrorMapping(t *testing.T) {
	cases := []struct {
		status   int
		sentinel error
	}{
		{http.StatusUnauthorized, ErrInvalidSecretKey},
		{http.StatusUnprocessableEntity, ErrUnknownPolicy},
		{http.StatusConflict, ErrChallenge},
		{http.StatusBadRequest, ErrInvalidEvidence},
		{http.StatusTooManyRequests, ErrQuotaExceeded},
	}
	for _, tc := range cases {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "x", "message": "boom"})
		}))
		c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.Attest(context.Background(), json.RawMessage(`{}`),
			AttestOptions{ChallengeID: "ch_1"})
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.sentinel)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status {
			t.Errorf("status %d: APIError = %v", tc.status, err)
		}
		srv.Close()
	}
}
