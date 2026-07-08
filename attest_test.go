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
	if _, err := NewAttestClient("rh_bogus_abc"); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("invalid-prefix key err = %v, want ErrInvalidSecretKey", err)
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
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Attest(context.Background(), json.RawMessage(`{"quote":"..."}`),
		AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Verdict != VerdictAllow {
		t.Errorf("verdict = %s, want allow", res.Verdict)
	}
}

// Cohort fields on verdict.device parse into the typed Device view.
func TestAttestClient_AttestParsesCohortFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{
				"verdict": "pass",
				"device": map[string]any{
					"ueid":                   "dev-9",
					"cohortKey":              "tpm20:win11:sb1:abc123",
					"cohortScope":            "tenant-fleet",
					"cohortPrevalence":       0.042,
					"cohortPrevalencePerPcr": map[string]any{"0": 0.9, "7": 0.5},
					"cohortSampleSize":       1287,
					"novelProfile":           false,
				},
			},
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Attest(context.Background(), json.RawMessage(`{}`),
		AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Device == nil {
		t.Fatal("Device is nil; want parsed cohort fields")
	}
	if res.Device.CohortKey == nil || *res.Device.CohortKey != "tpm20:win11:sb1:abc123" {
		t.Errorf("CohortKey = %v", res.Device.CohortKey)
	}
	if res.Device.CohortScope == nil || *res.Device.CohortScope != "tenant-fleet" {
		t.Errorf("CohortScope = %v", res.Device.CohortScope)
	}
	if res.Device.CohortPrevalence == nil || *res.Device.CohortPrevalence != 0.042 {
		t.Errorf("CohortPrevalence = %v", res.Device.CohortPrevalence)
	}
	if res.Device.CohortSampleSize == nil || *res.Device.CohortSampleSize != 1287 {
		t.Errorf("CohortSampleSize = %v", res.Device.CohortSampleSize)
	}
	if res.Device.NovelProfile == nil || *res.Device.NovelProfile != false {
		t.Errorf("NovelProfile = %v", res.Device.NovelProfile)
	}
	if got := res.Device.CohortPrevalencePerPcr["7"]; got != 0.5 {
		t.Errorf("CohortPrevalencePerPcr[7] = %v, want 0.5", got)
	}
}

// Cohort fields stay nil when the server omits them.
func TestAttestClient_AttestNoCohortFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{
				"verdict": "pass",
				"device":  map[string]any{"ueid": "dev-9"},
			},
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Attest(context.Background(), json.RawMessage(`{}`),
		AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Device == nil {
		t.Fatal("Device is nil; want a parsed (cohort-empty) device")
	}
	if res.Device.CohortKey != nil || res.Device.CohortPrevalence != nil || res.Device.NovelProfile != nil {
		t.Errorf("expected nil cohort fields, got key=%v prev=%v novel=%v",
			res.Device.CohortKey, res.Device.CohortPrevalence, res.Device.NovelProfile)
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
