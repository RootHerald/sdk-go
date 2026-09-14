package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewClient_RejectsBadKeys(t *testing.T) {
	if _, err := NewClient(""); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("empty key err = %v, want ErrInvalidSecretKey", err)
	}
	if _, err := NewClient("rh_bogus_abc"); !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("invalid-prefix key err = %v, want ErrInvalidSecretKey", err)
	}
	if _, err := NewClient("rh_sk_live_abc"); err != nil {
		t.Errorf("valid secret key err = %v, want nil", err)
	}
}

func TestClient_IssueChallenge(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"nonce": "n_1", "challenge": "rhc1.n_1.e30", "expiresAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	chal, err := c.IssueChallenge(context.Background(), "device-hint")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	if chal.Nonce != "n_1" || chal.Challenge != "rhc1.n_1.e30" || chal.ExpiresAt != "2030-01-01T00:00:00Z" {
		t.Errorf("challenge = %+v", chal)
	}
	if gotAuth != "Bearer rh_sk_test_key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/api/v1/attest/challenge" {
		t.Errorf("path = %q", gotPath)
	}
}

// The nonce is the backend's handle for the challenge: a response without it,
// or without the challenge string to relay, is malformed.
func TestClient_IssueChallengeRejectsIncompleteResponse(t *testing.T) {
	bodies := []map[string]string{
		{"challenge": "rhc1.n_1.e30", "expiresAt": "2030-01-01T00:00:00Z"},
		{"nonce": "n_1", "expiresAt": "2030-01-01T00:00:00Z"},
		{"nonce": "n_1", "challenge": "rhc1.n_1.e30"},
	}
	for i, body := range bodies {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(body)
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.IssueChallenge(context.Background(), "")
		srv.Close()
		if !errors.Is(err, ErrAttestHTTP) {
			t.Errorf("case %d: err = %v, want ErrAttestHTTP", i, err)
		}
	}
}

// Verify needs the nonce to name the challenge; without one nothing is sent.
func TestClient_VerifyRequiresNonce(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{})
	if !errors.Is(err, ErrChallenge) {
		t.Errorf("err = %v, want ErrChallenge", err)
	}
}

func TestClient_AttestPassVerdict(t *testing.T) {
	var gotDisclosure any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["nonce"] != "n_1" {
			t.Errorf("nonce = %v", body["nonce"])
		}
		if _, present := body["challengeId"]; present {
			t.Errorf("verify body carried a challengeId; the nonce is the handle: %v", body)
		}
		if _, present := body["policy"]; present {
			t.Errorf("verify body carried a policy; policies bind to the API key: %v", body)
		}
		gotDisclosure = body["requestedDisclosureClass"]
		w.Header().Set("Content-Type", "application/json")
		// Real wire shape: the pass/fail token lives at verdict.device.verdict,
		// with assuranceClaimsMet + enrollmentRequired as top-level siblings.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{
				"acr": "urn:rootherald:acr:device",
				"device": map[string]any{
					"verdict":         "pass",
					"ueid":            "dev-9",
					"earStatus":       "affirming",
					"attestationType": "tpm20",
					"quoteVerified":   true,
				},
			},
			"assuranceClaimsMet": []string{"urn:rootherald:assurance:hardware-backed"},
			"enrollmentRequired": false,
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{"quote":"..."}`),
		AttestOptions{Nonce: "n_1", RequestedDisclosureClass: "pseudonymous"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if res.Verdict != VerdictAllow {
		t.Errorf("verdict = %s, want allow", res.Verdict)
	}
	if res.Device == nil || res.Device.EARStatus != "affirming" || res.Device.AttestationType != "tpm20" {
		t.Errorf("device = %+v, want earStatus=affirming attestationType=tpm20", res.Device)
	}
	if len(res.AssuranceClaimsMet) != 1 || res.AssuranceClaimsMet[0] != "urn:rootherald:assurance:hardware-backed" {
		t.Errorf("assuranceClaimsMet = %v", res.AssuranceClaimsMet)
	}
	if res.EnrollmentRequired {
		t.Errorf("enrollmentRequired = true, want false")
	}
	if gotDisclosure != "pseudonymous" {
		t.Errorf("requestedDisclosureClass sent = %v, want pseudonymous", gotDisclosure)
	}
}

// enrollmentRequired surfaces the attest-first / enroll-on-miss signal, and an
// omitted RequestedDisclosureClass leaves the request key out.
func TestClient_AttestEnrollmentRequired(t *testing.T) {
	var sawDisclosureKey bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, sawDisclosureKey = body["requestedDisclosureClass"]
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict":            map[string]any{"device": map[string]any{"verdict": "fail"}},
			"assuranceClaimsMet": []string{},
			"enrollmentRequired": true,
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`),
		AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	if !res.EnrollmentRequired {
		t.Errorf("enrollmentRequired = false, want true")
	}
	if sawDisclosureKey {
		t.Errorf("requestedDisclosureClass sent though not supplied")
	}
}

// Cohort fields on verdict.device parse into the typed Device view.
func TestClient_AttestParsesCohortFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{
				"device": map[string]any{
					"verdict":                "pass",
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

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`),
		AttestOptions{Nonce: "n_1"})
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
func TestClient_AttestNoCohortFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{
				"device": map[string]any{"verdict": "pass", "ueid": "dev-9"},
			},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`),
		AttestOptions{Nonce: "n_1"})
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
func TestClient_AttestFailVerdictNotError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"device": map[string]any{"verdict": "fail"}},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`),
		AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Attest returned error for fail verdict: %v", err)
	}
	if res.Verdict != VerdictDeny {
		t.Errorf("verdict = %s, want deny", res.Verdict)
	}
}

func TestClient_ErrorMapping(t *testing.T) {
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
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.Verify(context.Background(), json.RawMessage(`{}`),
			AttestOptions{Nonce: "n_1"})
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

// The secret travels in an Authorization header on every request, so a base URL
// that is not https puts a full-privilege credential on the wire in the clear. A
// typo is enough, and nothing downstream would notice, because the request still
// succeeds.
func TestNewClient_RejectsInsecureBaseURL(t *testing.T) {
	for _, bad := range []string{
		"http://rootherald.io",
		"http://api.internal.example",
		"rootherald.io",
		"//rootherald.io",
		"",
	} {
		if _, err := NewClient("rh_sk_test", WithBaseURL(bad)); err == nil {
			t.Errorf("base URL %q was accepted; it puts the secret key in cleartext", bad)
		} else if !errors.Is(err, ErrInvalidBaseURL) {
			t.Errorf("base URL %q: got %v, want ErrInvalidBaseURL", bad, err)
		}
	}
}

// Loopback is exempt so the local docker stack still works over http.
func TestNewClient_AllowsHttpsAndLoopback(t *testing.T) {
	for _, ok := range []string{
		"https://rootherald.io",
		"https://preprod.rootherald.io",
		"http://localhost:8080",
		"http://127.0.0.1:5000",
		"http://[::1]:5000",
	} {
		if _, err := NewClient("rh_sk_test", WithBaseURL(ok)); err != nil {
			t.Errorf("base URL %q was rejected: %v", ok, err)
		}
	}
}
