package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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
	chal, err := c.IssueChallenge(context.Background())
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
		_, err := c.IssueChallenge(context.Background())
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
	if !errors.Is(err, ErrInvalidArgument) {
		t.Errorf("err = %v, want ErrInvalidArgument", err)
	}
	if errors.Is(err, ErrChallenge) {
		t.Errorf("a local argument error must not read as a 409: %v", err)
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
		for _, k := range []string{"challengeId", "policy", "expectedKey", "expectedDevices"} {
			if _, present := body[k]; present {
				t.Errorf("verify body carried %q: %v", k, body)
			}
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
	if res.Verdict != VerdictPass {
		t.Errorf("verdict = %s, want pass", res.Verdict)
	}
	if res.Device == nil || res.Device.EARStatus != "affirming" || res.Device.AttestationType != "tpm20" {
		t.Errorf("device = %+v, want earStatus=affirming attestationType=tpm20", res.Device)
	}
	if res.Device.QuoteVerified == nil || !*res.Device.QuoteVerified {
		t.Errorf("quoteVerified = %v, want true", res.Device.QuoteVerified)
	}
	if len(res.AssuranceClaimsMet) != 1 || res.AssuranceClaimsMet[0] != "urn:rootherald:assurance:hardware-backed" {
		t.Errorf("assuranceClaimsMet = %v", res.AssuranceClaimsMet)
	}
	if res.EnrollmentRequired {
		t.Errorf("enrollmentRequired = true, want false")
	}
	if res.Expected != nil {
		t.Errorf("expected = %+v, want nil when the challenge named nothing", res.Expected)
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

// Every device-verdict field the server sends parses into the typed view;
// the optional ones stay nil when omitted.
func TestClient_AttestParsesDeviceVerdictFields(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"verdict":{"device":{
			"verdict":"warn","ueid":"dev-9","disclosureClass":"derived","earStatus":"warning",
			"attestationType":"tpm20","attestedAt":"2026-10-10T10:00:00Z",
			"quoteVerified":true,"secureBootVerified":false,"eventLogVerified":true,
			"postureEvaluated":true,"postureSkippedReason":"","platform":"windows",
			"hardwareModel":"Intel PTT","tpmKind":"firmware-tpm","identityAnchor":"ek",
			"trustworthinessVector":{"instanceIdentity":2,"configuration":1},
			"hardwareGenuine":true,"ekChainTrusted":false,"sybilRisk":"none",
			"sybilResistance":"distinct-silicon","returningDevice":true,
			"identityAgeBucket":"under-90d","accountBindingBand":"2-3",
			"identityFirstSeen":"2026-08-01T00:00:00Z","attestationCount":12,"accountBindingCount":2,
			"possiblyRotated":false,"identitiesOnAnchor":1,"platformRotated":true,"platformRotationsInWindow":1,
			"bootChanged":true,"bootChangedStages":[4,7],"bootChangeAccepted":false,"bootBaselineAt":"2026-09-01T00:00:00Z",
			"cohortKey":"tpm20:win11:sb1:abc123","cohortScope":"tenant-fleet","cohortPrevalence":0.042,
			"cohortPrevalencePerPcr":{"0":0.9,"7":0.5},"cohortSampleSize":1287,"novelProfile":false
		}}}`))
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Attest: %v", err)
	}
	d := res.Device
	if d == nil {
		t.Fatal("Device is nil")
	}
	if res.Verdict != VerdictWarn || d.UEID != "dev-9" || d.DisclosureClass != "derived" || d.AttestedAt != "2026-10-10T10:00:00Z" {
		t.Errorf("device = %+v", d)
	}
	if d.Platform != "windows" || d.HardwareModel != "Intel PTT" || d.TpmKind != "firmware-tpm" || d.IdentityAnchor != "ek" {
		t.Errorf("device = %+v", d)
	}
	if d.SecureBootVerified == nil || *d.SecureBootVerified || d.EventLogVerified == nil || !*d.EventLogVerified || d.PostureEvaluated == nil || !*d.PostureEvaluated {
		t.Errorf("posture flags = %+v", d)
	}
	if d.TrustworthinessVector == nil || d.TrustworthinessVector.InstanceIdentity != 2 || d.TrustworthinessVector.Configuration != 1 {
		t.Errorf("trustworthinessVector = %+v", d.TrustworthinessVector)
	}
	if d.HardwareGenuine == nil || !*d.HardwareGenuine || d.EkChainTrusted == nil || *d.EkChainTrusted {
		t.Errorf("hardware flags = %+v", d)
	}
	if d.SybilRisk != "none" || d.SybilResistance != "distinct-silicon" || d.ReturningDevice == nil || !*d.ReturningDevice {
		t.Errorf("sybil fields = %+v", d)
	}
	if d.IdentityAgeBucket != "under-90d" || d.AccountBindingBand != "2-3" || d.IdentityFirstSeen != "2026-08-01T00:00:00Z" {
		t.Errorf("identity fields = %+v", d)
	}
	if d.AttestationCount == nil || *d.AttestationCount != 12 || d.AccountBindingCount == nil || *d.AccountBindingCount != 2 {
		t.Errorf("counts = %+v", d)
	}
	if d.PossiblyRotated == nil || *d.PossiblyRotated || d.IdentitiesOnAnchor == nil || *d.IdentitiesOnAnchor != 1 || d.PlatformRotated == nil || !*d.PlatformRotated || d.PlatformRotationsInWindow == nil || *d.PlatformRotationsInWindow != 1 {
		t.Errorf("rotation fields = %+v", d)
	}
	if d.BootChanged == nil || !*d.BootChanged || len(d.BootChangedStages) != 2 || d.BootChangedStages[1] != 7 || d.BootChangeAccepted == nil || *d.BootChangeAccepted || d.BootBaselineAt != "2026-09-01T00:00:00Z" {
		t.Errorf("boot fields = %+v", d)
	}
	if d.CohortKey == nil || *d.CohortKey != "tpm20:win11:sb1:abc123" || d.CohortScope == nil || *d.CohortScope != "tenant-fleet" {
		t.Errorf("cohort = %+v", d)
	}
	if d.CohortPrevalence == nil || *d.CohortPrevalence != 0.042 || d.CohortSampleSize == nil || *d.CohortSampleSize != 1287 || d.NovelProfile == nil || *d.NovelProfile {
		t.Errorf("cohort = %+v", d)
	}
	if got := d.CohortPrevalencePerPcr["7"]; got != 0.5 {
		t.Errorf("CohortPrevalencePerPcr[7] = %v, want 0.5", got)
	}
}

// Optional fields stay nil when the server omits them.
func TestClient_AttestNoOptionalFields(t *testing.T) {
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
		t.Fatal("Device is nil; want a parsed device")
	}
	d := res.Device
	if d.CohortKey != nil || d.CohortPrevalence != nil || d.NovelProfile != nil || d.HardwareGenuine != nil || d.QuoteVerified != nil || d.TrustworthinessVector != nil || d.AttestationCount != nil {
		t.Errorf("expected nil optional fields, got %+v", d)
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
	if res.Verdict != VerdictFail {
		t.Errorf("verdict = %s, want fail", res.Verdict)
	}
}

// The verdict vocabulary is the server's; a token outside it is a malformed
// response, never silently a pass or a fail.
func TestClient_VerifyRefusesUnknownVerdictToken(t *testing.T) {
	for _, token := range []any{"allow", "review", "", nil} {
		token := token
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"verdict": map[string]any{"device": map[string]any{"verdict": token}},
			})
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
		srv.Close()
		if !errors.Is(err, ErrAttestHTTP) {
			t.Errorf("token %v: err = %v, want ErrAttestHTTP", token, err)
		}
	}
}

func verdictServer(t *testing.T, verdict map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, k := range []string{"expectedKey", "expectedDevices"} {
			if _, present := body[k]; present {
				t.Errorf("verify body carried %q; the binding is compared locally", k)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"verdict": verdict})
	}))
}

// A verdict is only as bound as the server says it enforced: the echoed
// expected block must match what the caller asked for.
func TestClient_VerifyRequiresExpectedEcho(t *testing.T) {
	device := func(verdict, ueid string) map[string]any {
		return map[string]any{"verdict": verdict, "ueid": ueid}
	}
	cases := []struct {
		name    string
		verdict map[string]any
		opts    AttestOptions
		wantErr bool
	}{
		{"echo matches, any order",
			map[string]any{"device": device("pass", "dev-1"), "expected": map[string]any{"key": "k-1", "devices": []string{"dev-1", "other"}}},
			AttestOptions{Nonce: "n", ExpectedKey: "k-1", ExpectedDevices: []string{"other", "dev-1"}}, false},
		{"no expected block when a key was asked for",
			map[string]any{"device": device("pass", "dev-1")},
			AttestOptions{Nonce: "n", ExpectedKey: "k-1"}, true},
		{"different key echoed",
			map[string]any{"device": device("pass", "dev-1"), "expected": map[string]any{"key": "k-2"}},
			AttestOptions{Nonce: "n", ExpectedKey: "k-1"}, true},
		{"devices echoed as a subset",
			map[string]any{"device": device("pass", "dev-1"), "expected": map[string]any{"devices": []string{"dev-1"}}},
			AttestOptions{Nonce: "n", ExpectedDevices: []string{"dev-1", "other"}}, true},
		{"passing verdict names a device outside the list, even when echoed",
			map[string]any{"device": device("pass", "dev-1"), "expected": map[string]any{"devices": []string{"other"}}},
			AttestOptions{Nonce: "n", ExpectedDevices: []string{"other"}}, true},
		{"failing verdict for another device is a normal verdict",
			map[string]any{"device": device("fail", "dev-1"), "expected": map[string]any{"devices": []string{"other"}}},
			AttestOptions{Nonce: "n", ExpectedDevices: []string{"other"}}, false},
		{"nothing asked, nothing checked",
			map[string]any{"device": device("pass", "dev-1"), "expected": map[string]any{"key": "k-9"}},
			AttestOptions{Nonce: "n"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := verdictServer(t, tc.verdict)
			defer srv.Close()
			c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
			res, err := c.Verify(context.Background(), json.RawMessage(`{}`), tc.opts)
			if tc.wantErr {
				if !errors.Is(err, ErrExpectedNotEnforced) {
					t.Fatalf("err = %v, want ErrExpectedNotEnforced", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			if res.Expected == nil {
				t.Fatal("Expected is nil; want the echoed binding")
			}
		})
	}
}

func TestClient_ErrorMapping(t *testing.T) {
	cases := []struct {
		status   int
		code     string
		sentinel error
	}{
		{http.StatusUnauthorized, "invalid_secret_key", ErrInvalidSecretKey},
		{http.StatusUnauthorized, "activation_refused", ErrActivationRefused},
		{http.StatusUnprocessableEntity, "unknown_policy", ErrUnknownPolicy},
		{http.StatusUnprocessableEntity, "", ErrUnknownPolicy},
		{http.StatusUnprocessableEntity, "admission_refused", ErrAdmissionRefused},
		{http.StatusUnprocessableEntity, "posture_not_bound", ErrAttestHTTP},
		{http.StatusUnprocessableEntity, "expected_unknown", ErrAttestHTTP},
		{http.StatusUnprocessableEntity, "key_disclosure_too_low", ErrAttestHTTP},
		{http.StatusPaymentRequired, "plan_lapsed", ErrAttestHTTP},
		{http.StatusConflict, "x", ErrChallenge},
		{http.StatusConflict, "key_rotation_conflict", ErrAttestHTTP},
		{http.StatusBadRequest, "x", ErrInvalidEvidence},
		{http.StatusBadRequest, "wire_version_unsupported", ErrInvalidEvidence},
		{http.StatusBadRequest, "invalid_enroll_shape", ErrInvalidEvidence},
		{http.StatusBadRequest, "invalid_ask", ErrInvalidAsk},
		{http.StatusTooManyRequests, "budget_exhausted", ErrQuotaExceeded},
		{http.StatusTooManyRequests, "rate_limited", ErrRateLimited},
		{http.StatusTooManyRequests, "", ErrRateLimited},
	}
	for _, tc := range cases {
		tc := tc
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			body := map[string]string{"message": "boom"}
			if tc.code != "" {
				body["error"] = tc.code
			}
			_ = json.NewEncoder(w).Encode(body)
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.Verify(context.Background(), json.RawMessage(`{}`),
			AttestOptions{Nonce: "n_1"})
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("status %d %q: err = %v, want %v", tc.status, tc.code, err, tc.sentinel)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != tc.status || apiErr.Code != tc.code {
			t.Errorf("status %d: APIError = %v", tc.status, err)
		}
		srv.Close()
	}
}

// A 401 is only an invalid key when it is not an activation refusal; a 429 is
// only the budget when it says so, and a limiter 429 carries its retry hint.
func TestClient_RateLimitedCarriesRetryAfter(t *testing.T) {
	cases := []struct {
		name       string
		header     map[string]string
		body       string
		sentinel   error
		retryAfter int
	}{
		{"header wins over body", map[string]string{"Retry-After": "17"},
			`{"error":"rate_limited","message":"Too many requests","retryAfterSeconds":60}`, ErrRateLimited, 17},
		{"body when no header", nil,
			`{"error":"rate_limited","retryAfterSeconds":60}`, ErrRateLimited, 60},
		{"empty 429 is rate limited with no hint", nil, ``, ErrRateLimited, 0},
		{"quota header wins whatever the body", map[string]string{"X-RootHerald-Quota": "budget-exhausted"},
			`{}`, ErrQuotaExceeded, 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for k, v := range tc.header {
					w.Header().Set(k, v)
				}
				w.WriteHeader(http.StatusTooManyRequests)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()
			c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
			_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
			if !errors.Is(err, tc.sentinel) {
				t.Fatalf("err = %v, want %v", err, tc.sentinel)
			}
			var apiErr *APIError
			if !errors.As(err, &apiErr) || apiErr.RetryAfterSeconds != tc.retryAfter {
				t.Errorf("RetryAfterSeconds = %v, want %d", err, tc.retryAfter)
			}
		})
	}
}

func TestClient_BareUnauthorizedIsInvalidSecretKey(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if !errors.Is(err, ErrInvalidSecretKey) || errors.Is(err, ErrActivationRefused) {
		t.Errorf("err = %v, want ErrInvalidSecretKey", err)
	}
}

func TestNewClient_DefaultTimeout(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key")
	if c.http.Timeout != DefaultTimeout || DefaultTimeout != 30*time.Second {
		t.Errorf("timeout = %v, want 30s", c.http.Timeout)
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
