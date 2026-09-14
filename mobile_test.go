package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The bridge's forward is brokered as a plain Verify under its nonce, with the
// evidence passed through verbatim.
func TestVerifyMobileEvidence_BrokersVerify(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"device": map[string]any{"verdict": "pass", "ueid": "dev-9"}},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.VerifyMobileEvidence(context.Background(), MobileAppVerifyRequest{
		Nonce:    "n_1",
		Evidence: json.RawMessage(`{"iosAttestation":{"assertion":"YXNzZXJ0","keyId":"a2V5"}}`),
	})
	if err != nil {
		t.Fatalf("VerifyMobileEvidence: %v", err)
	}
	if res.Verdict != VerdictAllow || res.Device == nil || res.Device.UEID != "dev-9" {
		t.Errorf("result = %+v", res)
	}
	if gotBody["nonce"] != "n_1" {
		t.Errorf("nonce sent = %v", gotBody["nonce"])
	}
	ev, _ := gotBody["evidence"].(map[string]any)
	ios, _ := ev["iosAttestation"].(map[string]any)
	if ios["assertion"] != "YXNzZXJ0" || ios["keyId"] != "a2V5" {
		t.Errorf("evidence sent = %v", gotBody["evidence"])
	}
}

// A body the bridge could not have produced is refused before any network call.
func TestVerifyMobileEvidence_ValidatesBody(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	cases := []struct {
		name     string
		body     MobileAppVerifyRequest
		sentinel error
	}{
		{"missing nonce", MobileAppVerifyRequest{
			Evidence: json.RawMessage(`{"iosAttestation":{"assertion":"a","keyId":"k"}}`),
		}, ErrChallenge},
		{"no evidence", MobileAppVerifyRequest{Nonce: "n_1"}, ErrInvalidEvidence},
		{"no iosAttestation", MobileAppVerifyRequest{
			Nonce: "n_1", Evidence: json.RawMessage(`{"quote":{}}`),
		}, ErrInvalidEvidence},
		{"missing keyId", MobileAppVerifyRequest{
			Nonce: "n_1", Evidence: json.RawMessage(`{"iosAttestation":{"assertion":"a"}}`),
		}, ErrInvalidEvidence},
		{"attestation object instead of assertion", MobileAppVerifyRequest{
			Nonce: "n_1", Evidence: json.RawMessage(`{"iosAttestation":{"attestationObject":"o","keyId":"k"}}`),
		}, ErrInvalidEvidence},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.VerifyMobileEvidence(context.Background(), tc.body)
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("err = %v, want %v", err, tc.sentinel)
			}
		})
	}
}

// The link carries the challenge and nothing else; the bridge finds the tenant
// by the nonce inside it.
func TestBuildMobileAttestLink(t *testing.T) {
	got := BuildMobileAttestLink("https://bridge.rootherald.io/", "rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0")
	want := "https://bridge.rootherald.io/try/attest?challenge=rhc1.bm9uY2U.eyJhc2siOlsiaWRlbnRpdHkiXX0"
	if got != want {
		t.Errorf("link = %q, want %q", got, want)
	}
	if got := BuildMobileAttestLink("https://bridge.example", "a b&c"); got != "https://bridge.example/try/attest?challenge=a+b%26c" {
		t.Errorf("link = %q; the challenge must be query-escaped", got)
	}
}
