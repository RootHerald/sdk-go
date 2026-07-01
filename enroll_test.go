package rootherald

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// validEnrollBlob is a minimal well-formed enroll request blob.
func validEnrollBlob() EnrollRequestBlob {
	return EnrollRequestBlob{
		EkPublicKey:  "ZWtwdWI=",
		AkPublicArea: "YWtwdWI=",
		Platform:     PlatformWindows,
	}
}

func TestRelayEnroll_FreshEnroll201(t *testing.T) {
	var gotAuth, gotPath, gotMethod string
	var gotBody EnrollRequestBlob
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"deviceId":        "dev-1",
			"credentialBlob":  "cred",
			"encryptedSecret": "sec",
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayEnroll(context.Background(), validEnrollBlob())
	if err != nil {
		t.Fatalf("RelayEnroll: %v", err)
	}
	if res.AlreadyEnrolled {
		t.Errorf("AlreadyEnrolled = true, want false for 201")
	}
	if res.DeviceID != "dev-1" {
		t.Errorf("DeviceID = %q, want dev-1", res.DeviceID)
	}
	if res.Challenge == nil {
		t.Fatal("Challenge is nil; want the MakeCredential challenge for a fresh enroll")
	}
	if res.Challenge.CredentialBlob != "cred" || res.Challenge.EncryptedSecret != "sec" {
		t.Errorf("Challenge = %+v", res.Challenge)
	}
	if gotAuth != "Bearer rh_sk_test_key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/api/v1/devices/enroll" {
		t.Errorf("path = %q", gotPath)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q", gotMethod)
	}
	// Wire shape: the canonical JSON keys must round-trip verbatim.
	if gotBody.EkPublicKey != "ZWtwdWI=" || gotBody.AkPublicArea != "YWtwdWI=" || gotBody.Platform != PlatformWindows {
		t.Errorf("relayed enroll body = %+v", gotBody)
	}
}

func TestRelayEnroll_AlreadyEnrolled409(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{"deviceId": "dev-existing"})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayEnroll(context.Background(), validEnrollBlob())
	if err != nil {
		t.Fatalf("RelayEnroll 409 returned error: %v (409 already-enrolled is not an error)", err)
	}
	if !res.AlreadyEnrolled {
		t.Errorf("AlreadyEnrolled = false, want true for 409")
	}
	if res.DeviceID != "dev-existing" {
		t.Errorf("DeviceID = %q, want dev-existing", res.DeviceID)
	}
	if res.Challenge != nil {
		t.Errorf("Challenge = %+v, want nil for already-enrolled", res.Challenge)
	}
}

func TestRelayEnroll_409MissingDeviceID(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
	if err == nil {
		t.Fatal("expected error for 409 with no deviceId")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Errorf("err = %v, want *APIError with 409", err)
	}
}

func TestRelayEnroll_ValidatesBlob(t *testing.T) {
	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	cases := []struct {
		name string
		blob EnrollRequestBlob
	}{
		{"missing both", EnrollRequestBlob{}},
		{"missing ak", EnrollRequestBlob{EkPublicKey: "x"}},
		{"missing ek", EnrollRequestBlob{AkPublicArea: "y"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.RelayEnroll(context.Background(), tc.blob)
			if !errors.Is(err, ErrInvalidEnrollBlob) {
				t.Errorf("err = %v, want ErrInvalidEnrollBlob", err)
			}
		})
	}
}

func TestRelayEnroll_ErrorMapping(t *testing.T) {
	cases := []struct {
		status   int
		sentinel error
	}{
		{http.StatusUnauthorized, ErrInvalidSecretKey},
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
		_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.sentinel)
		}
		srv.Close()
	}
}

func TestRelayActivate_Success(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody EnrollActivationResponse
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"deviceId":   "dev-1",
			"status":     "enrolled",
			"enrolledAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		DeviceID:        "dev-1",
		DecryptedSecret: "c2VjcmV0",
	})
	if err != nil {
		t.Fatalf("RelayActivate: %v", err)
	}
	if res.DeviceID != "dev-1" || res.Status != "enrolled" || res.EnrolledAt != "2030-01-01T00:00:00Z" {
		t.Errorf("result = %+v", res)
	}
	if gotAuth != "Bearer rh_sk_test_key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/api/v1/devices/activate" {
		t.Errorf("path = %q", gotPath)
	}
	// Wire shape: deviceId/decryptedSecret round-trip verbatim.
	if gotBody.DeviceID != "dev-1" || gotBody.DecryptedSecret != "c2VjcmV0" {
		t.Errorf("relayed activate body = %+v", gotBody)
	}
}

func TestRelayActivate_ValidatesInput(t *testing.T) {
	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	cases := []struct {
		name string
		in   EnrollActivationResponse
	}{
		{"missing both", EnrollActivationResponse{}},
		{"missing secret", EnrollActivationResponse{DeviceID: "dev-1"}},
		{"missing deviceId", EnrollActivationResponse{DecryptedSecret: "s"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.RelayActivate(context.Background(), tc.in)
			if !errors.Is(err, ErrInvalidActivation) {
				t.Errorf("err = %v, want ErrInvalidActivation", err)
			}
		})
	}
}

func TestRelayActivate_ErrorMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "x", "message": "bad key"})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		DeviceID: "dev-1", DecryptedSecret: "s",
	})
	if !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("err = %v, want ErrInvalidSecretKey", err)
	}
}

// IssueChallenge is the renamed primary; CreateChallenge stays as a thin alias.
func TestIssueChallenge_AliasParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{
			"challengeId": "ch_1", "nonce": "n_1", "expiresAt": "2030-01-01T00:00:00Z",
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	a, err := c.IssueChallenge(context.Background(), "")
	if err != nil {
		t.Fatalf("IssueChallenge: %v", err)
	}
	b, err := c.CreateChallenge(context.Background(), "")
	if err != nil {
		t.Fatalf("CreateChallenge alias: %v", err)
	}
	if a.ChallengeID != b.ChallengeID || a.ChallengeID != "ch_1" {
		t.Errorf("IssueChallenge=%+v CreateChallenge=%+v", a, b)
	}
}

// Verify is the renamed primary; Attest stays as a thin alias.
func TestVerify_AliasParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"verdict": "pass"},
		})
	}))
	defer srv.Close()

	c, _ := NewAttestClient("rh_sk_test_key", WithBaseURL(srv.URL))
	v, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	a, err := c.Attest(context.Background(), json.RawMessage(`{}`), AttestOptions{ChallengeID: "ch_1"})
	if err != nil {
		t.Fatalf("Attest alias: %v", err)
	}
	if v.Verdict != VerdictAllow || a.Verdict != VerdictAllow {
		t.Errorf("Verify=%s Attest=%s, want allow", v.Verdict, a.Verdict)
	}
}
