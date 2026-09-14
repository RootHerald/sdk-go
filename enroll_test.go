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

// validEnrollBlob is a minimal well-formed TPM enroll request blob.
func validEnrollBlob() EnrollRequestBlob {
	return EnrollRequestBlob{
		EkPublicKey:  "ZWtwdWI=",
		AkPublicArea: "YWtwdWI=",
		Platform:     PlatformWindows,
	}
}

// validIOSEnrollBlob is a minimal well-formed App Attest enroll request blob.
func validIOSEnrollBlob() EnrollRequestBlob {
	return EnrollRequestBlob{
		Platform:             PlatformIOS,
		IOSKeyID:             "a2V5",
		IOSAttestationObject: "YXR0",
		Nonce:                "bm9uY2U",
	}
}

func TestRelayEnroll_TPM201(t *testing.T) {
	var gotAuth, gotPath, gotQuery, gotMethod string
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotMethod = r.Method
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrollmentId":    "enr-1",
			"credentialBlob":  "cred",
			"encryptedSecret": "sec",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	blob := validEnrollBlob()
	blob.TpmSelfReport = &TpmSelfReport{Manufacturer: "INTC", VendorString: "Intel"}
	res, err := c.RelayEnroll(context.Background(), blob)
	if err != nil {
		t.Fatalf("RelayEnroll: %v", err)
	}
	if res.Challenge == nil {
		t.Fatal("Challenge is nil; want the MakeCredential challenge")
	}
	if res.Challenge.EnrollmentID != "enr-1" || res.Challenge.CredentialBlob != "cred" || res.Challenge.EncryptedSecret != "sec" {
		t.Errorf("Challenge = %+v", res.Challenge)
	}
	if gotAuth != "Bearer rh_sk_test_key" {
		t.Errorf("auth = %q", gotAuth)
	}
	if gotPath != "/api/v1/attest/enroll" || gotQuery != "" {
		t.Errorf("path = %q query = %q", gotPath, gotQuery)
	}
	if gotMethod != http.MethodPost {
		t.Errorf("method = %q", gotMethod)
	}
	// Wire shape: the canonical JSON keys round-trip verbatim.
	if gotBody["ekPublicKey"] != "ZWtwdWI=" || gotBody["akPublicArea"] != "YWtwdWI=" || gotBody["platform"] != "windows" {
		t.Errorf("relayed enroll body = %v", gotBody)
	}
	report, _ := gotBody["tpmSelfReport"].(map[string]any)
	if report["manufacturer"] != "INTC" || report["vendorString"] != "Intel" {
		t.Errorf("tpmSelfReport = %v", gotBody["tpmSelfReport"])
	}
	for _, k := range []string{"iosKeyId", "iosAttestationObject", "nonce"} {
		if _, present := gotBody[k]; present {
			t.Errorf("TPM enroll body carried %q", k)
		}
	}
}

// A macOS enrollment answers with a nonce for the enclave key to sign.
func TestRelayEnroll_MacOS201(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrollmentId":   "enr-2",
			"challengeNonce": "bm9uY2U=",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	blob := validEnrollBlob()
	blob.Platform = PlatformMacOS
	res, err := c.RelayEnroll(context.Background(), blob)
	if err != nil {
		t.Fatalf("RelayEnroll: %v", err)
	}
	if res.Challenge == nil || res.Challenge.EnrollmentID != "enr-2" || res.Challenge.ChallengeNonce != "bm9uY2U=" {
		t.Errorf("Challenge = %+v", res.Challenge)
	}
}

// An iOS enrollment has no activation leg: the 201 is empty, and the relayed
// body carries only the App Attest fields.
func TestRelayEnroll_IOSEmpty201(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayEnroll(context.Background(), validIOSEnrollBlob())
	if err != nil {
		t.Fatalf("RelayEnroll: %v", err)
	}
	if res.Challenge == nil {
		t.Fatal("Challenge is nil; want an empty challenge to relay")
	}
	if relayed, _ := json.Marshal(res.Challenge); string(relayed) != "{}" {
		t.Errorf("relayed challenge = %s, want {}", relayed)
	}
	if gotBody["platform"] != "ios" || gotBody["iosKeyId"] != "a2V5" || gotBody["iosAttestationObject"] != "YXR0" || gotBody["nonce"] != "bm9uY2U" {
		t.Errorf("relayed enroll body = %v", gotBody)
	}
	for _, k := range []string{"ekPublicKey", "akPublicArea"} {
		if _, present := gotBody[k]; present {
			t.Errorf("iOS enroll body carried %q", k)
		}
	}
}

// A TPM or macOS 201 must name the enrollment and carry one proof to answer.
func TestRelayEnroll_RejectsIncomplete201(t *testing.T) {
	bodies := []map[string]string{
		{"credentialBlob": "cred", "encryptedSecret": "sec"},
		{"enrollmentId": "enr-1"},
		{"enrollmentId": "enr-1", "credentialBlob": "cred"},
		{},
	}
	for i, body := range bodies {
		body := body
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(body)
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
		srv.Close()
		if !errors.Is(err, ErrAttestHTTP) {
			t.Errorf("case %d: err = %v, want ErrAttestHTTP", i, err)
		}
	}
}

func TestRelayEnroll_409IsAPIError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]string{})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
	if err == nil {
		t.Fatal("expected error for 409")
	}
	var apiErr *APIError
	if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusConflict {
		t.Errorf("err = %v, want *APIError with 409", err)
	}
}

func TestRelayEnroll_ValidatesBlob(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	cases := []struct {
		name string
		blob EnrollRequestBlob
	}{
		{"missing both", EnrollRequestBlob{}},
		{"missing ak", EnrollRequestBlob{EkPublicKey: "x", Platform: PlatformWindows}},
		{"missing ek", EnrollRequestBlob{AkPublicArea: "y", Platform: PlatformLinux}},
		{"macos missing ak", EnrollRequestBlob{EkPublicKey: "x", Platform: PlatformMacOS}},
		{"ios missing keyId", EnrollRequestBlob{Platform: PlatformIOS, IOSAttestationObject: "a", Nonce: "n"}},
		{"ios missing attestation", EnrollRequestBlob{Platform: PlatformIOS, IOSKeyID: "k", Nonce: "n"}},
		{"ios missing nonce", EnrollRequestBlob{Platform: PlatformIOS, IOSKeyID: "k", IOSAttestationObject: "a"}},
		{"ios with tpm fields only", EnrollRequestBlob{Platform: PlatformIOS, EkPublicKey: "x", AkPublicArea: "y"}},
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
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("status %d: err = %v, want %v", tc.status, err, tc.sentinel)
		}
		srv.Close()
	}
}

func TestRelayActivate_Success(t *testing.T) {
	var gotAuth, gotPath string
	var gotBody map[string]any
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

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		EnrollmentID:    "enr-1",
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
	if gotPath != "/api/v1/attest/activate" {
		t.Errorf("path = %q", gotPath)
	}
	// Wire shape: enrollmentId/decryptedSecret round-trip verbatim and nothing
	// names a device.
	if gotBody["enrollmentId"] != "enr-1" || gotBody["decryptedSecret"] != "c2VjcmV0" {
		t.Errorf("relayed activate body = %v", gotBody)
	}
	for _, k := range []string{"deviceId", "challengeId", "akPublicKey", "signature"} {
		if _, present := gotBody[k]; present {
			t.Errorf("activate body carried %q", k)
		}
	}
}

// A macOS activation proves residency with a signature instead of a secret.
func TestRelayActivate_Signature(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]string{"deviceId": "dev-2", "status": "enrolled"})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		EnrollmentID: "enr-2",
		Signature:    "c2ln",
	})
	if err != nil {
		t.Fatalf("RelayActivate: %v", err)
	}
	if res.DeviceID != "dev-2" {
		t.Errorf("result = %+v", res)
	}
	if gotBody["enrollmentId"] != "enr-2" || gotBody["signature"] != "c2ln" {
		t.Errorf("relayed activate body = %v", gotBody)
	}
	if _, present := gotBody["decryptedSecret"]; present {
		t.Errorf("macOS activate body carried decryptedSecret")
	}
}

func TestRelayActivate_ValidatesInput(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	cases := []struct {
		name string
		in   EnrollActivationResponse
	}{
		{"missing all", EnrollActivationResponse{}},
		{"missing proof", EnrollActivationResponse{EnrollmentID: "enr-1"}},
		{"missing enrollmentId with secret", EnrollActivationResponse{DecryptedSecret: "s"}},
		{"missing enrollmentId with signature", EnrollActivationResponse{Signature: "s"}},
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

// An unknown, spent or foreign enrollment and a wrong proof are refused alike
// with a 401.
func TestRelayActivate_ErrorMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": "Invalid credential activation response"})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		EnrollmentID: "enr-1", DecryptedSecret: "s",
	})
	if !errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("err = %v, want ErrInvalidSecretKey", err)
	}
}

// Verify is the renamed primary; Attest stays as a thin alias.
func TestVerify_AliasParity(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"verdict": map[string]any{"device": map[string]any{"verdict": "pass"}},
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	v, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	a, err := c.Verify(context.Background(), json.RawMessage(`{}`), AttestOptions{Nonce: "n_1"})
	if err != nil {
		t.Fatalf("Attest alias: %v", err)
	}
	if v.Verdict != VerdictAllow || a.Verdict != VerdictAllow {
		t.Errorf("Verify=%s Attest=%s, want allow", v.Verdict, a.Verdict)
	}
}
