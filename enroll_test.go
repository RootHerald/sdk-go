package rootherald

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// validEnrollBlob is a minimal well-formed wire 8.0 TPM enroll request blob.
func validEnrollBlob() EnrollRequestBlob {
	return EnrollRequestBlob{
		EkPublicKey: "ZWtwdWI=",
		AttestationKey: &AttestationKeyPublic{
			PublicArea:       "YWtwdWI=",
			ParentPublicArea: "cGFyZW50",
			QualifiedName:    "cW4=",
		},
		Platform: PlatformWindows,
	}
}

// validMacOSEnrollBlob is the flat Secure Enclave body: the enclave key twice,
// no parent.
func validMacOSEnrollBlob() EnrollRequestBlob {
	return EnrollRequestBlob{
		EkPublicKey:  "ZWtwdWI=",
		AkPublicArea: "ZWtwdWI=",
		Platform:     PlatformMacOS,
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
	// Wire shape: the canonical JSON keys round-trip verbatim, with the AK
	// nested under attestationKey and no top-level akPublicArea.
	if gotBody["ekPublicKey"] != "ZWtwdWI=" || gotBody["platform"] != "windows" {
		t.Errorf("relayed enroll body = %v", gotBody)
	}
	ak, _ := gotBody["attestationKey"].(map[string]any)
	if ak["publicArea"] != "YWtwdWI=" || ak["parentPublicArea"] != "cGFyZW50" || ak["qualifiedName"] != "cW4=" {
		t.Errorf("attestationKey = %v", gotBody["attestationKey"])
	}
	report, _ := gotBody["tpmSelfReport"].(map[string]any)
	if report["manufacturer"] != "INTC" || report["vendorString"] != "Intel" {
		t.Errorf("tpmSelfReport = %v", gotBody["tpmSelfReport"])
	}
	for _, k := range []string{"akPublicArea", "iosKeyId", "iosAttestationObject", "nonce"} {
		if _, present := gotBody[k]; present {
			t.Errorf("TPM enroll body carried %q", k)
		}
	}
}

// RelayEnrollJSON relays the device's JSON byte-for-byte: fields this SDK does
// not model reach the server unchanged.
func TestRelayEnrollJSON_Verbatim(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrollmentId": "enr-1", "credentialBlob": "cred", "encryptedSecret": "sec",
		})
	}))
	defer srv.Close()

	const body = `{"ekPublicKey":"e","platform":"linux","attestationKey":{"publicArea":"p","parentPublicArea":"q","qualifiedName":"n"},"futureField":{"a":[1]}}`
	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayEnrollJSON(context.Background(), json.RawMessage(body))
	if err != nil {
		t.Fatalf("RelayEnrollJSON: %v", err)
	}
	if res.Challenge == nil || res.Challenge.EnrollmentID != "enr-1" {
		t.Errorf("Challenge = %+v", res.Challenge)
	}
	var want map[string]any
	_ = json.Unmarshal([]byte(body), &want)
	if !reflect.DeepEqual(gotBody, want) {
		t.Errorf("relayed body = %v, want %v", gotBody, want)
	}

	for name, bad := range map[string]string{
		"flat TPM body": `{"ekPublicKey":"e","akPublicArea":"a","platform":"windows"}`,
		"not json":      `{`,
		"no platform":   `{"ekPublicKey":"e"}`,
	} {
		gotBody = nil
		_, err := c.RelayEnrollJSON(context.Background(), json.RawMessage(bad))
		if !errors.Is(err, ErrInvalidEnrollBlob) || gotBody != nil {
			t.Errorf("%s: err = %v (request sent = %v), want ErrInvalidEnrollBlob and no request", name, err, gotBody != nil)
		}
	}
}

// A macOS enrollment stays flat and answers with a nonce for the enclave key
// to sign.
func TestRelayEnroll_MacOS201(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"enrollmentId":   "enr-2",
			"challengeNonce": "bm9uY2U=",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	res, err := c.RelayEnroll(context.Background(), validMacOSEnrollBlob())
	if err != nil {
		t.Fatalf("RelayEnroll: %v", err)
	}
	if res.Challenge == nil || res.Challenge.EnrollmentID != "enr-2" || res.Challenge.ChallengeNonce != "bm9uY2U=" {
		t.Errorf("Challenge = %+v", res.Challenge)
	}
	if gotBody["ekPublicKey"] != "ZWtwdWI=" || gotBody["akPublicArea"] != "ZWtwdWI=" || gotBody["platform"] != "macos" {
		t.Errorf("relayed enroll body = %v", gotBody)
	}
	if _, present := gotBody["attestationKey"]; present {
		t.Errorf("macOS enroll body carried attestationKey")
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
	for _, k := range []string{"ekPublicKey", "akPublicArea", "attestationKey"} {
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

// Three shapes are accepted: the nested 8.0 TPM body, the flat macOS body and
// the iOS body. A flat TPM body is the 7.0 shape and is refused before any
// request, as is a body that carries both.
func TestRelayEnroll_ValidatesBlob(t *testing.T) {
	c, _ := NewClient("rh_sk_test_key", WithBaseURL("http://127.0.0.1:0"))
	ak := &AttestationKeyPublic{PublicArea: "p", ParentPublicArea: "q", QualifiedName: "n"}
	cases := []struct {
		name string
		blob EnrollRequestBlob
	}{
		{"empty", EnrollRequestBlob{}},
		{"unknown platform", EnrollRequestBlob{EkPublicKey: "x", AttestationKey: ak, Platform: "android"}},
		{"tpm flat 7.0 shape", EnrollRequestBlob{EkPublicKey: "x", AkPublicArea: "y", Platform: PlatformWindows}},
		{"tpm both shapes", EnrollRequestBlob{EkPublicKey: "x", AkPublicArea: "y", AttestationKey: ak, Platform: PlatformLinux}},
		{"tpm missing attestationKey", EnrollRequestBlob{EkPublicKey: "x", Platform: PlatformWindows}},
		{"tpm missing ek", EnrollRequestBlob{AttestationKey: ak, Platform: PlatformLinux}},
		{"tpm missing publicArea", EnrollRequestBlob{EkPublicKey: "x", AttestationKey: &AttestationKeyPublic{ParentPublicArea: "q", QualifiedName: "n"}, Platform: PlatformWindows}},
		{"tpm missing parentPublicArea", EnrollRequestBlob{EkPublicKey: "x", AttestationKey: &AttestationKeyPublic{PublicArea: "p", QualifiedName: "n"}, Platform: PlatformWindows}},
		{"tpm missing qualifiedName", EnrollRequestBlob{EkPublicKey: "x", AttestationKey: &AttestationKeyPublic{PublicArea: "p", ParentPublicArea: "q"}, Platform: PlatformWindows}},
		{"macos missing ak", EnrollRequestBlob{EkPublicKey: "x", Platform: PlatformMacOS}},
		{"macos missing ek", EnrollRequestBlob{AkPublicArea: "y", Platform: PlatformMacOS}},
		{"macos with attestationKey", EnrollRequestBlob{EkPublicKey: "x", AkPublicArea: "y", AttestationKey: ak, Platform: PlatformMacOS}},
		{"ios missing keyId", EnrollRequestBlob{Platform: PlatformIOS, IOSAttestationObject: "a", Nonce: "n"}},
		{"ios missing attestation", EnrollRequestBlob{Platform: PlatformIOS, IOSKeyID: "k", Nonce: "n"}},
		{"ios missing nonce", EnrollRequestBlob{Platform: PlatformIOS, IOSKeyID: "k", IOSAttestationObject: "a"}},
		{"ios with tpm fields only", EnrollRequestBlob{Platform: PlatformIOS, EkPublicKey: "x", AttestationKey: ak}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := c.RelayEnroll(context.Background(), tc.blob)
			if !errors.Is(err, ErrInvalidEnrollBlob) {
				t.Errorf("err = %v, want ErrInvalidEnrollBlob", err)
			}
		})
	}
	for _, ok := range []EnrollRequestBlob{validEnrollBlob(), validMacOSEnrollBlob(), validIOSEnrollBlob()} {
		if err := validateEnrollBlob(ok); err != nil {
			t.Errorf("%s blob refused: %v", ok.Platform, err)
		}
	}
}

func TestRelayEnroll_ErrorMapping(t *testing.T) {
	cases := []struct {
		status   int
		code     string
		sentinel error
	}{
		{http.StatusUnauthorized, "x", ErrInvalidSecretKey},
		{http.StatusBadRequest, "x", ErrInvalidEvidence},
		{http.StatusBadRequest, "wire_version_unsupported", ErrInvalidEvidence},
		{http.StatusBadRequest, "invalid_enroll_shape", ErrInvalidEvidence},
		{http.StatusTooManyRequests, "x", ErrRateLimited},
	}
	for _, tc := range cases {
		tc := tc
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(tc.status)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": tc.code, "message": "boom"})
		}))
		c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
		_, err := c.RelayEnroll(context.Background(), validEnrollBlob())
		if !errors.Is(err, tc.sentinel) {
			t.Errorf("status %d %q: err = %v, want %v", tc.status, tc.code, err, tc.sentinel)
		}
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.Code != tc.code {
			t.Errorf("status %d %q: APIError = %+v", tc.status, tc.code, apiErr)
		}
		srv.Close()
	}
}

func TestRelayActivate_Success(t *testing.T) {
	var gotAuth, gotPath string
	var gotRaw []byte
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotPath = r.URL.Path
		gotRaw, _ = io.ReadAll(r.Body)
		_ = json.Unmarshal(gotRaw, &gotBody)
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
	for _, k := range []string{"deviceId", "challengeId", "akPublicKey", "signature", "nitroAttestationDocument", "nitroDocumentError"} {
		if _, present := gotBody[k]; present {
			t.Errorf("activate body carried %q", k)
		}
	}
	// A body without the Nitro members posts exactly as before they existed:
	// no "" and no null in their place.
	if want := `{"enrollmentId":"enr-1","decryptedSecret":"c2VjcmV0"}`; string(gotRaw) != want {
		t.Errorf("relayed activate body = %s, want %s", gotRaw, want)
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
	for _, k := range []string{"decryptedSecret", "nitroAttestationDocument", "nitroDocumentError"} {
		if _, present := gotBody[k]; present {
			t.Errorf("macOS activate body carried %q", k)
		}
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
		// A Nitro document is evidence, not a proof: the secret is still required.
		{"nitro document without secret", decodeActivation(t, `{"enrollmentId":"enr-1","nitroAttestationDocument":"AAAA"}`)},
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

// decodeActivation decodes a client's activate body the way a customer backend
// receives it, before handing it to RelayActivate.
func decodeActivation(t *testing.T, body string) EnrollActivationResponse {
	t.Helper()
	var activation EnrollActivationResponse
	if err := json.Unmarshal([]byte(body), &activation); err != nil {
		t.Fatalf("decode activate body: %v", err)
	}
	return activation
}

// The Nitro members cross the relay as the client wrote them. The reordered
// error with an unknown member fails a relay that types the error's fields.
// Fixtures stay compact and free of <, > and &, which json.Marshal rewrites.
func TestRelayActivate_NitroMembersPassThrough(t *testing.T) {
	cases := []struct {
		name   string
		member string
		body   string
	}{
		{
			"document",
			"nitroAttestationDocument",
			`{"enrollmentId":"enr-1","decryptedSecret":"c2VjcmV0","nitroAttestationDocument":"hEShATgioFkBAqVp+/0="}`,
		},
		{
			"error",
			"nitroDocumentError",
			`{"enrollmentId":"enr-1","decryptedSecret":"c2VjcmV0","nitroDocumentError":{"stage":"nsm_request","tpmRc":323,"responseShape":"Error"}}`,
		},
		{
			"error reordered with unknown member",
			"nitroDocumentError",
			`{"enrollmentId":"enr-1","decryptedSecret":"c2VjcmV0","nitroDocumentError":{"responseShape":"Error","tpmRc":323,"stage":"nsm_request","detail":"x"}}`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var gotRaw []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotRaw, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]string{"deviceId": "dev-1", "status": "enrolled"})
			}))
			defer srv.Close()

			c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
			if _, err := c.RelayActivate(context.Background(), decodeActivation(t, tc.body)); err != nil {
				t.Fatalf("RelayActivate: %v", err)
			}

			var sent, posted map[string]json.RawMessage
			if err := json.Unmarshal([]byte(tc.body), &sent); err != nil {
				t.Fatalf("decode fixture: %v", err)
			}
			if err := json.Unmarshal(gotRaw, &posted); err != nil {
				t.Fatalf("decode posted body %s: %v", gotRaw, err)
			}
			if !bytes.Equal(posted[tc.member], sent[tc.member]) {
				t.Errorf("posted %s = %s, want %s", tc.member, posted[tc.member], sent[tc.member])
			}
		})
	}
}

// An unknown, spent or foreign enrollment and a wrong proof are refused alike
// with one 401 activation_refused, which is not an invalid key: the key was
// accepted before the action ran.
func TestRelayActivate_ErrorMapping(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"error": "activation_refused", "message": "Invalid credential activation response",
		})
	}))
	defer srv.Close()

	c, _ := NewClient("rh_sk_test_key", WithBaseURL(srv.URL))
	_, err := c.RelayActivate(context.Background(), EnrollActivationResponse{
		EnrollmentID: "enr-1", DecryptedSecret: "s",
	})
	if !errors.Is(err, ErrActivationRefused) || errors.Is(err, ErrInvalidSecretKey) {
		t.Errorf("err = %v, want ErrActivationRefused", err)
	}
}
