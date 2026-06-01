package rootherald

import "time"

// Verdict is the result of an attestation check.
type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictDeny   Verdict = "deny"
	VerdictReview Verdict = "review"
)

// DeviceClaims holds the device-scoped subset of an attestation token.
type DeviceClaims struct {
	UEID     string `json:"ueid,omitempty"`
	HWModel  string `json:"hwmodel,omitempty"`
	Dbgstat  string `json:"dbgstat,omitempty"`
	EARState int    `json:"ear_status,omitempty"`
}

// AttestationClaims is the decoded RootHerald attestation token.
type AttestationClaims struct {
	Subject    string                 `json:"sub"`
	Issuer     string                 `json:"iss"`
	Audience   []string               `json:"aud"`
	ExpiresAt  time.Time              `json:"exp"`
	IssuedAt   time.Time              `json:"iat,omitempty"`
	NotBefore  time.Time              `json:"nbf,omitempty"`
	Nonce      string                 `json:"eat_nonce,omitempty"`
	EATProfile string                 `json:"eat_profile,omitempty"`
	Device     DeviceClaims           `json:"-"`
	Raw        map[string]interface{} `json:"-"`
}

// VerifyResult bundles the verdict and the decoded claims returned by the verifier.
type VerifyResult struct {
	Verdict   Verdict           `json:"verdict"`
	Reason    string            `json:"reason,omitempty"`
	RiskScore float64           `json:"risk_score,omitempty"`
	Claims    AttestationClaims `json:"-"`
}
