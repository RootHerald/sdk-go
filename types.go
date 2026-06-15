package rootherald

import (
	"strings"
	"time"
)

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
	Subject    string    `json:"sub"`
	Issuer     string    `json:"iss"`
	Audience   []string  `json:"aud"`
	ExpiresAt  time.Time `json:"exp"`
	IssuedAt   time.Time `json:"iat,omitempty"`
	NotBefore  time.Time `json:"nbf,omitempty"`
	Nonce      string    `json:"eat_nonce,omitempty"`
	EATProfile string    `json:"eat_profile,omitempty"`
	// Verdict is the attestation verdict carried by the token, mapped from the
	// platform's raw "verdict" claim ("pass"/"fail"/"warn") to the SDK enum
	// (VerdictAllow/VerdictDeny/VerdictReview). If the token carries no verdict
	// claim it defaults to VerdictReview (fail-closed: an unrecognised token is
	// not silently treated as an allow).
	Verdict    Verdict                `json:"verdict"`
	Device     DeviceClaims           `json:"-"`
	Raw        map[string]interface{} `json:"-"`
}

// mapVerdict translates the platform's raw verdict vocabulary
// ("pass"/"fail"/"warn", as emitted by the attestation token's flat "verdict"
// claim) into the SDK Verdict enum. Unknown or empty values map to
// VerdictReview so an unrecognised token is never silently allowed.
func mapVerdict(raw string) Verdict {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "pass", "allow", "affirming":
		return VerdictAllow
	case "fail", "deny", "contraindicated":
		return VerdictDeny
	case "warn", "warning", "review":
		return VerdictReview
	default:
		return VerdictReview
	}
}

// VerifyResult bundles the verdict and the decoded claims returned by the verifier.
type VerifyResult struct {
	Verdict   Verdict           `json:"verdict"`
	Reason    string            `json:"reason,omitempty"`
	RiskScore float64           `json:"risk_score,omitempty"`
	Claims    AttestationClaims `json:"-"`
}
