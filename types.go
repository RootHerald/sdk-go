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

// DeviceVerdict is the typed view of the Background-Check verify response's
// verdict.device object. Cohort fields are ADDITIVE and advisory only (never a
// trust gate); the server populates them when a quote-bound event log was
// supplied and omits them otherwise — hence the pointer/omitempty fields, which
// stay nil/absent when the server did not return them.
type DeviceVerdict struct {
	UEID            string `json:"ueid,omitempty"`
	EARStatus       string `json:"earStatus,omitempty"`
	Verdict         string `json:"verdict,omitempty"`
	AttestationType string `json:"attestationType,omitempty"`

	// CohortKey identifies the cohort this device was bucketed into.
	CohortKey *string `json:"cohortKey,omitempty"`
	// CohortScope is the cohort comparison scope ("global" | "tenant-fleet").
	CohortScope *string `json:"cohortScope,omitempty"`
	// CohortPrevalence is the fraction of the cohort sharing this profile (nil if unknown).
	CohortPrevalence *float64 `json:"cohortPrevalence,omitempty"`
	// CohortPrevalencePerPcr maps a PCR index to its prevalence fraction.
	CohortPrevalencePerPcr map[string]float64 `json:"cohortPrevalencePerPcr,omitempty"`
	// CohortSampleSize is the number of devices in the cohort sample (nil if unknown).
	CohortSampleSize *int64 `json:"cohortSampleSize,omitempty"`
	// NovelProfile reports whether this is a previously-unseen profile (nil if not evaluated).
	NovelProfile *bool `json:"novelProfile,omitempty"`
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
