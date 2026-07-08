package rootherald

import (
	"strings"
)

// Verdict is the result of an attestation check.
type Verdict string

const (
	VerdictAllow  Verdict = "allow"
	VerdictDeny   Verdict = "deny"
	VerdictReview Verdict = "review"
)

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
