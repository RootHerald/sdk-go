package rootherald

import (
	"strings"
)

// Verdict is the result of an attestation check: the server's own
// verdict.device.verdict token, the same vocabulary in every RootHerald SDK.
type Verdict string

const (
	// VerdictPass: the device satisfied the policy.
	VerdictPass Verdict = "pass"
	// VerdictWarn: the device passed with reduced assurance; the policy says
	// whether to proceed.
	VerdictWarn Verdict = "warn"
	// VerdictFail: the device did not satisfy the policy, or is not enrolled
	// (see AttestResult.EnrollmentRequired).
	VerdictFail Verdict = "fail"
)

// DeviceVerdict is the typed view of the Background-Check verify response's
// verdict.device object. Cohort fields are ADDITIVE and advisory only (never a
// trust gate); the server populates them when a quote-bound event log was
// supplied and omits them otherwise — hence the pointer/omitempty fields, which
// stay nil/absent when the server did not return them.
type DeviceVerdict struct {
	// UEID is this tenant's alias for the device, absent when the device is
	// not enrolled. It is for the backend only and must not reach the device.
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

// parseVerdict reads the verdict.device.verdict token. Anything outside the
// three values the server emits is refused (ok == false) rather than mapped,
// so a token the SDK does not understand is never silently passed.
func parseVerdict(raw string) (Verdict, bool) {
	switch v := Verdict(strings.ToLower(strings.TrimSpace(raw))); v {
	case VerdictPass, VerdictWarn, VerdictFail:
		return v, true
	default:
		return "", false
	}
}
