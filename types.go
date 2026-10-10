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

// ExpectedBinding is what the challenge bound the verdict to, echoed by the
// server after it enforced it. Verify compares it with what the caller asked
// for and refuses a verdict that does not echo it, so a server that ignored
// the binding cannot pass silently.
type ExpectedBinding struct {
	// Key is the ExpectedKey the challenge named.
	Key string `json:"key,omitempty"`
	// Devices is the ExpectedDevices the challenge named.
	Devices []string `json:"devices,omitempty"`
}

// TrustworthinessVector is the AR4SI trustworthiness vector. Each dimension:
// 0 = unknown, 1 = warning, 2 = affirming.
type TrustworthinessVector struct {
	InstanceIdentity int `json:"instanceIdentity,omitempty"`
	Configuration    int `json:"configuration,omitempty"`
	Executables      int `json:"executables,omitempty"`
	FileSystem       int `json:"fileSystem,omitempty"`
	Hardware         int `json:"hardware,omitempty"`
	RuntimeOpaque    int `json:"runtimeOpaque,omitempty"`
	SourcedData      int `json:"sourcedData,omitempty"`
	StorageOpaque    int `json:"storageOpaque,omitempty"`
}

// DeviceVerdict is the typed view of the Background-Check verify response's
// verdict.device object: every field the server sends. Fields gated by a
// disclosure class are omitted when the applied class is lower, and the
// cohort fields only arrive when a quote-bound event log was supplied, so an
// optional field is a pointer or omitempty and stays nil/empty when the server
// did not return it. Cohort fields are advisory only, never a trust gate.
type DeviceVerdict struct {
	// UEID is this tenant's alias for the device: HMAC(tenant salt, device),
	// so two tenants observing one machine receive uncorrelated values.
	// Omitted below pseudonymous. It is for the backend only and must not
	// reach the device.
	UEID string `json:"ueid,omitempty"`
	// DisclosureClass is the class actually applied: min(requested, key ceiling).
	DisclosureClass string `json:"disclosureClass,omitempty"`
	EARStatus       string `json:"earStatus,omitempty"`
	Verdict         string `json:"verdict,omitempty"`
	AttestationType string `json:"attestationType,omitempty"`
	// AttestedAt is the ISO 8601 timestamp of the appraisal.
	AttestedAt string `json:"attestedAt,omitempty"`

	QuoteVerified      *bool `json:"quoteVerified,omitempty"`
	SecureBootVerified *bool `json:"secureBootVerified,omitempty"`
	EventLogVerified   *bool `json:"eventLogVerified,omitempty"`
	// PostureEvaluated reports whether boot state was checked at all; false on
	// an identity-only challenge.
	PostureEvaluated *bool `json:"postureEvaluated,omitempty"`
	// PostureSkippedReason is "plan_lapsed" when a posture policy could not
	// ask for posture.
	PostureSkippedReason string `json:"postureSkippedReason,omitempty"`
	Platform             string `json:"platform,omitempty"`
	HardwareModel        string `json:"hardwareModel,omitempty"`
	// TpmKind is the kind of root of trust: discrete-tpm | firmware-tpm |
	// cloud-vtpm | mobile-hardware | mobile-software | emulated | unknown.
	TpmKind string `json:"tpmKind,omitempty"`
	// ChipAnchorId is experimental, off by default: a rotation-resistant
	// identity keyed on the per-chip ODCA intermediate.
	ChipAnchorId string `json:"chipAnchorId,omitempty"`
	// IdentityAnchor is what UEID is anchored to: ek or odca-chip-intermediate.
	IdentityAnchor        string                 `json:"identityAnchor,omitempty"`
	TrustworthinessVector *TrustworthinessVector `json:"trustworthinessVector,omitempty"`
	// HardwareGenuine is true if the root of trust is genuine hardware silicon.
	HardwareGenuine *bool `json:"hardwareGenuine,omitempty"`
	// EkChainTrusted is true when the root of trust was proved at enrollment
	// (EK chain or platform attestation).
	EkChainTrusted *bool `json:"ekChainTrusted,omitempty"`
	// SybilRisk is the derived Sybil posture: none | elevated.
	SybilRisk string `json:"sybilRisk,omitempty"`
	// SybilResistance is how farmable this device's attested identity is,
	// strongest to weakest: distinct-silicon | distinct-silicon-rotatable |
	// per-instance | per-key.
	SybilResistance string `json:"sybilResistance,omitempty"`
	// ReturningDevice is true if this hardware identity has been seen before.
	ReturningDevice *bool `json:"returningDevice,omitempty"`
	// IdentityAgeBucket is a coarse identity-age band, e.g. new | under-7d |
	// under-90d | over-90d. Pseudonymous and above.
	IdentityAgeBucket string `json:"identityAgeBucket,omitempty"`
	// AccountBindingBand is a coarse per-tenant binding-count band, e.g. 1 |
	// 2-3 | 4-10 | 10+. Pseudonymous and above.
	AccountBindingBand string `json:"accountBindingBand,omitempty"`
	// IdentityFirstSeen is the ISO 8601 timestamp this hardware identity was
	// first seen. Derived and above.
	IdentityFirstSeen string `json:"identityFirstSeen,omitempty"`
	// AttestationCount is the attestations for this identity in your tenant,
	// including this one. Derived and above.
	AttestationCount *int64 `json:"attestationCount,omitempty"`
	// AccountBindingCount is the distinct enrollments of this device into
	// your tenant. Derived and above.
	AccountBindingCount *int64 `json:"accountBindingCount,omitempty"`
	// PossiblyRotated is true when the silicon appears to have rotated its EK
	// and re-enrolled.
	PossiblyRotated *bool `json:"possiblyRotated,omitempty"`
	// IdentitiesOnAnchor is the distinct identities this device's chip anchor
	// produced inside the policy's rotation window.
	IdentitiesOnAnchor *int64 `json:"identitiesOnAnchor,omitempty"`
	// PlatformRotated is true when this device has attested from a different
	// OS than it first enrolled from.
	PlatformRotated *bool `json:"platformRotated,omitempty"`
	// PlatformRotationsInWindow is the OS switches inside the policy's
	// rotation window.
	PlatformRotationsInWindow *int64 `json:"platformRotationsInWindow,omitempty"`
	// BootChanged is true when a watched boot stage differs from the accepted
	// boot set.
	BootChanged *bool `json:"bootChanged,omitempty"`
	// BootChangedStages lists the PCR indices that differ. Present with
	// BootChanged.
	BootChangedStages []int `json:"bootChangedStages,omitempty"`
	// BootChangeAccepted is true when the change fell inside the maintenance
	// window and became the new baseline.
	BootChangeAccepted *bool `json:"bootChangeAccepted,omitempty"`
	// BootBaselineAt is the ISO 8601 timestamp the accepted boot set was
	// first seen. Present with BootChanged.
	BootBaselineAt string `json:"bootBaselineAt,omitempty"`

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
