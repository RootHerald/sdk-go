# Changelog

## Unreleased

### Breaking

- Policies bind to API keys. `AttestOptions.Policy` is gone and the SDK never
  sends a `policy` field on the challenge or verify request; the server
  refuses the field with `400 policy_bound_to_key`. The key carries an
  identity policy and, on Pro, a posture policy; the resolved policy is
  pinned on the challenge at mint. Bind a policy to the key from the
  dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`.
- `ErrUnknownPolicy` (422 `unknown_policy`) now means a policy bound to the
  key no longer exists; nothing is substituted. Enrollment admission runs
  under the key's identity policy, pinned on the challenge when
  `RelayEnrollWithChallenge` names one.

### Additive

Existing calls keep their shape and behaviour.

- The challenge carries the ask. `IssueChallengeWithOptions` takes
  `ChallengeOptions{Ask, KeyPurpose, DeviceHint}`; `Ask` is
  `AskIdentity` / `AskPosture` / `AskKey`. `IssueChallenge` still sends no ask,
  which the server reads as identity + posture. `Challenge` gains `Challenge`,
  the `rhc1.` string to relay to the client verbatim; `Nonce` stays.
- `AttestResult.Key` (`*CertifiedKey`: `KeyID`, `JWK`, `Purpose`,
  `AuthPolicy`, `CertifiedAt`) is the signing key a passing verdict certified
  when the challenge asked for `AskKey`; nil otherwise.
- `VerifyKeySignature(jwk, message, signature)` checks a device's signature
  locally, ECDSA over SHA-256/SHA-384 for P-256/P-384, raw `r||s` or DER.
  Returns false for anything it cannot verify; never panics. Standard library
  only.
- `RelayEnrollWithChallenge(ctx, blob, challengeID)` pins admission to the
  policy on a live challenge (`?challengeId=` on the enroll request).
  `EnrollActivationChallenge` gains `ChallengeID`.
- New sentinel `ErrAdmissionRefused` (422 `admission_refused`), told apart
  from `ErrUnknownPolicy` by the server's error code. The refused TPM class
  is in `APIError.Message`.
- Package doc and README no longer show an `AlreadyEnrolled` branch; that
  field was removed with the 409 short-circuit and the snippet did not compile.

## 0.1.0

Initial release.
