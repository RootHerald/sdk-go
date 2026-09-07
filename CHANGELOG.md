# Changelog

## Unreleased

Additive. Existing calls keep their shape and behaviour.

- The challenge carries the ask. `IssueChallengeWithOptions` takes
  `ChallengeOptions{Ask, Policy, KeyPurpose, DeviceHint}`; `Ask` is
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
- `RelayEnrollWithChallenge(ctx, blob, challengeID)` admits against the
  challenge's policy (`?challengeId=` on the enroll request).
  `EnrollActivationChallenge` gains `ChallengeID`.
- New sentinels `ErrPolicyDowngrade` (422 `policy_downgrade`) and
  `ErrAdmissionRefused` (422 `admission_refused`), told apart from
  `ErrUnknownPolicy` by the server's error code. The refused TPM class is in
  `APIError.Message`.
- Package doc and README no longer show an `AlreadyEnrolled` branch; that
  field was removed with the 409 short-circuit and the snippet did not compile.

## 0.1.0

Initial release.
