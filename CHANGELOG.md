# Changelog

## Unreleased

### Breaking

- Wire 7.0: nothing a client sends locates a row. `Challenge` is
  `{Nonce, Challenge, ExpiresAt}`; `ChallengeID` is gone and `Nonce` is the
  backend's handle. `AttestOptions.ChallengeID` is `AttestOptions.Nonce` and
  the verify request carries `nonce`; a missing one is still `ErrChallenge`.
  `IssueChallenge` requires the `challenge` string on the response.
- `RelayEnroll` sends no query string and `RelayEnrollWithChallenge` is gone.
  `RelayEnrollResult` is `{Challenge}` only; the 201 body no longer carries a
  `deviceId`. `EnrollActivationChallenge` is
  `{EnrollmentID, CredentialBlob?, EncryptedSecret?, ChallengeNonce?}`; a TPM
  or macOS 201 must carry `enrollmentId` and one proof, and an iOS blob
  (`PlatformIOS`) accepts an empty 201.
- `EnrollActivationResponse` is `{EnrollmentID, DecryptedSecret?, Signature?}`;
  `DeviceID` and `AkPublicKey` are gone. `RelayActivate` requires
  `EnrollmentID` and one of `DecryptedSecret` / `Signature`.
  `RelayActivateResponse` is unchanged and its `DeviceID` is the tenant's
  alias, for the backend only.
- Policies bind to API keys. `AttestOptions.Policy` is gone and the SDK never
  sends a `policy` field on the challenge or verify request; the server
  refuses the field with `400 policy_bound_to_key`. The key carries an
  identity policy and, on Pro, a posture policy; the resolved policy is
  pinned on the challenge at mint. Bind a policy to the key from the
  dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`.
- `ErrUnknownPolicy` (422 `unknown_policy`) now means a policy bound to the
  key no longer exists; nothing is substituted. Enrollment admission runs
  under the key's identity policy.

### Additive

- The challenge carries the ask. `IssueChallengeWithOptions` takes
  `ChallengeOptions{Ask, KeyPurpose, DeviceHint}`; `Ask` is
  `AskIdentity` / `AskPosture` / `AskKey`. `IssueChallenge` still sends no ask,
  which the server reads as identity + posture. `Challenge.Challenge` is the
  `rhc1.` string to relay to the client verbatim.
- `AttestResult.Key` (`*CertifiedKey`: `KeyID`, `JWK`, `Purpose`,
  `AuthPolicy`, `CertifiedAt`) is the signing key a passing verdict certified
  when the challenge asked for `AskKey`; nil otherwise.
- `VerifyKeySignature(jwk, message, signature)` checks a device's signature
  locally, ECDSA over SHA-256/SHA-384 for P-256/P-384, raw `r||s` or DER.
  Returns false for anything it cannot verify; never panics. Standard library
  only.
- `EnrollRequestBlob` carries every platform's EnrollBegin body: `TpmSelfReport`
  for a TPM, and `PlatformIOS` with `IOSKeyID`, `IOSAttestationObject`, `Nonce`
  for App Attest. `RelayEnroll` validates the fields the platform requires.
- Mobile bridge: `BuildMobileAttestLink(bridgeBaseURL, challenge)` renders the
  Universal Link, `VerifyMobileEvidence(ctx, MobileAppVerifyRequest{Nonce,
  Evidence})` brokers the bridge's forward (`iosAttestation.{assertion,keyId}`)
  as a `Verify` under its nonce, and `MobileAppEnrollRequest{Nonce, Enrollment}`
  models the enroll forward.
- New sentinel `ErrAdmissionRefused` (422 `admission_refused`), told apart
  from `ErrUnknownPolicy` by the server's error code. The refused TPM class
  is in `APIError.Message`.
- Package doc and README no longer show an `AlreadyEnrolled` branch; that
  field was removed with the 409 short-circuit and the snippet did not compile.

## 0.1.0

Initial release.
