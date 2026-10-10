# Changelog

## 0.3.0

Wire 8.0. Every installation of a client has its own attestation key, created
inside the TPM at enrollment and handed back as an opaque AK blob the client
keeps and passes to every attest and mint. Keys are minted in their own
ceremony. A backend on this version cannot drive a 7.0 client, and the
reverse; the server refuses a 7.0-shaped enroll body with
`400 wire_version_unsupported`.

### Breaking

- `RelayEnroll` takes the 8.0 TPM body: `EkPublicKey` plus
  `AttestationKey *AttestationKeyPublic{PublicArea, ParentPublicArea,
  QualifiedName}`, and refuses a TPM body carrying a top-level `AkPublicArea`
  (the 7.0 shape) with `ErrInvalidEnrollBlob` before any request.
  `AkPublicArea` is macOS only; the macOS body stays flat and the iOS body is
  unchanged. `RelayEnrollJSON(ctx, json.RawMessage)` relays the client's JSON
  byte-for-byte, unknown fields included.
- Keys are minted by `IssueKeyChallenge(ctx, KeyChallengeOptions{Purpose,
  ExpectedDevices})` → `CertifyKey(ctx, nonce, certification)` →
  `CertifiedKey{DeviceID, KeyID, Purpose, Alg, Format, JWK, HardwareBound,
  CertifiedAt}`. `AskKey`, `ChallengeOptions.KeyPurpose`, `AttestResult.Key`
  and `CertifiedKey.AuthPolicy` are removed; a challenge that still asks for
  `"key"` is `ErrInvalidAsk` (400 `invalid_ask`), told apart from
  `ErrInvalidEvidence`.
- `IssueChallenge(ctx)` takes no `deviceHint`, and `ChallengeOptions` has no
  `DeviceHint`; it has `ExpectedKey` and `ExpectedDevices`. Pass the same
  values in `AttestOptions`: a verdict that does not echo them under
  `AttestResult.Expected` is `ErrExpectedNotEnforced`. A non-nil empty
  `ExpectedDevices`, or one with a blank alias, is `ErrInvalidArgument`.
- `JWK` is an EC P-256 key (`Crv`, `X`, `Y`) or an RSA-2048 key (`N`, `E`).
  `VerifyKeySignature` checks ES256 (raw `r||s` or DER) and RS256 (PKCS#1 v1.5
  over SHA-256, modulus of at least 2048 bits, signature of exactly the
  modulus length); P-384 is refused, since no device certifies one.
- `VerifyMobileEvidence`, `RelayMobileEnrollment`, `BuildMobileAttestLink`,
  `IOSAttestation`, `MobileAppEnrollRequest` and `MobileAppVerifyRequest` are
  removed with the mobile bridge.
- `DeviceVerdict` declares every field the server sends; the optional
  booleans and counts are pointers, nil when omitted.
- A 429 `budget_exhausted` is `ErrQuotaExceeded` with `APIError.Budget{ID,
  Name}`; the `quota_exceeded` code is gone. A 409 `key_rotation_conflict` is
  `ErrAttestHTTP` with the code preserved, not `ErrChallenge`.

### Migration

1. Re-enroll every installation: the client's `EnrollBegin` now returns an
   AK blob, which the client keeps and passes to `Attest` and `MintKey`.
2. Replace `IssueChallengeWithOptions(ctx, ChallengeOptions{Ask:
   []Ask{AskIdentity, AskKey}, KeyPurpose: "sign"})` plus `res.Key` with
   `IssueKeyChallenge(ctx, KeyChallengeOptions{Purpose: KeyPurposeSign,
   ExpectedDevices: []string{alias}})` and `CertifyKey(ctx, kc.Nonce,
   certification)`.
3. Drop the `deviceHint` argument of `IssueChallenge`; bind a challenge to a
   device with `ExpectedDevices`.
4. Replace `errors.Is(err, ErrQuotaExceeded)` checks that read
   `quota_exceeded` from `APIError.Code` with `budget_exhausted`, and read
   `APIError.Budget` for the budget that refused.
5. Delete any mobile-bridge handler.

## 0.2.0

### Breaking

- `Verdict` is the server's own token: `VerdictPass` / `VerdictWarn` /
  `VerdictFail` (`"pass"` / `"warn"` / `"fail"`) replace `VerdictAllow` /
  `VerdictReview` / `VerdictDeny`, the same vocabulary as every other
  RootHerald SDK. A response carrying any other token is `ErrAttestHTTP`
  instead of `VerdictReview`.
- `AttestResult.Key` is passed through as the server sent it; it is no longer
  nilled on a non-passing verdict. The server withholds it when it must.
- An empty `AttestOptions.Nonce` (and an empty nonce on
  `VerifyMobileEvidence`) is `ErrInvalidArgument`, not `ErrChallenge`; no
  request is made.
- A 401 carrying `activation_refused` is `ErrActivationRefused`, not
  `ErrInvalidSecretKey`. A 429 without `quota_exceeded` or an
  `X-RootHerald-Quota` header is `ErrRateLimited`, with
  `APIError.RetryAfterSeconds`, not `ErrQuotaExceeded`. A 422 whose code is
  neither `unknown_policy` nor `admission_refused` (`posture_not_bound`) is
  `ErrAttestHTTP` with the code preserved, not `ErrUnknownPolicy`.
- The default `http.Client` timeout is 30 s (`DefaultTimeout`), was 10 s.

### Additive

- `RelayMobileEnrollment(ctx, MobileAppEnrollRequest)` relays a bridge
  `{nonce, enrollment}` body after checking the envelope nonce equals the
  one inside the blob.
- `CertifiedKey.AuthPolicy` is documented as hex, which is what the server
  sends.

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
