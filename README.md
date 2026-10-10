# rootherald-go

Server-side Go SDK for RootHerald device attestation.

Wire 8.0 from `v0.3.0`. A 7.0 client cannot enroll against an 8.0 server;
see the [CHANGELOG](./CHANGELOG.md) for the migration.

**Backend relay (server → server).** The user's client does local TPM work and
hands your server opaque blobs (no keys, no RootHerald contact). Your server
relays those blobs to RootHerald with `Client`, authenticated by your `rh_sk_`
secret key. The verdict is computed by RootHerald and returned to *your
backend*; it never travels through the client.

**Three ceremonies, two calls each.**

- `client.RelayEnroll(ctx, blob)` / `client.RelayActivate(ctx, activation)`:
  enroll an installation (`POST /api/v1/attest/enroll`, `/activate`).
- `client.IssueKeyChallenge(ctx, KeyChallengeOptions{Purpose, ExpectedDevices})` /
  `client.CertifyKey(ctx, nonce, certification)`: mint a device-bound key
  (`POST /api/v1/keys/challenge`, `/certify`).
- `client.IssueChallenge(ctx)` or
  `client.IssueChallengeWithOptions(ctx, ChallengeOptions{Ask, ExpectedKey, ExpectedDevices})` /
  `client.Verify(ctx, evidence, AttestOptions{Nonce, RequestedDisclosureClass, ExpectedKey, ExpectedDevices})`:
  attest (`POST /api/v1/attest/challenge`, `/verify`).
- `VerifyKeySignature(jwk, message, signature)`: check a signature from a
  certified key locally, with the standard library only.

**The challenge carries the ask.** What the device is asked to prove is fixed
when you issue the challenge, bound to it server-side, and echoed to the client
inside the `Challenge` string. `Verify` appraises against that stored ask, so
nothing between the two calls can widen or weaken it.

```bash
go get github.com/RootHerald/sdk-go
```

The secret key is **required** and must start with `rh_sk_`; any other value is
rejected. The base URL defaults to the production RootHerald API and must be
`https` (loopback excepted). The module has no dependencies.

## Enroll an installation

Each installation of your client enrolls once. The client's `EnrollBegin`
creates an attestation key (AK) inside the TPM and returns an opaque AK blob
alongside the enroll body; the client keeps the blob and passes it to every
later attest and mint. Windows needs one elevation per enrollment.

```go
import rh "github.com/RootHerald/sdk-go"

client, err := rh.NewClient(os.Getenv("ROOTHERALD_SECRET_KEY")) // rh_sk_…

// Leg 1: relay the client's EnrollBegin() body. Admission runs under the
// key's identity policy, so a device that could never satisfy it is refused
// before it gets an attestation key.
er, err := client.RelayEnrollJSON(ctx, enrollBody) // the client's JSON, byte-for-byte

// Hand er.Challenge (the 201 body) to the client's EnrollComplete(), which
// returns an activation response; relay it to finish binding.
act, err := client.RelayActivate(ctx, activationResponse)
// act.DeviceID is this tenant's alias for the device. Keep it here; do not
// send it back to the client.
```

`RelayEnrollJSON` relays the device's JSON unchanged; `RelayEnroll` takes the
typed `EnrollRequestBlob`. Both accept the nested TPM body
(`EkPublicKey` + `AttestationKey{PublicArea, ParentPublicArea, QualifiedName}`),
the flat macOS body (`EkPublicKey` + `AkPublicArea`) and the iOS body, and
refuse a flat TPM body, the wire 7.0 shape, with `ErrInvalidEnrollBlob` before
any request.

The alias is the device's only identity: a new AK, a new key, a re-enrollment
or a TPM clear never changes it. Bind accounts to it. An iOS enrollment has
nothing to activate: its `Challenge` marshals to `{}` and there is no second
leg.

When to enroll:

- The client has no AK blob: enroll first.
- The client's attest or mint reports the AK blob unloadable (TPM cleared,
  parent changed): discard the blob, enroll, retry once.
- `Verify` answers `EnrollmentRequired: true`: enroll.

## Attest

```go
// 1. Mint a challenge. Relay chal.Challenge to the client; keep chal.Nonce.
chal, err := client.IssueChallengeWithOptions(ctx, rh.ChallengeOptions{
    Ask: []rh.Ask{rh.AskIdentity},
})

// 2. The client's Attest answers with an opaque `evidence` blob. Appraise it.
res, err := client.Verify(ctx, evidence, rh.AttestOptions{Nonce: chal.Nonce})
if err != nil {
    // 401 invalid secret key / activation refused, 422 unknown policy /
    // admission refused, 409 nonce spent or expired, 400 evidence, 429 budget
    // / rate limited — use errors.Is(err, rh.ErrUnknownPolicy) etc.
    http.Error(w, "attestation error", http.StatusBadGateway)
    return
}
if res.Verdict != rh.VerdictPass {
    // An un-enrolled / failing device is a verdict, NOT an error; it carries
    // res.EnrollmentRequired.
    http.Error(w, "denied", http.StatusForbidden)
    return
}
alias := res.Device.UEID // bind the session to it
```

`evidence` is `rh.Evidence` (a `json.RawMessage`), passed through to
RootHerald verbatim. Nothing in it names a device: the server finds the
challenge by the nonce and the device by the proof inside the evidence.
`res.Verdict` is the server's own token, `VerdictPass` / `VerdictWarn` /
`VerdictFail`; a response carrying anything else is `ErrAttestHTTP`, never a
guessed verdict.

`IssueChallenge(ctx)` asks for identity and posture. A posture ask runs under
the key's posture policy and checks the boot configuration; use it for
step-up, with `res.AssuranceClaimsMet` listing the policy claims the device
satisfied.

**Name the device that must answer.** `ExpectedDevices` takes aliases you
enrolled, `ExpectedKey` a `KeyID` you certified; any other device answers a
failing verdict with reason `expected_device_mismatch`, and an unknown value is
`422 expected_unknown`. Pass the same values to `Verify`: the verdict echoes
what the server enforced under `res.Expected`, and `Verify` refuses a verdict
that does not echo it (`ErrExpectedNotEnforced`).

```go
chal, err := client.IssueChallengeWithOptions(ctx, rh.ChallengeOptions{
    Ask:             []rh.Ask{rh.AskIdentity},
    ExpectedDevices: []string{session.DeviceID},
})
res, err := client.Verify(ctx, evidence, rh.AttestOptions{
    Nonce:           chal.Nonce,
    ExpectedDevices: []string{session.DeviceID},
})
```

Policies bind to your API key, not to calls. Change what a key enforces from
the dashboard; a `policy` field in a hand-built request body is refused with
`400 policy_bound_to_key`.

## Device-bound signing keys

A key is created inside the chip and certified by the installation's AK; you
get its public half, the device keeps the blob. A signature on a request then
proves the request came from that device, and you check it with no
RootHerald call.

```go
// 1. Mint a key challenge for the device that just passed an attest
//    challenge. Relay kc.KeyChallenge to the client; keep kc.Nonce.
kc, err := client.IssueKeyChallenge(ctx, rh.KeyChallengeOptions{
    Purpose:         rh.KeyPurposeSign,
    ExpectedDevices: []string{res.Device.UEID},
})

// 2. The client's MintKey answers with a `certification` and keeps its key
//    blob. Relay the certification verbatim.
key, err := client.CertifyKey(ctx, kc.Nonce, certification)
saveDeviceKey(key.DeviceID, key.KeyID, key.JWK)

// Later, without any RootHerald call: the client signed `message` with its
// key and sent {message, signature}.
jwk := loadDeviceKey(session.DeviceID)
if !rh.VerifyKeySignature(jwk, message, signature) {
    http.Error(w, "signature rejected", http.StatusForbidden)
    return
}
```

`CertifyKey` returns a `CertifiedKey`:

```go
key.DeviceID      // string — the alias of the device that holds the key
key.KeyID         // string — RootHerald's id for the key
key.Purpose       // KeyPurposeSign | KeyPurposeDecrypt
key.Alg           // "ES256" | "RS256" | "ECDH-ES" | "RSA-OAEP-256"
key.Format        // "jwe" | "apple-ecies" | "" — decrypt keys only
key.JWK           // {Kty: "EC", Crv: "P-256", X, Y} or {Kty: "RSA", N, E}
key.HardwareBound // bool — false on macOS, where only possession is proved
key.CertifiedAt   // time.Time
```

Keys are P-256 or RSA-2048, chosen by the device. A signature proves which
chip signed, not how the machine booted; run an attest challenge for that.

Minting again for the same purpose rotates the key under the same `KeyID`; a
re-enrolled installation gets new key IDs. The key ID identifies an
installation's credential, never a device: bind accounts to the alias.

`VerifyKeySignature(jwk, message, signature)` takes the signed bytes and the
raw signature. ES256: a 64-byte signature is read as `r || s`, any other
length as DER. RS256: PKCS#1 v1.5 over SHA-256, a modulus of at least 2048
bits, and a signature of exactly the modulus length (256 bytes). It returns
`false` and never panics on malformed input.

## Errors

An un-enrolled or failing device is a verdict, not an error. Only protocol,
auth and budget problems return one, as an `*APIError` (with `StatusCode`,
the server's `Code` and `Message`) wrapping a sentinel for `errors.Is`:

| Status | Server `error` code                                  | Sentinel               |
| ------ | ---------------------------------------------------- | ---------------------- |
| 401    | `activation_refused`                                 | `ErrActivationRefused` |
| 401    | anything else                                        | `ErrInvalidSecretKey`  |
| 400    | `invalid_ask`                                        | `ErrInvalidAsk`        |
| 400    | anything else, including `wire_version_unsupported`, `invalid_enroll_shape` | `ErrInvalidEvidence` |
| 409    | `key_rotation_conflict`                              | `ErrAttestHTTP`        |
| 409    | anything else                                        | `ErrChallenge`         |
| 422    | `unknown_policy`, or none                            | `ErrUnknownPolicy`     |
| 422    | `admission_refused`                                  | `ErrAdmissionRefused`  |
| 422    | `expected_unknown`, `key_disclosure_too_low`         | `ErrAttestHTTP`        |
| 429    | `budget_exhausted`, or an `X-RootHerald-Quota` header | `ErrQuotaExceeded` (`APIError.Budget`) |
| 429    | anything else                                        | `ErrRateLimited`       |

`ErrActivationRefused` is `RelayActivate` being refused for an unknown, spent
or foreign `EnrollmentID` or a wrong proof; the secret key was accepted.
`ErrInvalidAsk` is a programming error in your backend, not a device failure.
`ErrRateLimited` is the request-rate limiter, with `APIError.RetryAfterSeconds`
from `Retry-After` (else the body, else 0); `ErrQuotaExceeded` is the budget
ceiling, with `APIError.Budget` naming the budget that refused. Any other
status, and a code no sentinel covers (`posture_not_bound`, `plan_lapsed`), is
`ErrAttestHTTP` with `APIError.Code` preserved. Input the SDK refuses locally,
such as an empty `Nonce` or a certification that is none of the platform
shapes, is `ErrInvalidArgument` and makes no request; a malformed enroll body
is `ErrInvalidEnrollBlob`.

A response whose `verdict.device.verdict` is not `pass`/`warn`/`fail`, or whose
certified key is malformed, is `ErrAttestHTTP` rather than returned
half-parsed. A verdict that does not echo the `ExpectedKey` / `ExpectedDevices`
you passed to `Verify` is `ErrExpectedNotEnforced`.

Every request times out after 30 s (`rh.DefaultTimeout`) unless
`WithHTTPClient` supplies a client with its own `Timeout`. The default is the
same in every RootHerald server SDK.

## The verdict shape

`Verify` returns an `AttestResult`. `res.Device` is the typed
`verdict.device` object with every field the server sends; fields gated by
disclosure class are nil or empty below it, and the API key's ceiling (default
`pseudonymous`) caps what `RequestedDisclosureClass` can ask for. `res.Raw`
is the whole verdict object as decoded.

```go
res.Verdict             // VerdictPass | VerdictWarn | VerdictFail
res.Expected            // *ExpectedBinding{Key, Devices} — what the server enforced
res.AssuranceClaimsMet  // []string — from the response root
res.EnrollmentRequired  // bool — from the response root

res.Device.UEID                  // string — the alias (pseudonymous+)
res.Device.DisclosureClass       // "verdict" | "pseudonymous" | "derived" | "full"
res.Device.EARStatus             // string
res.Device.AttestationType       // string, e.g. "tpm20"
res.Device.AttestedAt            // string, ISO 8601
res.Device.QuoteVerified         // *bool
res.Device.SecureBootVerified    // *bool
res.Device.EventLogVerified      // *bool
res.Device.PostureEvaluated      // *bool
res.Device.Platform              // string
res.Device.TpmKind               // "discrete-tpm" | "firmware-tpm" | …
res.Device.HardwareGenuine       // *bool
res.Device.SybilResistance       // "distinct-silicon" | …
res.Device.ReturningDevice       // *bool
res.Device.BootChanged           // *bool
res.Device.BootChangedStages     // []int
res.Device.TrustworthinessVector // *TrustworthinessVector
```

See `examples/hello/` for a runnable end-to-end demo.
