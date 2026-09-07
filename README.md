# rootherald-go

Server-side Go SDK for RootHerald device attestation.

**Background-Check (server → server)** via `Client`: your dumb client
collects an opaque evidence blob and hands it to *your* server, which appraises
it with RootHerald using your `rh_sk_` secret key. The client never holds a key
or talks to RootHerald.

```bash
go get github.com/RootHerald/sdk-go
```

## Quick start: Background-Check (server → server)

```go
import rh "github.com/RootHerald/sdk-go"

// Construct once with your SECRET key (rh_sk_…). Any key without the rh_sk_
// prefix is rejected.
client, err := rh.NewClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
if err != nil {
    log.Fatal(err)
}

// 1) Mint a challenge and send it down to the dumb client.
chal, err := client.IssueChallenge(ctx, "" /* optional deviceHint */)
// relay chal.Challenge to the client verbatim; it quotes over the nonce inside
// it and returns `evidence`.

// 2) Submit the opaque evidence the client returned and get a verdict.
res, err := client.Verify(ctx, evidence, rh.AttestOptions{
    ChallengeID: chal.ChallengeID,
    Policy:      "rootherald:builtin:strict-hardware", // optional
})
if err != nil {
    // 401 invalid secret key, 422 unknown policy / policy downgrade, 409
    // challenge, 400 evidence, 429 quota — use errors.Is(err, rh.ErrUnknownPolicy) etc.
    http.Error(w, "attestation error", http.StatusBadGateway)
    return
}
if res.Verdict != rh.VerdictAllow {
    // An un-enrolled / failing device is a verdict, NOT an error.
    http.Error(w, "denied", http.StatusForbidden)
    return
}
```

`evidence` is `rootherald.Evidence` (a `json.RawMessage`), passed through to
RootHerald verbatim. The raw `verdict` maps to the SDK enum as: `pass` →
`VerdictAllow`, `fail` → `VerdictDeny`, `warn`/unknown → `VerdictReview`
(fail-closed).

## The challenge carries the ask

`IssueChallenge` asks for identity and posture. `IssueChallengeWithOptions`
sets the ask explicitly and can pin the policy the challenge will be appraised
under; a `Verify` that later names a weaker policy fails with
`ErrPolicyDowngrade`.

Asking for `AskKey` has the device create a TPM-resident signing key and
certify it with its attestation key. A passing verdict then carries the public
half as `res.Key`; store it against the user and check later requests locally,
with no call to RootHerald:

```go
chal, err := client.IssueChallengeWithOptions(ctx, rh.ChallengeOptions{
    Ask:        []rh.Ask{rh.AskIdentity, rh.AskKey},
    KeyPurpose: "sign",
})
res, err := client.Verify(ctx, evidence, rh.AttestOptions{ChallengeID: chal.ChallengeID})
if err == nil && res.Verdict == rh.VerdictAllow && res.Key != nil {
    store(userID, res.Key.KeyID, res.Key.JWK) // P-256 or P-384 public key
}

// On a later request the device signed with that key. The signature is ECDSA
// over SHA-256(message) (SHA-384 for P-384), raw r||s or DER; a malformed one
// is false, never a panic.
if !rh.VerifyKeySignature(jwk, message, signature) {
    http.Error(w, "signature rejected", http.StatusForbidden)
    return
}
```

## One-time device enroll (backend-relayed)

The client emits opaque `EnrollBegin()` / `EnrollComplete()` blobs; this backend
helper relays them with the `rh_sk_` secret. Enrolment always issues a
challenge, including for a device already known — re-enrolment is how a device
rotates its attestation key — so every enroll is followed by activate:

```go
er, _ := client.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/attest/enroll
// hand er.Challenge to the client's EnrollComplete, then relay the result
act, _ := client.RelayActivate(ctx, activationResponse) // POST /api/v1/attest/activate
_ = act.DeviceID
```

`RelayEnrollWithChallenge(ctx, blob, chal.ChallengeID)` admits the device
against that challenge's policy instead of the tenant default, so a device
whose TPM class can never satisfy it is refused before it gets an attestation
key: `errors.Is(err, rh.ErrAdmissionRefused)`, with the class in
`APIError.Message`.

See `examples/hello/` for a runnable end-to-end demo.
