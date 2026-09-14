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
// it and returns `evidence`. Keep chal.Nonce: it is your handle for the
// challenge.

// 2) Submit the opaque evidence the client returned and get a verdict.
res, err := client.Verify(ctx, evidence, rh.AttestOptions{Nonce: chal.Nonce})
if err != nil {
    // 401 invalid secret key, 422 unknown policy / admission refused, 409
    // nonce spent or expired, 400 evidence, 429 quota — use
    // errors.Is(err, rh.ErrUnknownPolicy) etc.
    http.Error(w, "attestation error", http.StatusBadGateway)
    return
}
if res.Verdict != rh.VerdictAllow {
    // An un-enrolled / failing device is a verdict, NOT an error; it carries
    // res.EnrollmentRequired.
    http.Error(w, "denied", http.StatusForbidden)
    return
}
```

`evidence` is `rootherald.Evidence` (a `json.RawMessage`), passed through to
RootHerald verbatim. Nothing in it names a device: the server finds the
challenge by the nonce and the device by the proof inside the evidence. The
raw `verdict` maps to the SDK enum as: `pass` → `VerdictAllow`, `fail` →
`VerdictDeny`, `warn`/unknown → `VerdictReview` (fail-closed).
`res.Device.UEID` is your tenant's alias for the device; it is for your
backend and must not be sent to the device.

## The challenge carries the ask

`IssueChallenge` asks for identity and posture. `IssueChallengeWithOptions`
sets the ask explicitly.

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; a posture ask runs under the posture
policy and everything else under the identity policy. The resolved policy is
pinned on the challenge when it is minted, and `Verify` appraises under it.
Change what a key enforces from the dashboard or
`PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a hand-built
request body is refused with `400 policy_bound_to_key`. `ErrUnknownPolicy`
(422 `unknown_policy`) means a policy bound to the key no longer exists;
nothing is substituted.

Asking for `AskKey` has the device create a TPM-resident signing key and
certify it with its attestation key. A passing verdict then carries the public
half as `res.Key`; store it against the user and check later requests locally,
with no call to RootHerald:

```go
chal, err := client.IssueChallengeWithOptions(ctx, rh.ChallengeOptions{
    Ask:        []rh.Ask{rh.AskIdentity, rh.AskKey},
    KeyPurpose: "sign",
})
res, err := client.Verify(ctx, evidence, rh.AttestOptions{Nonce: chal.Nonce})
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
helper relays them with the `rh_sk_` secret. Enrollment always issues a
challenge, including for a device already known — re-enrollment is how a device
rotates its attestation key — so every TPM or macOS enroll is followed by
activate:

```go
er, _ := client.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/attest/enroll
// relay er.Challenge to the client's EnrollComplete verbatim, then relay the result
act, _ := client.RelayActivate(ctx, activationResponse) // POST /api/v1/attest/activate
_ = act.DeviceID // your tenant's alias for the device; never send it to the device
```

`er.Challenge` names the open enrollment (`EnrollmentID`) and carries the
proof to answer: `CredentialBlob` + `EncryptedSecret` for a TPM,
`ChallengeNonce` for macOS. The client echoes `EnrollmentID` with its
`DecryptedSecret` or `Signature`. An iOS blob (`Platform: rh.PlatformIOS`)
enrolls in one leg: the 201 is empty and there is nothing to activate.

Admission runs under the identity policy bound to your API key, so a device
whose TPM class can never satisfy it is refused before it gets an attestation
key: `errors.Is(err, rh.ErrAdmissionRefused)`, with the class in
`APIError.Message`.

## Mobile users through the RootHerald bridge

App Attest is reachable only from a native app, so a browser page hands a
mobile user to the RootHerald bridge, which opens the companion app and
forwards its evidence to the backend URLs you registered. Render the link in
a real `<a href>` the user taps:

```go
href := rh.BuildMobileAttestLink("https://bridge.rootherald.io", chal.Challenge)
```

The bridge posts `{ nonce, evidence }` to your registered `appVerifyUrl`;
broker it exactly like desktop evidence and store the verdict keyed by the
nonce, which the page receives back as `returnUrl?nonce=<handle>`:

```go
var body rh.MobileAppVerifyRequest
_ = json.NewDecoder(req.Body).Decode(&body)
res, err := client.VerifyMobileEvidence(ctx, body)
```

A first-time device posts `{ nonce, enrollment }` (`rh.MobileAppEnrollRequest`)
to your registered `appEnrollUrl`; hand `body.Enrollment` to `RelayEnroll`.

See `examples/hello/` for a runnable end-to-end demo.
