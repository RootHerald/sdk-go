# rootherald-go

Server-side Go SDK for RootHerald device attestation.

**Background-Check (server → server)** via `AttestClient`: your dumb client
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
client, err := rh.NewAttestClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
if err != nil {
    log.Fatal(err)
}

// 1) Mint a relay-friendly nonce and send it down to the dumb client.
chal, err := client.IssueChallenge(ctx, "" /* optional deviceHint */)
// relay chal.Nonce to the client; it quotes over it and returns `evidence`.

// 2) Submit the opaque evidence the client returned and get a verdict.
res, err := client.Verify(ctx, evidence, rh.AttestOptions{
    ChallengeID: chal.ChallengeID,
    Policy:      "rootherald:builtin:strict-hardware", // optional
})
if err != nil {
    // 401 invalid secret key, 422 unknown policy, 409 challenge, 400 evidence,
    // 429 quota — use errors.Is(err, rh.ErrUnknownPolicy) etc.
    http.Error(w, "attestation error", http.StatusBadGateway)
    return
}
if res.Verdict != rh.VerdictAllow {
    // An un-enrolled / failing device is a verdict, NOT an error.
    http.Error(w, "denied", http.StatusForbidden)
    return
}
```

> `IssueChallenge` / `Verify` are the ABI 2.0 names; `CreateChallenge` / `Attest`
> remain as deprecated aliases.

`evidence` is `rootherald.Evidence` (a `json.RawMessage`), passed through to
RootHerald verbatim. The raw `verdict` maps to the SDK enum as: `pass` →
`VerdictAllow`, `fail` → `VerdictDeny`, `warn`/unknown → `VerdictReview`
(fail-closed).

## One-time device enroll (backend-relayed)

The client emits opaque `EnrollBegin()` / `EnrollComplete()` blobs; this backend
helper relays them with the `rh_sk_` secret:

```go
er, _ := client.RelayEnroll(ctx, enrollRequestBlob) // POST /api/v1/devices/enroll
if er.AlreadyEnrolled {
    // device already bound; skip activate, just use er.DeviceID
} else {
    // hand er.Challenge to the client's EnrollComplete, then relay the result
    act, _ := client.RelayActivate(ctx, activationResponse) // POST /api/v1/devices/activate
    _ = act.DeviceID
}
```

See `examples/hello/` for a runnable end-to-end demo.
