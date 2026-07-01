# rootherald-go

Server-side Go SDK for RootHerald device attestation. Two paths:

- **Background-Check (server → server)** — `AttestClient`: your dumb client
  collects an opaque evidence blob and hands it to *your* server, which appraises
  it with RootHerald using your `rh_sk_` secret key. The client never holds a
  key or talks to RootHerald.
- **Badge tier (offline verify)** — `Client.Verify` + chi/gin middleware:
  verify a RootHerald-issued EAT (JWT) against the issuer's JWKS, no network call
  once warm. Also verifies CAEP webhook Security Event Tokens.

```bash
go get github.com/RootHerald/sdk-go
```

## Quick start — Background-Check (server → server)

```go
import rh "github.com/RootHerald/sdk-go"

// Construct once with your SECRET key (rh_sk_…). A publishable key (rh_pk_…)
// is rejected — it must never be used server-side.
client, err := rh.NewAttestClient(os.Getenv("ROOTHERALD_SECRET_KEY"))
if err != nil {
    log.Fatal(err)
}

// 1) Mint a relay-friendly nonce and send it down to the dumb client.
chal, err := client.CreateChallenge(ctx, "" /* optional deviceHint */)
// relay chal.Nonce to the client; it quotes over it and returns `evidence`.

// 2) Submit the opaque evidence the client returned and get a verdict.
res, err := client.Attest(ctx, evidence, rh.AttestOptions{
    ChallengeID: chal.ChallengeID,
    Policy:      "rootherald:builtin:strict-hardware", // optional
    ReturnToken: true,                                 // optional signed EAT
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
// res.Token (when ReturnToken) is a signed EAT, verifiable offline with Verify.
```

`evidence` is `rootherald.Evidence` (a `json.RawMessage`) — passed through to
RootHerald verbatim. The raw `verdict` maps to the SDK enum as: `pass` →
`VerdictAllow`, `fail` → `VerdictDeny`, `warn`/unknown → `VerdictReview`
(fail-closed).

## Quick start — Badge tier (offline verify)

```go
client := rh.NewClient("https://rootherald.io",
    rh.WithIssuer("rootherald.io/myorg"),
    rh.WithAudience("my-app"),
)

verdict, claims, err := client.Verify(ctx, token)
if err != nil || verdict != rh.VerdictAllow {
    http.Error(w, "denied", http.StatusUnauthorized)
    return
}
log.Printf("device %s allowed", claims.Subject)
```

`Verify` checks the token offline against the issuer's JWKS and returns the
verdict the token carries (same mapping as above; always check the returned
`Verdict` — a structurally valid token can still carry a non-allow verdict).

> **Note:** the legacy `Client.VerifyOnline` is deprecated. It targets a
> self-hosted `{verdict, reason, risk_score}` service and does not exist on the
> stock RootHerald deployment — use `AttestClient` for the server → server path
> and `Verify` for offline badge checks.

## chi middleware

```go
import rhchi "github.com/RootHerald/sdk-go/chi"

r := chi.NewRouter()
r.Use(rhchi.Guard(rhchi.GuardConfig{
    Verifier: client.Verifier(), Action: "signup",
    // Accepted verdicts (default ["allow"]); a verified token whose verdict
    // is not in this set is rejected with 403.
    Verdicts: []string{"allow"},
}))
```

## gin middleware

```go
import rhgin "github.com/RootHerald/sdk-go/gin"

r := gin.Default()
r.POST("/signup", rhgin.Guard(rhgin.GuardConfig{Verifier: client.Verifier()}), signupHandler)
```

## Webhooks

```go
v := rh.NewWebhookVerifier(
    "https://rootherald.io/myorg",
    "tenant-1",
    "https://rootherald.io/.well-known/jwks.json",
)
event, err := v.Verify(string(reqBody))
```

See `examples/hello/` for a runnable end-to-end demo.
