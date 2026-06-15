# rootherald-go

Server-side Go SDK for verifying RootHerald attestation tokens and CAEP webhook
Security Event Tokens.

```bash
go get github.com/RootHerald/sdk-go
```

## Quick start

```go
import rh "github.com/RootHerald/sdk-go"

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
verdict the token carries. The platform's raw `verdict` claim maps to the SDK
enum as: `pass` → `VerdictAllow`, `fail` → `VerdictDeny`, `warn` →
`VerdictReview`. A missing or unrecognised verdict maps to `VerdictReview`
(fail-closed), so always check the returned `Verdict` — a token with a valid
signature can still carry a non-allow verdict.

> **Note:** verification is offline (JWKS) only. There is no hosted
> `POST /api/v1/verify` endpoint; the `VerifyOnline` method targets a
> self-hosted verification service and will not work against the stock
> RootHerald deployment.

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
