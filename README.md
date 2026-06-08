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

## chi middleware

```go
import rhchi "github.com/RootHerald/sdk-go/chi"

r := chi.NewRouter()
r.Use(rhchi.Guard(rhchi.GuardConfig{
    Verifier: client.Verifier(), Action: "signup",
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
