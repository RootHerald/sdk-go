# Root Herald — Go SDK

Backend SDK for verifying [Root Herald](https://rootherald.io) device attestation JWTs from Go services. Includes `net/http`, `chi`, and `gin` middleware.

## Install

```bash
go get github.com/RootHerald/sdk-go
```

## 30-second integration

```go
package main

import (
    "log"
    "net/http"

    rootherald "github.com/RootHerald/sdk-go"
    rhchi "github.com/RootHerald/sdk-go/chi"
    "github.com/go-chi/chi/v5"
)

func main() {
    client, err := rootherald.NewClient(
        rootherald.WithIssuer("https://api.rootherald.io"),
        rootherald.WithAudience("plat_your_client_id"),
    )
    if err != nil {
        log.Fatal(err)
    }

    r := chi.NewRouter()
    r.Use(rhchi.RequireAttestation(client))

    r.Get("/me", func(w http.ResponseWriter, req *http.Request) {
        verdict := rootherald.FromContext(req.Context())
        w.Write([]byte("device: " + verdict.Device.DeviceID))
    })

    http.ListenAndServe(":8080", r)
}
```

## What you get

- `rootherald.NewClient(...)` — handles JWKS fetch + caching automatically
- `client.Verify(ctx, token)` — verifies a token, returns a strongly-typed `AttestationVerdict`
- `rhchi.RequireAttestation` — chi router middleware
- `rhgin.RequireAttestation` — gin middleware (in `github.com/RootHerald/sdk-go/gin`)
- `rootherald.FromContext(ctx)` — typed access to the verdict from inside a handler

## Trust chain

The SDK fetches Root Herald's signing keys from `{issuer}/.well-known/jwks.json` and caches them (default 1 hour). Tokens are verified locally — no per-request call to Root Herald. Key rotation is handled automatically.

## License

MIT. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
