// Package rootherald is the server-side SDK for verifying RootHerald attestation tokens
// and CAEP webhook Security Event Tokens.
//
// RootHerald uses the IETF RATS Passport Model: the device collects evidence (TPM quote,
// Secure Enclave attestation, …), the RootHerald verifier produces an EAT-flavoured JWT,
// and your application checks that token here before granting access.
//
// Quick start:
//
//	client := rootherald.NewClient("https://rootherald.io",
//	    rootherald.WithIssuer("rootherald.io/myorg"),
//	    rootherald.WithAudience("my-app"),
//	)
//	verdict, claims, err := client.Verify(ctx, token)
//	if err != nil || verdict != rootherald.VerdictAllow {
//	    http.Error(w, "attestation rejected", http.StatusUnauthorized)
//	    return
//	}
//	log.Printf("device %s allowed", claims.Subject)
package rootherald
