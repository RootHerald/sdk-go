package rootherald

import "errors"

// Sentinel errors. Use errors.Is to switch on them.
var (
	ErrTokenExpired     = errors.New("rootherald: token expired")
	ErrIssuerMismatch   = errors.New("rootherald: issuer mismatch")
	ErrAudienceMismatch = errors.New("rootherald: audience mismatch")
	ErrSignature        = errors.New("rootherald: signature invalid")
	ErrUnknownKID       = errors.New("rootherald: unknown key id")
	ErrUnsupportedAlg   = errors.New("rootherald: unsupported algorithm")
	ErrWebhookSig       = errors.New("rootherald: webhook signature invalid")
	ErrJwksUnavailable  = errors.New("rootherald: jwks unavailable")
	ErrVerifierHTTP     = errors.New("rootherald: verifier http error")
)
