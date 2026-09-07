package rootherald

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"strings"
)

// VerifyKeySignature checks a signature made by a key RootHerald certified
// (AttestResult.Key.JWK) over message, with no call to RootHerald. The customer
// stores the JWK at attestation time and checks each later request locally.
//
// The signature is ECDSA over SHA-256(message) for P-256 and SHA-384(message)
// for P-384, in either the raw r||s form (64 or 96 bytes, as a TPM emits) or
// ASN.1 DER. It returns false for anything it cannot verify — an unsupported
// key, a point off the curve, or a malformed signature — and never panics.
func VerifyKeySignature(jwk JWK, message, signature []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()

	if jwk.Kty != "EC" {
		return false
	}
	var (
		curve  elliptic.Curve
		digest []byte
	)
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
		d := sha256.Sum256(message)
		digest = d[:]
	case "P-384":
		curve = elliptic.P384()
		d := sha512.Sum384(message)
		digest = d[:]
	default:
		return false
	}

	size := (curve.Params().BitSize + 7) / 8
	x, okX := decodeCoordinate(jwk.X, size)
	y, okY := decodeCoordinate(jwk.Y, size)
	if !okX || !okY {
		return false
	}
	pub := &ecdsa.PublicKey{Curve: curve, X: x, Y: y}
	// ECDH() rejects a point that is not on the curve (or is the identity),
	// which the deprecated IsOnCurve would otherwise be needed for.
	if _, err := pub.ECDH(); err != nil {
		return false
	}

	if len(signature) == 2*size {
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		if ecdsa.Verify(pub, digest, r, s) {
			return true
		}
	}
	return ecdsa.VerifyASN1(pub, digest, signature)
}

// decodeCoordinate decodes one base64url JWK coordinate of exactly size bytes.
// JWK coordinates are unpadded, but padding is tolerated.
func decodeCoordinate(s string, size int) (*big.Int, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil || len(raw) != size {
		return nil, false
	}
	return new(big.Int).SetBytes(raw), true
}
