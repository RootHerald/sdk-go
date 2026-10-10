package rootherald

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"strings"
)

// minRSAModulusBits is the smallest RSA key a device certifies.
const minRSAModulusBits = 2048

// VerifyKeySignature checks a signature made by a key RootHerald certified
// (CertifiedKey.JWK) over message, with no call to RootHerald. The customer
// stores the JWK at certification and checks each later request locally.
//
// An EC P-256 key checks ES256: ECDSA over SHA-256(message), in either the
// raw r||s form (64 bytes, as a TPM emits) or ASN.1 DER. An RSA key checks
// RS256: PKCS#1 v1.5 over SHA-256(message), with a modulus of at least 2048
// bits and a signature of exactly the modulus length (256 bytes for
// RSA-2048).
//
// A signature proves possession of the key at that moment, not how the
// machine booted; run an attest challenge for that.
//
// It returns false for anything it cannot verify — an unsupported key, a
// point off the curve, a short modulus, or a malformed signature — and never
// panics: a verifier that can panic is a verifier that can be made to skip a
// check.
func VerifyKeySignature(jwk JWK, message, signature []byte) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if len(signature) == 0 {
		return false
	}
	digest := sha256.Sum256(message)
	switch jwk.Kty {
	case "EC":
		return verifyES256(jwk, digest[:], signature)
	case "RSA":
		return verifyRS256(jwk, digest[:], signature)
	}
	return false
}

func verifyES256(jwk JWK, digest, signature []byte) bool {
	if jwk.Crv != "P-256" {
		return false
	}
	curve := elliptic.P256()
	size := (curve.Params().BitSize + 7) / 8
	x, okX := decodeFixed(jwk.X, size)
	y, okY := decodeFixed(jwk.Y, size)
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
		return ecdsa.Verify(pub, digest, r, s)
	}
	return ecdsa.VerifyASN1(pub, digest, signature)
}

func verifyRS256(jwk JWK, digest, signature []byte) bool {
	n, okN := decodeBase64URL(jwk.N)
	e, okE := decodeBase64URL(jwk.E)
	if !okN || !okE || len(n) == 0 || len(e) == 0 || len(e) > 4 {
		return false
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < minRSAModulusBits || pub.E < 3 {
		return false
	}
	if len(signature) != pub.Size() {
		return false
	}
	return rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest, signature) == nil
}

// decodeFixed decodes one base64url JWK coordinate of exactly size bytes.
func decodeFixed(s string, size int) (*big.Int, bool) {
	raw, ok := decodeBase64URL(s)
	if !ok || len(raw) != size {
		return nil, false
	}
	return new(big.Int).SetBytes(raw), true
}

// decodeBase64URL decodes an unpadded base64url JWK parameter; padding is
// tolerated.
func decodeBase64URL(s string) ([]byte, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	if err != nil {
		return nil, false
	}
	return raw, true
}
