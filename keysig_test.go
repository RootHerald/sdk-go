package rootherald

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"testing"
)

// jwkFor renders an EC public key the way the server does: unpadded base64url
// coordinates at the curve's full width.
func jwkFor(t *testing.T, pub *ecdsa.PublicKey, crv string) JWK {
	t.Helper()
	size := (pub.Curve.Params().BitSize + 7) / 8
	return JWK{
		Kty: "EC",
		Crv: crv,
		X:   base64.RawURLEncoding.EncodeToString(pub.X.FillBytes(make([]byte, size))),
		Y:   base64.RawURLEncoding.EncodeToString(pub.Y.FillBytes(make([]byte, size))),
	}
}

// rsaJWKFor renders an RSA public key as the server does: unpadded base64url
// big-endian modulus and exponent.
func rsaJWKFor(pub *rsa.PublicKey) JWK {
	return JWK{
		Kty: "RSA",
		N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

// rawSig signs digest and returns the fixed-width r||s form a TPM emits.
func rawSig(t *testing.T, priv *ecdsa.PrivateKey, digest []byte) []byte {
	t.Helper()
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		t.Fatal(err)
	}
	size := (priv.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*size)
	r.FillBytes(out[:size])
	s.FillBytes(out[size:])
	return out
}

func TestVerifyKeySignature_P256_DERAndRaw(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkFor(t, &priv.PublicKey, "P-256")
	msg := []byte(`{"action":"transfer","amount":100,"nonce":"n1"}`)
	digest := sha256.Sum256(msg)

	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKeySignature(jwk, msg, der) {
		t.Error("DER signature rejected")
	}

	raw := rawSig(t, priv, digest[:])
	if len(raw) != 64 {
		t.Fatalf("raw sig len = %d, want 64", len(raw))
	}
	if !VerifyKeySignature(jwk, msg, raw) {
		t.Error("raw r||s signature rejected")
	}

	// Padded coordinates are tolerated.
	padded := jwk
	padded.X = base64.URLEncoding.EncodeToString(priv.PublicKey.X.FillBytes(make([]byte, 32)))
	if !VerifyKeySignature(padded, msg, der) {
		t.Error("padded base64url coordinate rejected")
	}
}

// RS256 is PKCS#1 v1.5 over SHA-256, with a signature of exactly the modulus
// length.
func TestVerifyKeySignature_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	jwk := rsaJWKFor(&priv.PublicKey)
	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 256 {
		t.Fatalf("sig len = %d, want 256", len(sig))
	}
	if !VerifyKeySignature(jwk, msg, sig) {
		t.Error("RS256 signature rejected")
	}

	padded := jwk
	padded.E = base64.URLEncoding.EncodeToString(big.NewInt(int64(priv.E)).Bytes())
	if !VerifyKeySignature(padded, msg, sig) {
		t.Error("padded base64url exponent rejected")
	}

	if VerifyKeySignature(jwk, []byte("tampered"), sig) {
		t.Error("tampered message accepted")
	}
	flipped := append([]byte(nil), sig...)
	flipped[10] ^= 0x01
	if VerifyKeySignature(jwk, msg, flipped) {
		t.Error("corrupted signature accepted")
	}
	if VerifyKeySignature(jwk, msg, sig[:255]) {
		t.Error("short signature accepted")
	}
	if VerifyKeySignature(jwk, msg, append(append([]byte(nil), sig...), 0)) {
		t.Error("long signature accepted")
	}

	pss, err := rsa.SignPSS(rand.Reader, priv, crypto.SHA256, digest[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyKeySignature(jwk, msg, pss) {
		t.Error("PSS signature accepted as RS256")
	}

	other, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyKeySignature(rsaJWKFor(&other.PublicKey), msg, sig) {
		t.Error("signature accepted under a different key")
	}

	bad := jwk
	bad.E = ""
	if VerifyKeySignature(bad, msg, sig) {
		t.Error("missing exponent accepted")
	}
	bad = jwk
	bad.E = "AQ"
	if VerifyKeySignature(bad, msg, sig) {
		t.Error("exponent 1 accepted")
	}
	bad = jwk
	bad.N = "!!not base64!!"
	if VerifyKeySignature(bad, msg, sig) {
		t.Error("undecodable modulus accepted")
	}
	bad = jwk
	bad.E = base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 9))
	if VerifyKeySignature(bad, msg, sig) {
		t.Error("oversized exponent accepted")
	}
}

// A modulus below 2048 bits is refused, whatever the signature.
func TestVerifyKeySignature_RSAShortModulus(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	sig, err := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if VerifyKeySignature(rsaJWKFor(&priv.PublicKey), msg, sig) {
		t.Error("1024-bit modulus accepted")
	}
}

// Only the curve a device certifies is verified: a P-384 key is refused even
// with a valid signature.
func TestVerifyKeySignature_P384Refused(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkFor(t, &priv.PublicKey, "P-384")
	msg := []byte("hello")
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if VerifyKeySignature(jwk, msg, der) {
		t.Error("P-384 key accepted")
	}
	if VerifyKeySignature(jwk, msg, rawSig(t, priv, digest[:])) {
		t.Error("P-384 raw signature accepted")
	}
}

func TestVerifyKeySignature_Negatives(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkFor(t, &priv.PublicKey, "P-256")
	msg := []byte("original")
	digest := sha256.Sum256(msg)
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	raw := rawSig(t, priv, digest[:])

	if VerifyKeySignature(jwk, []byte("tampered"), der) {
		t.Error("tampered message accepted (DER)")
	}
	if VerifyKeySignature(jwk, []byte("tampered"), raw) {
		t.Error("tampered message accepted (raw)")
	}

	flipped := append([]byte(nil), raw...)
	flipped[10] ^= 0x01
	if VerifyKeySignature(jwk, msg, flipped) {
		t.Error("corrupted raw signature accepted")
	}

	if VerifyKeySignature(jwkFor(t, &other.PublicKey, "P-256"), msg, der) {
		t.Error("signature accepted under a different key")
	}

	for name, sig := range map[string][]byte{
		"empty":         {},
		"nil":           nil,
		"garbage":       []byte("not a signature at all, definitely not DER"),
		"truncated der": der[:len(der)/2],
		"zero raw":      make([]byte, 64),
		"all-ff raw":    bytes.Repeat([]byte{0xff}, 64),
		"short raw":     raw[:63],
		"long raw":      append(append([]byte(nil), raw...), 0),
	} {
		if VerifyKeySignature(jwk, msg, sig) {
			t.Errorf("%s signature accepted", name)
		}
	}

	// Key problems: wrong type, unknown curve, curve mismatch, off-curve point,
	// wrong-width coordinate, undecodable coordinate, RSA fields on an EC key.
	bad := jwk
	bad.Kty = "RSA"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("kty=RSA with EC coordinates accepted")
	}
	bad = jwk
	bad.Kty = "oct"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("kty=oct accepted")
	}
	bad = jwk
	bad.Crv = "secp256k1"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("unknown curve accepted")
	}
	bad = jwk
	bad.Crv = "P-384"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("P-256 coordinates under crv=P-384 accepted")
	}
	bad = jwk
	y := new(big.Int).Add(priv.PublicKey.Y, big.NewInt(1))
	bad.Y = base64.RawURLEncoding.EncodeToString(y.FillBytes(make([]byte, 32)))
	if VerifyKeySignature(bad, msg, der) {
		t.Error("off-curve point accepted")
	}
	bad = jwk
	bad.X = base64.RawURLEncoding.EncodeToString(priv.PublicKey.X.Bytes()[:31])
	if VerifyKeySignature(bad, msg, der) {
		t.Error("short coordinate accepted")
	}
	bad = jwk
	bad.X = "!!not base64!!"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("undecodable coordinate accepted")
	}
	if VerifyKeySignature(JWK{}, msg, der) {
		t.Error("zero JWK accepted")
	}
}
