package rootherald

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"math/big"
	"testing"
)

// jwkFor renders a public key the way the server does: unpadded base64url
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

func TestVerifyKeySignature_P384_DERAndRaw(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk := jwkFor(t, &priv.PublicKey, "P-384")
	msg := []byte("hello")
	digest := sha512.Sum384(msg)

	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyKeySignature(jwk, msg, der) {
		t.Error("P-384 DER signature rejected")
	}
	raw := rawSig(t, priv, digest[:])
	if len(raw) != 96 {
		t.Fatalf("raw sig len = %d, want 96", len(raw))
	}
	if !VerifyKeySignature(jwk, msg, raw) {
		t.Error("P-384 raw signature rejected")
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
	// wrong-width coordinate, undecodable coordinate.
	bad := jwk
	bad.Kty = "RSA"
	if VerifyKeySignature(bad, msg, der) {
		t.Error("kty=RSA accepted")
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
