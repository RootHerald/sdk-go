package rootherald

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// The envelope must be exactly what the device's whitelist parser opens: one
// header shape, the header as AAD, a fresh ephemeral key per call; and every
// key that cannot open it is refused before anything is encrypted.

var envelopePlaintext = []byte(`{"session":"s-1","exp":1893456000}`)

func decryptKey(alg, format string, jwk JWK) CertifiedKey {
	return CertifiedKey{DeviceID: "dev-alias", KeyID: "key-1", Purpose: KeyPurposeDecrypt, Alg: alg, Format: format, JWK: jwk, HardwareBound: true}
}

func ecDecryptKey(t *testing.T) (CertifiedKey, *ecdh.PrivateKey) {
	t.Helper()
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.PublicKey().Bytes()
	jwk := JWK{Kty: "EC", Crv: "P-256",
		X: base64.RawURLEncoding.EncodeToString(pub[1:33]),
		Y: base64.RawURLEncoding.EncodeToString(pub[33:])}
	return decryptKey(algECDHES, formatJWE, jwk), priv
}

func rsaDecryptKey(t *testing.T, bits int) (CertifiedKey, *rsa.PrivateKey) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return decryptKey(algRSAOAEP256, formatJWE, rsaJWKFor(&priv.PublicKey)), priv
}

func mustDecode(t *testing.T, s string) []byte {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64url %q: %v", s, err)
	}
	return raw
}

// ── ECDH-ES ─────────────────────────────────────────────────────────────────

func TestEncryptToDevice_EC_TwoEncryptionsDifferAndBothOpen(t *testing.T) {
	key, priv := ecDecryptKey(t)
	a, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two encryptions are byte-equal: the ephemeral key or IV is not fresh")
	}
	for _, jwe := range []string{a, b} {
		got, err := referenceOpen(jwe, priv, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, envelopePlaintext) {
			t.Fatalf("opened %q", got)
		}
	}
}

func TestEncryptToDevice_EC_HeaderIsExactlyAlgEncEpk(t *testing.T) {
	key, _ := ecDecryptKey(t)
	jwe, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwe, ".")
	if len(parts) != 5 {
		t.Fatalf("%d segments", len(parts))
	}
	header := string(mustDecode(t, parts[0]))
	var h struct {
		Alg string `json:"alg"`
		Enc string `json:"enc"`
		Epk struct {
			Kty, Crv, X, Y string
		} `json:"epk"`
	}
	dec := json.NewDecoder(strings.NewReader(header))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		t.Fatalf("header %s: %v", header, err)
	}
	want := fmt.Sprintf(`{"alg":"ECDH-ES","enc":"A256GCM","epk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}`, h.Epk.X, h.Epk.Y)
	if header != want {
		t.Fatalf("header is %s, want %s", header, want)
	}
	if len(mustDecode(t, h.Epk.X)) != 32 || len(mustDecode(t, h.Epk.Y)) != 32 {
		t.Fatal("epk coordinates are not 32 bytes")
	}
	if parts[1] != "" {
		t.Fatal("ECDH-ES carries an encrypted key segment")
	}
	if len(mustDecode(t, parts[2])) != 12 || len(mustDecode(t, parts[4])) != 16 {
		t.Fatal("iv is not 12 bytes or tag is not 16")
	}
	if len(mustDecode(t, parts[3])) != len(envelopePlaintext) {
		t.Fatal("ciphertext length")
	}
}

// ── RSA-OAEP-256 ────────────────────────────────────────────────────────────

func TestEncryptToDevice_RSA_TwoEncryptionsDifferAndBothOpen(t *testing.T) {
	key, priv := rsaDecryptKey(t, 2048)
	a, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	b, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Fatal("two encryptions are byte-equal")
	}
	for _, jwe := range []string{a, b} {
		got, err := referenceOpen(jwe, nil, priv, true)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, envelopePlaintext) {
			t.Fatalf("opened %q", got)
		}
	}
}

func TestEncryptToDevice_RSA_HeaderAndOAEPSHA256(t *testing.T) {
	key, priv := rsaDecryptKey(t, 2048)
	jwe, err := EncryptToDevice(key, envelopePlaintext)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(jwe, ".")
	if got := string(mustDecode(t, parts[0])); got != `{"alg":"RSA-OAEP-256","enc":"A256GCM"}` {
		t.Fatalf("header %s", got)
	}
	encryptedKey := mustDecode(t, parts[1])
	if len(encryptedKey) != 256 {
		t.Fatalf("encrypted key is %d bytes", len(encryptedKey))
	}
	cek, err := rsa.DecryptOAEP(sha256.New(), nil, priv, encryptedKey, nil)
	if err != nil || len(cek) != 32 {
		t.Fatalf("OAEP-SHA-256 unwrap: %v, %d bytes", err, len(cek))
	}
}

// ── AAD is the protected header ─────────────────────────────────────────────

func TestEncryptToDevice_HeaderEditedAfterSealingDoesNotOpen(t *testing.T) {
	ecKey, ecPriv := ecDecryptKey(t)
	rsaKey, rsaPriv := rsaDecryptKey(t, 2048)
	for _, tc := range []struct {
		key CertifiedKey
		ec  *ecdh.PrivateKey
		rsa *rsa.PrivateKey
	}{{ecKey, ecPriv, nil}, {rsaKey, nil, rsaPriv}} {
		jwe, err := EncryptToDevice(tc.key, envelopePlaintext)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(jwe, ".")
		// Equivalent JSON, different bytes: the AAD must be the bytes.
		edited := strings.Replace(string(mustDecode(t, parts[0])), `"enc":`, `"enc": `, 1)
		parts[0] = base64.RawURLEncoding.EncodeToString([]byte(edited))
		if _, err := referenceOpen(strings.Join(parts, "."), tc.ec, tc.rsa, false); err == nil {
			t.Fatalf("%s: an edited header still opened", tc.key.Alg)
		}
	}
}

// ── Refusals ────────────────────────────────────────────────────────────────

func TestEncryptToDevice_Refusals(t *testing.T) {
	ecKey, _ := ecDecryptKey(t)
	rsaKey, _ := rsaDecryptKey(t, 2048)
	shortRSA, _ := rsaDecryptKey(t, 1024)

	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p384Pub := p384.PublicKey().Bytes()
	p384Key := decryptKey(algECDHES, formatJWE, JWK{Kty: "EC", Crv: "P-384",
		X: base64.RawURLEncoding.EncodeToString(p384Pub[1:49]),
		Y: base64.RawURLEncoding.EncodeToString(p384Pub[49:])})

	offCurve := ecKey
	y := mustDecode(t, offCurve.JWK.Y)
	y[31] ^= 1
	offCurve.JWK.Y = base64.RawURLEncoding.EncodeToString(y)

	with := func(k CertifiedKey, f func(*CertifiedKey)) CertifiedKey { f(&k); return k }

	cases := []struct {
		name string
		key  CertifiedKey
		want error
	}{
		{"sign key", with(ecKey, func(k *CertifiedKey) { k.Purpose = KeyPurposeSign; k.Alg = "ES256"; k.Format = "" }), ErrInvalidArgument},
		{"sign key with a jwe format", with(ecKey, func(k *CertifiedKey) { k.Purpose = KeyPurposeSign; k.Alg = "ES256" }), ErrInvalidArgument},
		{"decrypt purpose with a sign alg", with(ecKey, func(k *CertifiedKey) { k.Alg = "ES256" }), ErrInvalidArgument},
		{"no format", with(ecKey, func(k *CertifiedKey) { k.Format = "" }), ErrInvalidArgument},
		{"apple-ecies", with(ecKey, func(k *CertifiedKey) { k.Format = "apple-ecies"; k.HardwareBound = false }), ErrEnvelopeFormatNotSupported},
		{"P-384", p384Key, ErrInvalidArgument},
		{"31-byte x", with(ecKey, func(k *CertifiedKey) { k.JWK.X = base64.RawURLEncoding.EncodeToString(make([]byte, 31)) }), ErrInvalidArgument},
		{"33-byte x", with(ecKey, func(k *CertifiedKey) { k.JWK.X = base64.RawURLEncoding.EncodeToString(make([]byte, 33)) }), ErrInvalidArgument},
		{"point off the curve", offCurve, ErrInvalidArgument},
		{"1024-bit modulus", shortRSA, ErrInvalidArgument},
		{"EC key with the RSA alg", with(ecKey, func(k *CertifiedKey) { k.Alg = algRSAOAEP256 }), ErrInvalidArgument},
		{"RSA key with the EC alg", with(rsaKey, func(k *CertifiedKey) { k.Alg = algECDHES }), ErrInvalidArgument},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := EncryptToDevice(tc.key, envelopePlaintext)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if out != "" {
				t.Fatal("a refused key still produced output")
			}
			if tc.want == ErrEnvelopeFormatNotSupported && !strings.Contains(err.Error(), "apple-ecies") {
				t.Fatalf("the refusal does not name the format: %v", err)
			}
		})
	}
}

// ── Determinism through the seam ────────────────────────────────────────────

func TestEncryptToDevice_SeamMakesTheEnvelopeReproducible(t *testing.T) {
	key, priv := ecDecryptKey(t)
	eph, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	seam := func() envelopeRandom {
		return envelopeRandom{
			ephemeral: func() (*ecdh.PrivateKey, error) { return eph, nil },
			bytes:     countingReader{},
		}
	}
	a, err := encryptToDevice(key, envelopePlaintext, seam())
	if err != nil {
		t.Fatal(err)
	}
	b, err := encryptToDevice(key, envelopePlaintext, seam())
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Fatal("the same ephemeral key and IV gave different envelopes")
	}
	if got, err := referenceOpen(a, priv, nil, true); err != nil || !bytes.Equal(got, envelopePlaintext) {
		t.Fatalf("open: %v %q", err, got)
	}
}

// countingReader yields 1, 2, 3, … so a seeded run is reproducible.
type countingReader struct{}

func (countingReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = byte(i + 1)
	}
	return len(p), nil
}

// referenceOpen is the device's parser in software: a whitelist over the
// header, fixed sizes, the header as AAD, and the same Concat KDF. With
// strict false the header members are not checked, so an edited header can
// be tried against the tag.
func referenceOpen(compact string, ec *ecdh.PrivateKey, rsaPriv *rsa.PrivateKey, strict bool) ([]byte, error) {
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		return nil, fmt.Errorf("%d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, err
	}
	var header map[string]json.RawMessage
	if err := json.Unmarshal(raw, &header); err != nil {
		return nil, err
	}
	var alg, enc string
	_ = json.Unmarshal(header["alg"], &alg)
	_ = json.Unmarshal(header["enc"], &enc)
	if enc != "A256GCM" {
		return nil, fmt.Errorf("enc %q", enc)
	}
	iv, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || len(iv) != 12 {
		return nil, errors.New("iv")
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(parts[3])
	if err != nil {
		return nil, err
	}
	tag, err := base64.RawURLEncoding.DecodeString(parts[4])
	if err != nil || len(tag) != 16 {
		return nil, errors.New("tag")
	}

	var cek []byte
	switch {
	case ec != nil:
		if strict && (len(header) != 3 || header["epk"] == nil) {
			return nil, fmt.Errorf("header members %v", header)
		}
		if alg != "ECDH-ES" || parts[1] != "" {
			return nil, errors.New("alg or encrypted key")
		}
		var epk map[string]string
		if err := json.Unmarshal(header["epk"], &epk); err != nil {
			return nil, err
		}
		if strict && len(epk) != 4 {
			return nil, fmt.Errorf("epk members %v", epk)
		}
		if epk["kty"] != "EC" || epk["crv"] != "P-256" {
			return nil, errors.New("epk")
		}
		x, errX := base64.RawURLEncoding.DecodeString(epk["x"])
		y, errY := base64.RawURLEncoding.DecodeString(epk["y"])
		if errX != nil || errY != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("epk coordinates")
		}
		pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, err
		}
		z, err := ec.ECDH(pub)
		if err != nil {
			return nil, err
		}
		cek = concatKDF(z)
	case rsaPriv != nil:
		if strict && len(header) != 2 {
			return nil, fmt.Errorf("header members %v", header)
		}
		if alg != "RSA-OAEP-256" {
			return nil, errors.New("alg")
		}
		encryptedKey, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			return nil, err
		}
		cek, err = rsa.DecryptOAEP(sha256.New(), nil, rsaPriv, encryptedKey, nil)
		if err != nil {
			return nil, err
		}
	default:
		return nil, errors.New("no recipient")
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, iv, append(ciphertext, tag...), []byte(parts[0]))
}

var _ io.Reader = countingReader{}
