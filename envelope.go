package rootherald

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/big"
)

// ErrEnvelopeFormatNotSupported is EncryptToDevice refusing a key whose
// Format it cannot produce: "apple-ecies", the Security.framework ECIES
// envelope a macOS enclave key opens, needs an Apple-side encryptor.
var ErrEnvelopeFormatNotSupported = errors.New("rootherald: envelope format not supported")

const (
	algECDHES     = "ECDH-ES"
	algRSAOAEP256 = "RSA-OAEP-256"
	encA256GCM    = "A256GCM"
	formatJWE     = "jwe"

	envelopeCoordinateBytes = 32
	envelopeIVBytes         = 12
	envelopeTagBytes        = 16
	envelopeCEKBytes        = 32
)

// EncryptToDevice encrypts plaintext so that only the device holding key
// can open it, with no call to RootHerald. The result is the JWE compact
// serialization the client's RootHeraldDecrypt accepts: ECDH-ES with a fresh
// ephemeral P-256 key per call for an EC key, RSA-OAEP-256 for an RSA key,
// A256GCM for both, with the protected header as the additional data.
//
// Encryption uses the public half, so anyone holding the JWK can encrypt to
// the device; what the chip guarantees is that only it can open the result.
// The key must be a decrypt key (KeyPurposeDecrypt) with Format "jwe": a
// sign key, a key without a format, a curve other than P-256, a coordinate
// that is not 32 bytes or an RSA modulus under 2048 bits is
// ErrInvalidArgument, and an "apple-ecies" key is
// ErrEnvelopeFormatNotSupported.
func EncryptToDevice(key CertifiedKey, plaintext []byte) (string, error) {
	return encryptToDevice(key, plaintext, envelopeRandom{
		ephemeral: func() (*ecdh.PrivateKey, error) { return ecdh.P256().GenerateKey(rand.Reader) },
		bytes:     rand.Reader,
	})
}

// envelopeRandom is the seam the known-answer tests inject the ephemeral key,
// CEK, OAEP seed and IV through. bytes is read for the CEK (32 bytes, RSA
// only), then by rsa.EncryptOAEP for its seed, then for the IV (12 bytes).
type envelopeRandom struct {
	ephemeral func() (*ecdh.PrivateKey, error)
	bytes     io.Reader
}

func encryptToDevice(key CertifiedKey, plaintext []byte, random envelopeRandom) (string, error) {
	if key.Purpose != KeyPurposeDecrypt {
		return "", fmt.Errorf("%w: key purpose is %q; only a decrypt key opens an envelope", ErrInvalidArgument, key.Purpose)
	}
	switch key.Format {
	case formatJWE:
	case "":
		return "", fmt.Errorf("%w: key has no envelope format; a decrypt key names jwe or apple-ecies", ErrInvalidArgument)
	default:
		return "", fmt.Errorf("%w: key format %q is not produced here; EncryptToDevice writes the jwe envelope a TPM decrypt key opens, and an apple-ecies key needs an Apple-side encryptor", ErrEnvelopeFormatNotSupported, key.Format)
	}
	switch {
	case key.JWK.Kty == "EC" && key.Alg == algECDHES:
		return encryptECDHES(key.JWK, plaintext, random)
	case key.JWK.Kty == "RSA" && key.Alg == algRSAOAEP256:
		return encryptRSAOAEP(key.JWK, plaintext, random)
	}
	return "", fmt.Errorf("%w: key alg %q with kty %q is not ECDH-ES on an EC key or RSA-OAEP-256 on an RSA key", ErrInvalidArgument, key.Alg, key.JWK.Kty)
}

func encryptECDHES(jwk JWK, plaintext []byte, random envelopeRandom) (string, error) {
	if jwk.Crv != "P-256" {
		return "", fmt.Errorf("%w: jwk.crv %q is not P-256; no device certifies another curve", ErrInvalidArgument, jwk.Crv)
	}
	x, okX := decodeBase64URL(jwk.X)
	y, okY := decodeBase64URL(jwk.Y)
	if !okX || !okY || len(x) != envelopeCoordinateBytes || len(y) != envelopeCoordinateBytes {
		return "", fmt.Errorf("%w: jwk.x and jwk.y must each decode to exactly %d bytes", ErrInvalidArgument, envelopeCoordinateBytes)
	}
	point := make([]byte, 0, 1+2*envelopeCoordinateBytes)
	point = append(append(append(point, 4), x...), y...)
	// NewPublicKey refuses a point that is not on the curve.
	recipient, err := ecdh.P256().NewPublicKey(point)
	if err != nil {
		return "", fmt.Errorf("%w: jwk is not a usable P-256 public key: %v", ErrInvalidArgument, err)
	}
	eph, err := random.ephemeral()
	if err != nil {
		return "", err
	}
	z, err := eph.ECDH(recipient)
	if err != nil {
		return "", err
	}
	cek := concatKDF(z)
	epk := eph.PublicKey().Bytes() // 0x04 || X || Y, each at the curve width
	header := fmt.Sprintf(`{"alg":"%s","enc":"%s","epk":{"kty":"EC","crv":"P-256","x":"%s","y":"%s"}}`,
		algECDHES, encA256GCM,
		base64.RawURLEncoding.EncodeToString(epk[1:1+envelopeCoordinateBytes]),
		base64.RawURLEncoding.EncodeToString(epk[1+envelopeCoordinateBytes:]))
	return seal(header, nil, cek, plaintext, random.bytes)
}

func encryptRSAOAEP(jwk JWK, plaintext []byte, random envelopeRandom) (string, error) {
	n, okN := decodeBase64URL(jwk.N)
	e, okE := decodeBase64URL(jwk.E)
	if !okN || !okE || len(n) == 0 || len(e) == 0 || len(e) > 4 {
		return "", fmt.Errorf("%w: jwk.n and jwk.e must be base64url integers", ErrInvalidArgument)
	}
	pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
	if pub.N.BitLen() < minRSAModulusBits || pub.E < 3 {
		return "", fmt.Errorf("%w: jwk.n must be a modulus of at least %d bits", ErrInvalidArgument, minRSAModulusBits)
	}
	cek := make([]byte, envelopeCEKBytes)
	if _, err := io.ReadFull(random.bytes, cek); err != nil {
		return "", err
	}
	encryptedKey, err := rsa.EncryptOAEP(sha256.New(), random.bytes, pub, cek, nil)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrInvalidArgument, err)
	}
	header := fmt.Sprintf(`{"alg":"%s","enc":"%s"}`, algRSAOAEP256, encA256GCM)
	return seal(header, encryptedKey, cek, plaintext, random.bytes)
}

func seal(header string, encryptedKey, cek, plaintext []byte, random io.Reader) (string, error) {
	protected := base64.RawURLEncoding.EncodeToString([]byte(header))
	iv := make([]byte, envelopeIVBytes)
	if _, err := io.ReadFull(random, iv); err != nil {
		return "", err
	}
	block, err := aes.NewCipher(cek)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	sealed := gcm.Seal(nil, iv, plaintext, []byte(protected))
	ciphertext, tag := sealed[:len(sealed)-envelopeTagBytes], sealed[len(sealed)-envelopeTagBytes:]
	enc := base64.RawURLEncoding.EncodeToString
	return protected + "." + enc(encryptedKey) + "." + enc(iv) + "." + enc(ciphertext) + "." + enc(tag), nil
}

// concatKDF is RFC 7518 §4.6.2 in one round: SHA-256(counter ‖ Z ‖
// AlgorithmID ‖ PartyUInfo ‖ PartyVInfo ‖ SuppPubInfo), each info field
// length-prefixed, AlgorithmID the enc name, PartyU and PartyV empty,
// keydatalen 256.
func concatKDF(z []byte) []byte {
	alg := []byte(encA256GCM)
	input := make([]byte, 0, 4+len(z)+4+len(alg)+4+4+4)
	input = append(input, 0, 0, 0, 1)
	input = append(input, z...)
	input = append(input, 0, 0, 0, byte(len(alg)))
	input = append(input, alg...)
	input = append(input, 0, 0, 0, 0)
	input = append(input, 0, 0, 0, 0)
	input = append(input, 0, 0, 1, 0)
	sum := sha256.Sum256(input)
	return sum[:]
}
