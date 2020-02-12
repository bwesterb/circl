// mode2aes implements the CRYSTALS-Dilithium signature scheme Dilithium2-AES
// as submitted to round2 of the NIST PQC competition and described in
//
// https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf
package mode2aes

import (
	"errors"
	"io"

	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode2aes/internal"
)

const (
	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = internal.PublicKeySize

	// Size of a packed PrivateKey
	PrivateKeySize = internal.PrivateKeySize

	// Size of a signature
	SignatureSize = internal.SignatureSize
)

// PublicKey is the type of Dilithium2-AES public key
type PublicKey internal.PublicKey

// PrivateKey is the type of Dilithium2-AES private key
type PrivateKey internal.PrivateKey

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	pk, sk, err := internal.GenerateKey(rand)
	return (*PublicKey)(pk), (*PrivateKey)(sk), err
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[SeedSize]byte) (*PublicKey, *PrivateKey) {
	pk, sk := internal.NewKeyFromSeed(seed)
	return (*PublicKey)(pk), (*PrivateKey)(sk)
}

// SignTo signs the given message and writes the signature into signature.
// It will panic if signature is not of length at least SignatureSize.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	internal.SignTo(
		(*internal.PrivateKey)(sk),
		msg,
		signature,
	)
}

// Sign signs the given message and returns the signature.
func Sign(sk *PrivateKey, msg []byte) []byte {
	var sig [SignatureSize]byte
	SignTo(sk, msg, sig[:])
	return sig[:]
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	return internal.Verify(
		(*internal.PublicKey)(pk),
		msg,
		signature,
	)
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Unpack(buf)
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Unpack(buf)
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	(*internal.PublicKey)(pk).Pack(buf)
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	(*internal.PrivateKey)(sk).Pack(buf)
}

// Packs the public key.
func (pk *PublicKey) MarshalBinary() ([]byte, error) {
	var buf [PublicKeySize]byte
	pk.Pack(&buf)
	return buf[:], nil
}

// Packs the private key.
func (sk *PrivateKey) MarshalBinary() ([]byte, error) {
	var buf [PrivateKeySize]byte
	sk.Pack(&buf)
	return buf[:], nil
}

// Unpacks the public key from data.
func (pk *PublicKey) UnmarshalBinary(data []byte) error {
	if len(data) != PublicKeySize {
		return errors.New("Packed public key must be of PublicKeySize bytes")
	}
	var buf [PublicKeySize]byte
	copy(buf[:], data)
	pk.Unpack(&buf)
	return nil
}

// Unpacks the private key from data.
func (sk *PrivateKey) UnmarshalBinary(data []byte) error {
	if len(data) != PrivateKeySize {
		return errors.New("Packed private key must be of PrivateKeySize bytes")
	}
	var buf [PrivateKeySize]byte
	copy(buf[:], data)
	sk.Unpack(&buf)
	return nil
}
