// mode defines the interface for the various modes of the Dilithium
// signature scheme modes.
package mode

import (
	"io"
)

// PublicKey is a Dilithium public key.
type PublicKey interface {
	// Packs public key
	Bytes() []byte
}

// PrivateKey is a Dilithium public key.
type PrivateKey interface {
	// Packs private key
	Bytes() []byte
}

// Mode is a certain configuration of the Dilithium signature scheme.
type Mode interface {
	// GenerateKey generates a public/private key pair using entropy from rand.
	// If rand is nil, crypto/rand.Reader will be used.
	GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error)

	// NewKeyFromSeed derives a public/private key pair using the given seed.
	// Panics if len(seed) != SeedSize()
	NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey)

	// SignTo signs the given message and writes the signature into signature.
	// It will panic if signature is not of length at least SignatureSize
	// or when sk has not been generated for this mode.
	SignTo(sk PrivateKey, msg []byte, signature []byte)

	// Sign signs the given message and returns the signature.
	// It will panic if sk has not been generated for this mode.
	Sign(sk PrivateKey, msg []byte) []byte

	// Verify checks whether the given signature by pk on msg is valid.
	// It will panic if pk is of the wrong mode.
	Verify(pk PublicKey, msg []byte, signature []byte) bool

	// Unpacks a public key.  Panics if the buffer is not of PublicKeySize()
	// length.
	PublicKeyFromBytes([]byte) PublicKey

	// Unpacks a private key.  Panics if the buffer is not
	// of PrivateKeySize() length.
	PrivateKeyFromBytes([]byte) PrivateKey

	// SeedSize returns the size of the seed for NewKeyFromSeed
	SeedSize() int

	// PublicKeySize returns the size of a packed PublicKey
	PublicKeySize() int

	// PrivateKeySize returns the size  of a packed PrivateKey
	PrivateKeySize() int

	// SignatureSize returns the size  of a signature
	SignatureSize() int

	// Name returns the name of this mode
	Name() string
}
