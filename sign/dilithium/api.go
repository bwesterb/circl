// Package dilithium implements Dilithium signature scheme.
//
// This scheme was submitted to the NIST PQC competition and described in
// https://pq-crystals.org/dilithium/data/dilithium-specification-round2.pdf
//
// This package implements eight different modes providing a convenient wrapper
// around all modes, they can be chosen at runtime. If your choice of mode is
// specific at compile-time, we recommend to use the subpackages.
package dilithium

//go:generate go run gen.go

import (
	"crypto"
	"io"

	"github.com/cloudflare/circl/sign/dilithium/internal"
)

// SeedSize is
const SeedSize = internal.SeedSize

// Supported Modes
var modes = map[string]Mode{}

// ModeNames returns the list of supported modes.
func ModeNames() []string {
	names := []string{}
	for name := range modes {
		names = append(names, name)
	}
	return names
}

// ModeByName returns the mode with the given name or nil when not supported.
func ModeByName(name string) Mode { return modes[name] }

// PublicKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore signficantly larger than a packed public key.
type PublicKey interface {
	// Packs public key
	Bytes() []byte
}

// PrivateKey is a Dilithium public key.
//
// The structure contains values precomputed during unpacking/key generation
// and is therefore signficantly larger than a packed private key.
type PrivateKey interface {
	// Packs private key
	Bytes() []byte

	crypto.Signer
}

// Mode is a valid configuration of the Dilithium signature scheme.
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
	// length.  Precomputes values to speed up subsequent calls to Verify.
	PublicKeyFromBytes([]byte) PublicKey

	// Unpacks a private key.  Panics if the buffer is not
	// of PrivateKeySize() length.  Precomputes values to speed up subsequent
	// calls to Sign(To).
	PrivateKeyFromBytes([]byte) PrivateKey

	// PublicKeySize returns the size of a packed PublicKey
	PublicKeySize() int

	// PrivateKeySize returns the size of a packed PrivateKey
	PrivateKeySize() int

	// SignatureSize returns the size of a signature
	SignatureSize() int

	// Name returns the name of this mode
	Name() string
}
