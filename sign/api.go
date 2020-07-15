// package sign provides a unified interface to all signature schemes
// supported by Circl.
package sign

import (
	"crypto"
	"crypto/x509"
	"encoding"
	"encoding/asn1"
	"sync"
)

var (
	mux sync.Mutex // protects schemes

	// List of schemes
	schemes = make(map[string]Scheme)
)

type SignatureOpts struct {
	// If non-empty, includes the given context in the signature if supported
	// and will cause an error during signing otherwise.
	Context string
}

// A public key is used to verify a signature set by the corresponding private
// key.
type PublicKey interface {
	// Returns the signature scheme for this public key.
	Scheme() Scheme

	encoding.BinaryMarshaler
}

// A private key allows one to create signatures.
type PrivateKey interface {
	// Returns the signature scheme for this private key.
	Scheme() Scheme

	// For compatibility with Go standard library
	crypto.Signer

	encoding.BinaryMarshaler
}

// A Scheme represents a specific instance of a signature scheme.
type Scheme interface {
	// GenerateKey creates a new key-pair.
	GenerateKey() (PublicKey, PrivateKey, error)

	// Creates a signature using the PrivateKey on the given message and
	// returns the signature. opts are additional options which can be nil.
	Sign(sk PrivateKey, message []byte, opts *SignatureOpts) []byte

	// Checks whether the given signature is a valid signature set by
	// the private key corresponding to the given public key on the
	// given message. opts are additional options which can be nil.
	Verify(pk PublicKey, message []byte, signature []byte, opts *SignatureOpts) bool

	// Deterministically derives a keypair from a seed.  If you're unsure,
	// you're better off using GenerateKey().
	//
	// Panics if seed is not of length SeedSize().
	DeriveKey(seed []byte) (PublicKey, PrivateKey)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPublicKey([]byte) (PublicKey, error)

	// Unmarshals a PublicKey from the provided buffer.
	UnmarshalBinaryPrivateKey([]byte) (PrivateKey, error)

	// Size of binary marshalled public keys
	PublicKeySize() uint

	// Size of binary marshalled public keys
	PrivateKeySize() uint

	// Name of the scheme
	Name() string

	// Size of signatures
	SignatureSize() uint

	// Size of seeds
	SeedSize() uint
}

// Additional methods when the signature scheme is supported in X509.
type CertificateScheme interface {
	// Return the appropriate OIDs for this instance.  It is implicitly
	// assumed that the encoding is simple: e.g. uses the same OID for
	// signature and public key like Ed25519.
	Oid() asn1.ObjectIdentifier

	// Returns the appropriate x509.PublicKeyAlgorithm.
	PublicKeyAlgorithm() x509.PublicKeyAlgorithm
}

// Additional methods when the signature scheme is supported in TLS.
type TlsScheme interface {
	TlsIdentifier() uint
}

// SchemeByName returns the scheme with the given name and nil if it is not
// supported.  Use ListSchemes() to list supported schemes.
func SchemeByName(name string) Scheme {
	mux.Lock()
	ret := schemes[name]
	mux.Unlock()
	return ret
}

// ListSchemeNames returns the names of all schemes supported.
func ListSchemeNames() []string {
	ret := []string{}
	mux.Lock()
	for name, _ := range schemes {
		ret = append(ret, name)
	}
	mux.Unlock()
	return ret
}

// RegisterScheme registers a new scheme.
func RegisterScheme(scheme Scheme) {
	if scheme == nil {
		panic("Scheme shouldn't be empty")
	}
	name := scheme.Name()
	mux.Lock()
	defer mux.Unlock()
	if schemes[name] != nil {
		panic("Scheme already registered")
	}
	schemes[name] = scheme
}
