package eddilithium3

import (
	"github.com/cloudflare/circl/sign"

	cryptoRand "crypto/rand"
	"errors"
)

type scheme struct{}

var Scheme sign.Scheme = &scheme{}

func (s *scheme) GenerateKey() (sign.PublicKey, sign.PrivateKey, error) {
	return GenerateKey(cryptoRand.Reader)
}

func (s *scheme) Sign(sk sign.PrivateKey, message []byte,
	opts *sign.SignatureOpts) []byte {
	sig := make([]byte, SignatureSize)
	if opts != nil && opts.Context != "" {
		panic("Does not support context")
	}
	SignTo(sk.(*PrivateKey), message, sig)
	return sig
}

func (s *scheme) Verify(pk sign.PublicKey, message, signature []byte,
	opts *sign.SignatureOpts) bool {
	if opts != nil && opts.Context != "" {
		panic("Does not support context")
	}
	return Verify(pk.(*PublicKey), message, signature)
}

func (s *scheme) DeriveKey(seed []byte) (sign.PublicKey, sign.PrivateKey) {
	if len(seed) != SeedSize {
		panic("Wrong seed size")
	}
	var tmp [SeedSize]byte
	copy(tmp[:], seed)
	return NewKeyFromSeed(&tmp)
}

func (s *scheme) UnmarshalBinaryPublicKey(buf []byte) (sign.PublicKey, error) {
	if len(buf) != PublicKeySize {
		return nil, errors.New("Wrong size for public key")
	}
	var tmp [PublicKeySize]byte
	var ret PublicKey
	copy(tmp[:], buf)
	ret.Unpack(&tmp)
	return &ret, nil
}

func (s *scheme) UnmarshalBinaryPrivateKey(buf []byte) (sign.PrivateKey, error) {
	if len(buf) != PrivateKeySize {
		return nil, errors.New("Wrong size for private key")
	}
	var tmp [PrivateKeySize]byte
	var ret PrivateKey
	copy(tmp[:], buf)
	ret.Unpack(&tmp)
	return &ret, nil
}

func (s *scheme) PublicKeySize() uint {
	return PublicKeySize
}

func (s *scheme) PrivateKeySize() uint {
	return PrivateKeySize
}

func (s *scheme) Name() string {
	return "Ed25519-Dilithium3"
}

func (s *scheme) SignatureSize() uint {
	return SignatureSize
}

func (s *scheme) SeedSize() uint {
	return SeedSize
}

func initialize() {
	sign.RegisterScheme(Scheme)
}

func (sk *PrivateKey) Scheme() sign.Scheme {
	return Scheme
}

func (sk *PublicKey) Scheme() sign.Scheme {
	return Scheme
}
