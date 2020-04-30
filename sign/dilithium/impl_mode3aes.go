// This file was auto-generated.

package dilithium

import (
	"fmt"
	"io"

	impl "github.com/cloudflare/circl/sign/dilithium/mode3aes"
)

// Mode3AES implements Dilithium signature scheme in Mode3AES.
var Mode3AES Mode

func init() {
	Mode3AES = mode3aesImpl{}
	modes[Mode3AES.Name()] = Mode3AES
}

type mode3aesImpl struct{}

func (mode3aesImpl) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return impl.GenerateKey(rand)
}
func (mode3aesImpl) NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", SeedSize))
	}
	seedBuf := [SeedSize]byte{}
	copy(seedBuf[:], seed)
	return impl.NewKeyFromSeed(&seedBuf)
}
func (mode3aesImpl) SignTo(sk PrivateKey, msg []byte, signature []byte) {
	impl.SignTo(sk.(*impl.PrivateKey), msg, signature)
}
func (mode3aesImpl) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*impl.PrivateKey)
	ret := [impl.SignatureSize]byte{}
	impl.SignTo(isk, msg, ret[:])
	return ret[:]
}
func (mode3aesImpl) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	return impl.Verify(pk.(*impl.PublicKey), msg, signature)
}
func (mode3aesImpl) PublicKeyFromBytes(data []byte) PublicKey {
	var ret impl.PublicKey
	if len(data) != impl.PublicKeySize {
		panic(fmt.Errorf("packed public key must be of %d bytes",
			impl.PublicKeySize))
	}
	var buf [impl.PublicKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}
func (mode3aesImpl) PrivateKeyFromBytes(data []byte) PrivateKey {
	var ret impl.PrivateKey
	if len(data) != impl.PrivateKeySize {
		panic(fmt.Errorf("packed private key must be of %d bytes",
			impl.PrivateKeySize))
	}
	var buf [impl.PrivateKeySize]byte
	copy(buf[:], data)
	ret.Unpack(&buf)
	return &ret
}
func (mode3aesImpl) PublicKeySize() int  { return impl.PublicKeySize }
func (mode3aesImpl) PrivateKeySize() int { return impl.PrivateKeySize }
func (mode3aesImpl) SignatureSize() int  { return impl.SignatureSize }
func (mode3aesImpl) Name() string        { return impl.Name }
func (mode3aesImpl) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey) {
	return impl.NewKeyFromExpandedSeed(seed)
}
