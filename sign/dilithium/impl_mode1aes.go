// This file was auto-generated.

package dilithium

import (
	"fmt"
	"io"

	impl "github.com/cloudflare/circl/sign/dilithium/mode1aes"
)

// Mode1AES implements Dilithium signature scheme in Mode1AES.
var Mode1AES Mode

func init() {
	Mode1AES = mode1aesImpl{}
	modes[Mode1AES.Name()] = Mode1AES
}

type mode1aesImpl struct{}

func (mode1aesImpl) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return impl.GenerateKey(rand)
}
func (mode1aesImpl) NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", SeedSize))
	}
	seedBuf := [SeedSize]byte{}
	copy(seedBuf[:], seed)
	return impl.NewKeyFromSeed(&seedBuf)
}
func (mode1aesImpl) SignTo(sk PrivateKey, msg []byte, signature []byte) {
	impl.SignTo(sk.(*impl.PrivateKey), msg, signature)
}
func (mode1aesImpl) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*impl.PrivateKey)
	ret := [impl.SignatureSize]byte{}
	impl.SignTo(isk, msg, ret[:])
	return ret[:]
}
func (mode1aesImpl) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	return impl.Verify(pk.(*impl.PublicKey), msg, signature)
}
func (mode1aesImpl) PublicKeyFromBytes(data []byte) PublicKey {
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
func (mode1aesImpl) PrivateKeyFromBytes(data []byte) PrivateKey {
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
func (mode1aesImpl) PublicKeySize() int  { return impl.PublicKeySize }
func (mode1aesImpl) PrivateKeySize() int { return impl.PrivateKeySize }
func (mode1aesImpl) SignatureSize() int  { return impl.SignatureSize }
func (mode1aesImpl) Name() string        { return impl.Name }
func (mode1aesImpl) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey) {
	return impl.NewKeyFromExpandedSeed(seed)
}
