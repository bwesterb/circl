// This file was auto-generated.

package dilithium

import (
	"fmt"
	"io"

	impl "github.com/cloudflare/circl/sign/dilithium/mode4aes"
)

// Mode4AES implements Dilithium signature scheme in Mode4AES.
var Mode4AES Mode

func init() {
	Mode4AES = mode4aesImpl{}
	modes[Mode4AES.Name()] = Mode4AES
}

type mode4aesImpl struct{}

func (mode4aesImpl) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return impl.GenerateKey(rand)
}
func (mode4aesImpl) NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", SeedSize))
	}
	seedBuf := [SeedSize]byte{}
	copy(seedBuf[:], seed)
	return impl.NewKeyFromSeed(&seedBuf)
}
func (mode4aesImpl) SignTo(sk PrivateKey, msg []byte, signature []byte) {
	impl.SignTo(sk.(*impl.PrivateKey), msg, signature)
}
func (mode4aesImpl) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*impl.PrivateKey)
	ret := [impl.SignatureSize]byte{}
	impl.SignTo(isk, msg, ret[:])
	return ret[:]
}
func (mode4aesImpl) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	return impl.Verify(pk.(*impl.PublicKey), msg, signature)
}
func (mode4aesImpl) PublicKeyFromBytes(data []byte) PublicKey {
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
func (mode4aesImpl) PrivateKeyFromBytes(data []byte) PrivateKey {
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
func (mode4aesImpl) PublicKeySize() int  { return impl.PublicKeySize }
func (mode4aesImpl) PrivateKeySize() int { return impl.PrivateKeySize }
func (mode4aesImpl) SignatureSize() int  { return impl.SignatureSize }
func (mode4aesImpl) Name() string        { return impl.Name }
func (mode4aesImpl) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey) {
	return impl.NewKeyFromExpandedSeed(seed)
}
