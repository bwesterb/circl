// This file was auto-generated.

package dilithium

import (
	"fmt"
	"io"

	impl "github.com/cloudflare/circl/sign/dilithium/mode2aes"
)

// Mode2AES implements Dilithium signature scheme in Mode2AES.
var Mode2AES Mode

func init() {
	Mode2AES = mode2aesImpl{}
	modes[Mode2AES.Name()] = Mode2AES
}

type mode2aesImpl struct{}

func (mode2aesImpl) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return impl.GenerateKey(rand)
}
func (mode2aesImpl) NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", SeedSize))
	}
	seedBuf := [SeedSize]byte{}
	copy(seedBuf[:], seed)
	return impl.NewKeyFromSeed(&seedBuf)
}
func (mode2aesImpl) SignTo(sk PrivateKey, msg []byte, signature []byte) {
	impl.SignTo(sk.(*impl.PrivateKey), msg, signature)
}
func (mode2aesImpl) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*impl.PrivateKey)
	ret := [impl.SignatureSize]byte{}
	impl.SignTo(isk, msg, ret[:])
	return ret[:]
}
func (mode2aesImpl) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	return impl.Verify(pk.(*impl.PublicKey), msg, signature)
}
func (mode2aesImpl) PublicKeyFromBytes(data []byte) PublicKey {
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
func (mode2aesImpl) PrivateKeyFromBytes(data []byte) PrivateKey {
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
func (mode2aesImpl) PublicKeySize() int  { return impl.PublicKeySize }
func (mode2aesImpl) PrivateKeySize() int { return impl.PrivateKeySize }
func (mode2aesImpl) SignatureSize() int  { return impl.SignatureSize }
func (mode2aesImpl) Name() string        { return impl.Name }
func (mode2aesImpl) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey) {
	return impl.NewKeyFromExpandedSeed(seed)
}
