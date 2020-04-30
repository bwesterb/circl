// This file was auto-generated.

package dilithium

import (
	"fmt"
	"io"

	impl "github.com/cloudflare/circl/sign/dilithium/mode4"
)

// Mode4 implements Dilithium signature scheme in Mode4.
var Mode4 Mode

func init() {
	Mode4 = mode4Impl{}
	modes[Mode4.Name()] = Mode4
}

type mode4Impl struct{}

func (mode4Impl) GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	return impl.GenerateKey(rand)
}
func (mode4Impl) NewKeyFromSeed(seed []byte) (PublicKey, PrivateKey) {
	if len(seed) != SeedSize {
		panic(fmt.Sprintf("seed must be of length %d", SeedSize))
	}
	seedBuf := [SeedSize]byte{}
	copy(seedBuf[:], seed)
	return impl.NewKeyFromSeed(&seedBuf)
}
func (mode4Impl) SignTo(sk PrivateKey, msg []byte, signature []byte) {
	impl.SignTo(sk.(*impl.PrivateKey), msg, signature)
}
func (mode4Impl) Sign(sk PrivateKey, msg []byte) []byte {
	isk := sk.(*impl.PrivateKey)
	ret := [impl.SignatureSize]byte{}
	impl.SignTo(isk, msg, ret[:])
	return ret[:]
}
func (mode4Impl) Verify(pk PublicKey, msg []byte, signature []byte) bool {
	return impl.Verify(pk.(*impl.PublicKey), msg, signature)
}
func (mode4Impl) PublicKeyFromBytes(data []byte) PublicKey {
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
func (mode4Impl) PrivateKeyFromBytes(data []byte) PrivateKey {
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
func (mode4Impl) PublicKeySize() int  { return impl.PublicKeySize }
func (mode4Impl) PrivateKeySize() int { return impl.PrivateKeySize }
func (mode4Impl) SignatureSize() int  { return impl.SignatureSize }
func (mode4Impl) Name() string        { return impl.Name }
func (mode4Impl) NewKeyFromExpandedSeed(seed *[96]byte) (PublicKey, PrivateKey) {
	return impl.NewKeyFromExpandedSeed(seed)
}
