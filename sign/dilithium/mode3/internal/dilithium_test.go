package internal

import (
	"encoding/binary"
	"testing"

	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

// Checks whether p is normalized.  Only used in tests.
func PolyNormalized(p *common.Poly) bool {
	p2 := *p
	p2.Normalize()
	return p2 == *p
}

func BenchmarkVerify(b *testing.B) {
	var seed [32]byte
	var msg [8]byte
	var sig [SignatureSize]byte
	pk, sk := NewKeyFromSeed(&seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		SignTo(sk, msg[:], sig[:])
		b.StartTimer()
		Verify(pk, msg[:], sig[:])
	}
}

func BenchmarkSign(b *testing.B) {
	var seed [32]byte
	var msg [8]byte
	var sig [SignatureSize]byte
	_, sk := NewKeyFromSeed(&seed)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		SignTo(sk, msg[:], sig[:])
	}
}

func BenchmarkGenerateKey(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		NewKeyFromSeed(&seed)
	}
}

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	var seed [common.SeedSize]byte
	var sig [SignatureSize]byte
	var msg [8]byte
	var pkb [PublicKeySize]byte
	var skb [PrivateKeySize]byte
	var pk2 PublicKey
	var sk2 PrivateKey
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := NewKeyFromSeed(&seed)
		for j := uint64(0); j < 10; j++ {
			binary.LittleEndian.PutUint64(msg[:], j)
			SignTo(sk, msg[:], sig[:])
			if !Verify(pk, msg[:], sig[:]) {
				t.Fatal()
			}
		}
		pk.Pack(&pkb)
		pk2.Unpack(&pkb)
		if *pk != pk2 {
			t.Fatal()
		}
		sk.Pack(&skb)
		sk2.Unpack(&skb)
		if *sk != sk2 {
			t.Fatal()
		}
	}
}
