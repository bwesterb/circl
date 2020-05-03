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
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of verification (as in the reference
	// implementation.)
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
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of signing (as in the reference implementation.)
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

func BenchmarkPublicFromPrivate(b *testing.B) {
	var seed [32]byte
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		_, sk := NewKeyFromSeed(&seed)
		b.StartTimer()
		sk.Public()
	}
}

func TestSignThenVerifyAndPkSkPacking(t *testing.T) {
	var seed [common.SeedSize]byte
	var sig [SignatureSize]byte
	var msg [8]byte
	var pkb1, pkb2 [PublicKeySize]byte
	var skb1, skb2 [PrivateKeySize]byte
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
		pk.Pack(&pkb1)
		pk2.Unpack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
		sk.Pack(&skb1)
		sk2.Unpack(&skb1)
		sk2.Pack(&skb2)
		if skb1 != skb2 {
			t.Fatal()
		}
	}
}

func TestPublicFromPrivate(t *testing.T) {
	var seed [common.SeedSize]byte
	for i := uint64(0); i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], i)
		pk, sk := NewKeyFromSeed(&seed)
		pk2 := sk.Public().(*PublicKey)
		var pkb1, pkb2 [PublicKeySize]byte
		pk.Pack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
	}
}