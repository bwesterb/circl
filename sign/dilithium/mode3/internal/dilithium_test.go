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

func TestSign(t *testing.T) {
	var seed [common.SeedSize]byte
	var sig [SignatureSize]byte
	msg := []byte{
		86, 101, 114, 105, 108, 121, 44, 32, 118, 101, 114,
		105, 108, 121, 44, 32, 73, 32, 115, 97, 121, 32,
		117, 110, 116, 111, 32, 121, 111, 117, 44, 32, 208,
		181, 120, 99, 101, 112, 116, 32, 97, 32, 99, 111,
		114, 110, 32, 111, 102, 32, 119, 104, 101, 97, 116,
		32, 102, 97, 108, 108, 32, 105, 110, 116, 111, 32,
		116, 104, 101, 32, 103, 114, 111, 117, 110, 100,
		32, 97, 110, 100, 32, 100, 105, 101, 44, 32, 105,
		116, 32, 97, 98, 105, 100, 101, 116, 104, 32, 97,
		108, 111, 110, 101, 58, 32, 98, 117, 116, 32, 105,
		102, 32, 105, 116, 32, 100, 105, 101, 44, 32, 105,
		116, 32, 98, 114, 105, 110, 103, 101, 116, 104, 32,
		102, 111, 114, 116, 104, 32, 109, 117, 99, 104, 32,
		102, 114, 117, 105, 116, 46,
	}

	pk, sk := NewKeyFromSeed(&seed)
	SignTo(sk, msg, sig[:])
	if !Verify(pk, msg, sig[:]) {
		t.Fatal()
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
		pk2 := sk.Public()
		var pkb1, pkb2 [PublicKeySize]byte
		pk.Pack(&pkb1)
		pk2.Pack(&pkb2)
		if pkb1 != pkb2 {
			t.Fatal()
		}
	}
}
