package dilithium_test

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/cloudflare/circl/sign/dilithium"
)

func BenchmarkDilithium(b *testing.B) {
	for _, name := range dilithium.ModeNames() {
		m := dilithium.ModeByName(name)
		b.Run(name+"/GenerateKey", func(b *testing.B) { benchmarkGenerateKey(b, m) })
		b.Run(name+"/Sign", func(b *testing.B) { benchmarkSign(b, m) })
		b.Run(name+"/Verify", func(b *testing.B) { benchmarkVerify(b, m) })
	}
}

func benchmarkVerify(b *testing.B, m dilithium.Mode) {
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of verification (as in the reference
	// implementation.)
	var seed [dilithium.SeedSize]byte
	var msg [8]byte
	sig := make([]byte, m.SignatureSize())
	pk, sk := m.NewKeyFromSeed(seed[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		m.SignTo(sk, msg[:], sig[:])
		b.StartTimer()
		m.Verify(pk, msg[:], sig[:])
	}
}

func benchmarkSign(b *testing.B, m dilithium.Mode) {
	// Note that the expansion of the matrix A is done at Unpacking/Keygen
	// instead of at the moment of signing (as in the reference implementation.)
	var seed [dilithium.SeedSize]byte
	var msg [8]byte
	sig := make([]byte, m.SignatureSize())
	_, sk := m.NewKeyFromSeed(seed[:])
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(msg[:], uint64(i))
		m.SignTo(sk, msg[:], sig[:])
	}
}

func benchmarkGenerateKey(b *testing.B, m dilithium.Mode) {
	var seed [dilithium.SeedSize]byte
	for i := 0; i < b.N; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		m.NewKeyFromSeed(seed[:])
	}
}

func TestDilithium(t *testing.T) {
	for _, name := range dilithium.ModeNames() {
		m := dilithium.ModeByName(name)
		t.Run(m.Name(), func(t *testing.T) {
			testSignThenVerifyAndPkSkPacking(t, m)
			testPublicFromPrivate(t, m)
		})
	}
}

func testSignThenVerifyAndPkSkPacking(t *testing.T, m dilithium.Mode) {
	var seed [dilithium.SeedSize]byte
	var msg [8]byte
	sig := make([]byte, m.SignatureSize())
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		pk, sk := m.NewKeyFromSeed(seed[:])
		for j := uint64(0); j < 10; j++ {
			binary.LittleEndian.PutUint64(msg[:], j)
			m.SignTo(sk, msg[:], sig[:])
			if !m.Verify(pk, msg[:], sig[:]) {
				t.Fatal()
			}
		}
		skb1 := sk.Bytes()
		sk2 := m.PrivateKeyFromBytes(skb1)
		skb2 := sk2.Bytes()
		if !bytes.Equal(skb1, skb2) {
			t.Fatal()
		}
		pkb1 := pk.Bytes()
		pk2 := m.PublicKeyFromBytes(pkb1)
		pkb2 := pk2.Bytes()
		if !bytes.Equal(pkb1, pkb2) {
			t.Fatal()
		}
	}
}

func testPublicFromPrivate(t *testing.T, m dilithium.Mode) {
	var seed [dilithium.SeedSize]byte
	for i := 0; i < 100; i++ {
		binary.LittleEndian.PutUint64(seed[:], uint64(i))
		pk, sk := m.NewKeyFromSeed(seed[:])
		pk2 := sk.Public().(dilithium.PublicKey)
		pkb1 := pk.Bytes()
		pkb2 := pk2.Bytes()
		if !bytes.Equal(pkb1, pkb2) {
			t.Fatal()
		}
	}
}
