package internal

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

// Tests specific to the current mode

func hash(in []byte) [16]byte {
	var ret [16]byte
	h := shake.NewShake256()
	h.Write(in)    // nolint:errcheck
	h.Read(ret[:]) // nolint:errcheck
	return ret
}

func TestNewKeyFromSeed(t *testing.T) {
	var seed [common.SeedSize]byte
	var pkp [PublicKeySize]byte
	var skp [PrivateKeySize]byte
	pk, sk := NewKeyFromSeed(&seed)
	pk.Pack(&pkp)
	sk.Pack(&skp)

	// Generated with reference implementation.
	ehpk := [16]byte{
		231, 153, 127, 199, 26, 103, 150, 5,
		109, 70, 51, 164, 7, 105, 196, 149,
	}
	ehsk := [16]byte{
		224, 84, 49, 155, 186, 189, 46, 21,
		108, 86, 232, 238, 146, 60, 42, 142,
	}

	if hash(pkp[:]) != ehpk {
		t.Fatalf("pk not ok")
	}
	if hash(skp[:]) != ehsk {
		t.Fatalf("sk not ok")
	}
}

func TestVectorDeriveUniformLeqEta(t *testing.T) {
	var p common.Poly
	var seed [32]byte
	p2 := common.Poly{
		8380416, 0, 8380415, 1, 8380416, 8380415, 1, 8380415,
		8380416, 3, 8380416, 8380414, 3, 8380415, 2, 3, 1, 1,
		8380414, 1, 0, 2, 8380414, 8380415, 8380415, 8380416,
		8380414, 3, 8380416, 8380414, 8380416, 8380414, 1, 3, 2,
		0, 8380416, 3, 8380415, 8380415, 2, 3, 8380416, 0, 2, 1,
		1, 8380414, 8380414, 3, 1, 0, 8380416, 2, 1, 8380415, 3,
		2, 8380414, 3, 3, 8380414, 1, 8380414, 1, 2, 8380414, 2,
		8380415, 8380415, 3, 1, 0, 8380415, 8380414, 8380415, 3,
		8380416, 8380416, 8380414, 2, 8380416, 8380414, 0, 0, 3,
		8380414, 8380415, 2, 8380416, 8380414, 0, 3, 2, 1, 8380414,
		0, 1, 0, 8380416, 2, 2, 0, 8380414, 0, 2, 8380414, 8380416,
		1, 8380415, 1, 8380416, 3, 8380414, 0, 2, 8380415, 3,
		8380415, 8380414, 8380416, 2, 3, 1, 0, 0, 2, 1, 3, 0, 1,
		3, 3, 8380415, 0, 8380416, 3, 1, 2, 8380415, 0, 3, 1,
		8380416, 8380414, 2, 8380414, 8380414, 0, 8380415, 8380416,
		8380415, 1, 8380416, 3, 8380414, 1, 1, 3, 8380414, 3, 2,
		2, 0, 3, 8380416, 2, 8380416, 0, 8380415, 8380416, 8380416,
		3, 8380414, 0, 0, 8380415, 8380414, 8380416, 2, 1, 8380416,
		2, 2, 8380414, 1, 1, 2, 1, 8380415, 8380416, 1, 1, 0, 1,
		8380416, 0, 8380416, 2, 8380415, 1, 0, 1, 8380414, 3,
		8380414, 8380415, 8380416, 0, 0, 1, 2, 8380415, 8380414,
		0, 8380415, 0, 2, 0, 8380416, 1, 8380415, 1, 8380416, 0,
		0, 8380414, 3, 0, 3, 0, 2, 3, 0, 3, 8380416, 8380415,
		8380415, 8380416, 2, 3, 0, 3, 2, 8380415, 3, 2, 8380416,
		8380415, 3, 1, 0, 8380414, 2, 8380416, 3,
	}
	for i := 0; i < 32; i++ {
		seed[i] = byte(i)
	}
	PolyDeriveUniformLeqEta(&p, &seed, 30000)
	p.Normalize()
	if p != p2 {
		t.Fatalf("%v != %v", p, p2)
	}
}