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
		136, 123, 170, 243, 169, 141, 10, 166, 185,
		92, 140, 26, 104, 103, 230, 9,
	}
	ehsk := [16]byte{
		186, 114, 237, 48, 145, 130, 170, 80, 158,
		89, 80, 19, 179, 173, 144, 137,
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
		2, 8380412, 8380413, 8380416, 8380416, 8380415, 4, 1, 5,
		1, 8380413, 8380412, 5, 8380412, 8380416, 8380415, 8380412,
		4, 1, 1, 8380414, 8380413, 8380413, 8380416, 4, 8380415,
		4, 8380415, 8380416, 8380412, 2, 8380412, 4, 2, 8380416,
		5, 8380415, 8380412, 0, 3, 8380416, 5, 8380416, 4, 3,
		8380413, 4, 8380412, 1, 2, 8380413, 8380416, 8380413, 3,
		5, 8380413, 8380414, 8380414, 2, 0, 8380412, 4, 8380412,
		1, 8380412, 8380413, 0, 8380413, 8380413, 4, 1, 0, 8380413,
		8380415, 4, 0, 8380414, 8380413, 3, 2, 4, 8380412, 8380415,
		0, 8380414, 5, 4, 8380413, 1, 1, 8380414, 8380415, 3, 3,
		3, 3, 8380412, 0, 8380415, 3, 8380414, 8380412, 8380414,
		8380412, 2, 8380412, 8380416, 3, 8380412, 2, 0, 3, 1, 0,
		3, 8380413, 0, 8380414, 2, 2, 0, 5, 8380416, 8380414, 5,
		4, 0, 8380415, 1, 3, 5, 5, 8380416, 3, 4, 0, 0, 3, 0, 0,
		3, 5, 8380412, 8380414, 8380412, 5, 3, 8380416, 5, 5, 4,
		8380416, 1, 5, 5, 1, 5, 3, 8380414, 1, 1, 8380415, 8380415,
		2, 2, 8380414, 0, 8380413, 3, 8380414, 5, 8380413, 0, 4,
		0, 8380416, 8380416, 3, 1, 8380412, 2, 8380413, 8380413,
		0, 8380414, 4, 2, 5, 2, 0, 1, 8380412, 8380412, 8380416,
		8380416, 3, 3, 1, 3, 4, 5, 2, 5, 3, 3, 8380415, 2, 8380415,
		5, 2, 3, 4, 3, 8380414, 0, 1, 8380416, 8380415, 3, 4, 3,
		8380412, 0, 8380416, 8380412, 3, 5, 8380415, 3, 3, 8380414,
		8380416, 8380412, 5, 1, 8380413, 1, 4, 8380415, 8380413,
		8380416, 8380413, 5, 5, 0, 5, 0, 5, 2, 1, 8380414, 8380415,
		2, 8380412, 8380412, 4,
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
