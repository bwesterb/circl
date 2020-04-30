package mode3_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode3"
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
	var pkp [mode3.PublicKeySize]byte
	var skp [mode3.PrivateKeySize]byte
	pk, sk := mode3.NewKeyFromSeed(&seed)
	pk.Pack(&pkp)
	sk.Pack(&skp)

	// Generated with reference implementation.
	ehpk := [16]byte{
		183, 37, 211, 31, 183, 9, 102, 79, 133, 135,
		226, 251, 106, 96, 254, 128,
	}
	ehsk := [16]byte{
		164, 79, 207, 31, 67, 209, 36, 134, 92, 99,
		203, 243, 129, 163, 183, 235,
	}

	if hash(pkp[:]) != ehpk {
		t.Fatalf("pk not ok")
	}
	if hash(skp[:]) != ehsk {
		t.Fatalf("sk not ok")
	}
}
