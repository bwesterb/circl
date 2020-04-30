package mode4_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode4"
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
	var pkp [mode4.PublicKeySize]byte
	var skp [mode4.PrivateKeySize]byte
	pk, sk := mode4.NewKeyFromSeed(&seed)
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
