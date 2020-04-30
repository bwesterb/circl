package mode2aes_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode2aes"
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
	var pkp [mode2aes.PublicKeySize]byte
	var skp [mode2aes.PrivateKeySize]byte
	pk, sk := mode2aes.NewKeyFromSeed(&seed)
	pk.Pack(&pkp)
	sk.Pack(&skp)

	// Generated with reference implementation.
	ehpk := [16]byte{
		35, 196, 233, 81, 102, 98, 57, 78, 136,
		229, 89, 207, 40, 116, 215, 164,
	}
	ehsk := [16]byte{
		42, 191, 208, 210, 148, 206, 27, 43,
		171, 91, 134, 4, 130, 196, 187, 193,
	}

	if hash(pkp[:]) != ehpk {
		t.Fatalf("pk not ok")
	}
	if hash(skp[:]) != ehsk {
		t.Fatalf("sk not ok")
	}
}
