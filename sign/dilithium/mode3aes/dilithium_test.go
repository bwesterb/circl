package mode3aes_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode3aes"
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
	var pkp [mode3aes.PublicKeySize]byte
	var skp [mode3aes.PrivateKeySize]byte
	pk, sk := mode3aes.NewKeyFromSeed(&seed)
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
