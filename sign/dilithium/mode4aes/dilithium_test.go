package mode4aes_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode4aes"
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
	var pkp [mode4aes.PublicKeySize]byte
	var skp [mode4aes.PrivateKeySize]byte
	pk, sk := mode4aes.NewKeyFromSeed(&seed)
	pk.Pack(&pkp)
	sk.Pack(&skp)

	// Generated with reference implementation.
	ehpk := [16]byte{
		247, 248, 80, 193, 216, 255, 130, 200,
		104, 171, 47, 24, 138, 198, 36, 179,
	}
	ehsk := [16]byte{
		124, 28, 139, 93, 246, 63, 208, 150,
		144, 29, 164, 60, 0, 250, 113, 232,
	}

	if hash(pkp[:]) != ehpk {
		t.Fatalf("pk not ok")
	}
	if hash(skp[:]) != ehsk {
		t.Fatalf("sk not ok")
	}
}
