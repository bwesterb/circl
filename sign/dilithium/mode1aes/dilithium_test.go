package mode1aes_test

import (
	"testing"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode1aes"
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
	var pkp [mode1aes.PublicKeySize]byte
	var skp [mode1aes.PrivateKeySize]byte
	pk, sk := mode1aes.NewKeyFromSeed(&seed)
	pk.Pack(&pkp)
	sk.Pack(&skp)

	// Generated with reference implementation.
	ehpk := [16]byte{
		119, 130, 172, 20, 109, 158, 99, 98, 33,
		50, 156, 254, 100, 100, 113, 18,
	}
	ehsk := [16]byte{
		190, 85, 133, 60, 225, 210, 193, 17, 63,
		201, 111, 18, 149, 146, 135, 137,
	}

	if hash(pkp[:]) != ehpk {
		t.Fatalf("pk not ok")
	}
	if hash(skp[:]) != ehsk {
		t.Fatalf("sk not ok")
	}
}
