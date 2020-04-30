package internal

import common "github.com/cloudflare/circl/sign/dilithium/internal"

const (
	Name           = "Dilithium1-AES"
	UseAES         = true
	PublicKeySize  = 896
	PrivateKeySize = 2096
	SignatureSize  = 1387
	K              = 3
	L              = 2
	Eta            = 7
	DoubleEtaBits  = 4
	Beta           = 375
	Omega          = 64
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)
