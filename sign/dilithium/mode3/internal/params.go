package internal

import common "github.com/cloudflare/circl/sign/dilithium/internal"

const (
	Name           = "Dilithium3"
	UseAES         = false
	PublicKeySize  = 1472
	PrivateKeySize = 3504
	SignatureSize  = 2701
	K              = 5
	L              = 4
	Eta            = 5
	DoubleEtaBits  = 4
	Beta           = 275
	Omega          = 96
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)
