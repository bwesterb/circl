package internal

import common "github.com/cloudflare/circl/sign/dilithium/internal"

const (
	Name           = "Dilithium4"
	UseAES         = false
	PublicKeySize  = 1760
	PrivateKeySize = 3856
	SignatureSize  = 3366
	K              = 6
	L              = 5
	Eta            = 3
	DoubleEtaBits  = 3
	Beta           = 175
	Omega          = 120
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)
