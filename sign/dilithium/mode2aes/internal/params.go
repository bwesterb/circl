package internal

import common "github.com/cloudflare/circl/sign/dilithium/internal"

const (
	Name           = "Dilithium2-AES"
	UseAES         = true
	PublicKeySize  = 1184
	PrivateKeySize = 2800
	SignatureSize  = 2044
	K              = 4
	L              = 3
	Eta            = 6
	DoubleEtaBits  = 4
	Beta           = 325
	Omega          = 80
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)
