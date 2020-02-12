package internal

const (
	SeedSize = 32
	N        = 256
	Q        = 8380417
	QBits    = 23
	D        = 14
	Gamma1   = ((Q - 1) / 16)
	Gamma2   = Gamma1 / 2
	Alpha    = 2 * Gamma2

	// Size of T1 packed.  (Note that the formula is not valid in general.)
	PolyT1Size = (N * (QBits - D)) / 8

	// Size of T0 packed.  (Note that the formula is not valid in general.)
	PolyT0Size = (N * D) / 8

	// Size of a packed polynomial of norm <γ1.
	PolyLeGamma1Size = (N * (QBits - 3)) / 8

	// Size of a packed polynomial whose coeffients are in [0,16).
	PolyLe16Size = N / 2
)
