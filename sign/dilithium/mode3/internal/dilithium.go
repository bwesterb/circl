package internal

import (
	cryptoRand "crypto/rand"
	"io"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
)

const (
	// Size of a packed polynomial of norm ≤η.
	// (Note that the  formula is not valid in general.)
	PolyLeqEtaSize = (common.N * DoubleEtaBits) / 8
)

// PublicKey is the type of Dilithium public keys.
type PublicKey struct {
	rho [32]byte
	t1  VecK

	// Cached values
	t1p [common.PolyT1Size * K]byte
}

// PublicKey is the type of Dilithium private keys.
type PrivateKey struct {
	rho [32]byte
	key [32]byte
	s1  VecL
	s2  VecK
	t0  VecK
	tr  [48]byte
}

type unpackedSignature struct {
	z    VecL
	hint VecK
	c    common.Poly
}

// Packs the signature into buf.
func (sig *unpackedSignature) Pack(buf []byte) {
	sig.z.PackLeGamma1(buf[:])
	sig.hint.PackHint(buf[L*common.PolyLeGamma1Size:])
	sig.c.PackB60(buf[L*common.PolyLeGamma1Size+Omega+K:])
}

// Sets sig to the signature encoded in the buffer.
//
// Returns whether buf contains a properly packed signature.
func (sig *unpackedSignature) Unpack(buf []byte) bool {
	if len(buf) < SignatureSize {
		return false
	}
	sig.z.UnpackLeGamma1(buf[:])
	if sig.z.Exceeds(common.Gamma1 - Beta) {
		return false
	}
	if !sig.hint.UnpackHint(buf[L*common.PolyLeGamma1Size:]) {
		return false
	}
	sig.c.UnpackB60(buf[L*common.PolyLeGamma1Size+Omega+K:])
	return true
}

// Packs the public key into buf.
func (pk *PublicKey) Pack(buf *[PublicKeySize]byte) {
	copy(buf[:32], pk.rho[:])
	copy(buf[32:], pk.t1p[:])
}

// Sets pk to the public key encoded in buf.
func (pk *PublicKey) Unpack(buf *[PublicKeySize]byte) {
	copy(pk.rho[:], buf[:32])
	copy(pk.t1p[:], buf[32:])
	pk.t1.UnpackT1(pk.t1p[:])
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	copy(buf[:32], sk.rho[:])
	copy(buf[32:64], sk.key[:])
	copy(buf[64:112], sk.tr[:])
	offset := 112
	sk.s1.PackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * L
	sk.s2.PackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * K
	sk.t0.PackT0(buf[offset:])
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	copy(sk.rho[:], buf[:32])
	copy(sk.key[:], buf[32:64])
	copy(sk.tr[:], buf[64:112])
	offset := 112
	sk.s1.UnpackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * L
	sk.s2.UnpackLeqEta(buf[offset:])
	offset += PolyLeqEtaSize * K
	sk.t0.UnpackT0(buf[offset:])
}

// TODO cache A?
// TODO cache tr?

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [32]byte
	if rand == nil {
		rand = cryptoRand.Reader
	}
	_, err := io.ReadFull(rand, seed[:])
	if err != nil {
		return nil, nil, err
	}
	pk, sk := NewKeyFromSeed(&seed)
	return pk, sk, nil
}

// NewKeyFromExpandedSeed derives a public/private key pair using the
// given expanded seed.
//
// Use NewKeyFromSeed instead of this function.  This function is only exposed
// to generate the NIST KAT test vectors.
func NewKeyFromExpandedSeed(seed *[96]byte) (*PublicKey, *PrivateKey) {
	var pk PublicKey
	var sk PrivateKey
	var sSeed [32]byte
	var t VecK

	var A Mat

	copy(pk.rho[:], seed[:32])
	copy(sSeed[:], seed[32:64])
	copy(sk.key[:], seed[64:])
	copy(sk.rho[:], pk.rho[:])

	A.Derive(&pk.rho)

	for i := uint16(0); i < L; i++ {
		PolyDeriveUniformLeqEta(&sk.s1[i], &sSeed, i)
	}

	for i := uint16(0); i < K; i++ {
		PolyDeriveUniformLeqEta(&sk.s2[i], &sSeed, i+L)
	}

	// Set t to A s1 + s2
	s1h := sk.s1
	s1h.NTT()
	for i := 0; i < K; i++ {
		PolyDotHat(&t[i], &A[i], &s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, &sk.s2)
	t.Normalize()

	// Compute t0, t1 = Power2Round(t)
	t.Power2Round(&sk.t0, &pk.t1)

	// Finish public key
	pk.t1.PackT1(pk.t1p[:])

	var packedPk [PublicKeySize]byte
	pk.Pack(&packedPk)
	h := shake.NewShake256()
	h.Write(packedPk[:])
	h.Read(sk.tr[:])

	return &pk, &sk
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[common.SeedSize]byte) (*PublicKey, *PrivateKey) {
	var buf [96]byte
	h := shake.NewShake128()
	h.Write(seed[:])
	h.Read(buf[:])
	return NewKeyFromExpandedSeed(&buf)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	var sig unpackedSignature
	var A Mat
	var tr, mu [48]byte
	var zh VecL
	var Az, Az2dct1, w1 VecK
	var ch, cp common.Poly

	// Note that Unpack() checked whether ‖z‖_∞ < γ_1 - β
	// and ensured that there at most ω ones in pk.hint.
	if !sig.Unpack(signature) {
		return false
	}

	A.Derive(&pk.rho)

	// tr = CRH(ρ ‖ t1)
	h := shake.NewShake256()
	h.Write(pk.rho[:])
	h.Write(pk.t1p[:])
	h.Read(tr[:])

	// μ = CRH(tr ‖ msg)
	h.Reset()
	h.Write(tr[:])
	h.Write(msg)
	h.Read(mu[:])

	// Compute Az
	zh = sig.z
	zh.NTT()

	for i := 0; i < K; i++ {
		PolyDotHat(&Az[i], &A[i], &zh)
	}

	// Next, we compute Az - 2^d·c·t1.
	// Note that the coefficients of t1 are bounded by 256 = 2^9,
	// so the coefficients of Az2dct1 will bounded by 2^{9+d} = 2^23 < 2q,
	// which is small enough for NTT().
	Az2dct1.MulBy2toD(&pk.t1)
	Az2dct1.NTT()
	ch = sig.c
	ch.NTT()
	for i := 0; i < K; i++ {
		Az2dct1[i].MulHat(&Az2dct1[i], &ch)
	}
	Az2dct1.Sub(&Az, &Az2dct1)
	Az2dct1.ReduceLe2Q()
	Az2dct1.InvNTT()
	Az2dct1.NormalizeAssumingLe2Q()

	// w1 = UseHint(pk.hint, Az - 2^d·c·t1).
	w1.UseHint(&Az2dct1, &sig.hint)

	// c' = H(μ, w1)
	PolyDeriveUniformB60(&cp, &mu, &w1)
	return sig.c == cp
}

// SignTo signs the given message and writes the signature into signature
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	var A Mat
	var mu, rhop [48]byte
	var s1h, y, yh VecL
	var s2h, t0h, w, w0, w1, w0mcs2, ct0, w0mcs2pct0 VecK
	var ch common.Poly
	var yNonce uint16
	var sig unpackedSignature

	if len(signature) < SignatureSize {
		panic("Signature does not fit in that byteslice")
	}

	A.Derive(&sk.rho)

	//  μ = CRH(tr ‖ msg)
	h := shake.NewShake256()
	h.Write(sk.tr[:])
	h.Write(msg)
	h.Read(mu[:])

	// ρ' = CRH(μ ‖ key)
	h.Reset()
	h.Write(sk.key[:])
	h.Write(mu[:])
	h.Read(rhop[:])

	// Precompute NTT(s1), NTT(s2) ad NTT(t0)
	s1h = sk.s1
	s1h.NTT()
	s2h = sk.s2
	s2h.NTT()
	t0h = sk.t0
	t0h.NTT()

	// Main rejection loop
	for {
		// y = ExpandMask(ρ', key)
		for i := 0; i < L; i++ {
			PolyDeriveUniformLeGamma1(&y[i], &rhop, yNonce)
			yNonce++
		}

		// Set w to A y
		yh = y
		yh.NTT()
		for i := 0; i < K; i++ {
			PolyDotHat(&w[i], &A[i], &yh)
			w[i].ReduceLe2Q()
			w[i].InvNTT()
		}

		// Decompose w into w0 and w1
		w.NormalizeAssumingLe2Q()
		w.Decompose(&w0, &w1)

		// c = H(μ, w1)
		PolyDeriveUniformB60(&sig.c, &mu, &w1)
		ch = sig.c
		ch.NTT()

		// TODO check reference implementation reduction of checks to these
		//      three cases.
		// Ensure ‖ w0 - c·s2 ‖_∞ < γ2 - β.  See Lemma 2 in the spec.
		for i := 0; i < K; i++ {
			w0mcs2[i].MulHat(&ch, &s2h[i])
			w0mcs2[i].InvNTT()
		}
		w0mcs2.Sub(&w0, &w0mcs2)
		w0mcs2.Normalize()

		if w0mcs2.Exceeds(common.Gamma2 - Beta) {
			continue
		}

		// z = y + c·s1
		for i := 0; i < L; i++ {
			sig.z[i].MulHat(&ch, &s1h[i])
			sig.z[i].InvNTT()
		}
		sig.z.Add(&sig.z, &y)
		sig.z.Normalize()

		// Ensure  ‖z‖_∞ < γ1 - β
		if sig.z.Exceeds(common.Gamma1 - Beta) {
			continue
		}

		// Compute c·t0
		for i := 0; i < K; i++ {
			ct0[i].MulHat(&ch, &t0h[i])
			ct0[i].InvNTT()
		}
		ct0.NormalizeAssumingLe2Q()

		// Ensure ‖c·t0‖_∞ < γ2.
		if ct0.Exceeds(common.Gamma2) {
			continue
		}

		// Create the hint
		w0mcs2pct0.Add(&w0mcs2, &ct0)
		w0mcs2pct0.NormalizeAssumingLe2Q()
		hintPop := sig.hint.MakeHint(&w0mcs2pct0, &w1)
		if hintPop > Omega {
			continue
		}

		break
	}

	sig.Pack(signature[:])
}