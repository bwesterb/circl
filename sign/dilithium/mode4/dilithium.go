// Package mode4 implements Dilithium signature scheme in mode4.
package mode4

import (
	"crypto"
	cryptoRand "crypto/rand"
	"errors"
	"io"

	"github.com/cloudflare/circl/internal/shake"
	common "github.com/cloudflare/circl/sign/dilithium/internal"
	"github.com/cloudflare/circl/sign/dilithium/mode4/internal"
)

const (
	Name = "Dilithium4"

	// Size of seed for NewKeyFromSeed
	SeedSize = common.SeedSize

	// Size of a packed PublicKey
	PublicKeySize = 1760

	// Size of a packed PrivateKey
	PrivateKeySize = 3856

	// Size of a signature
	SignatureSize = 3366
)

// PublicKey is the type of Dilithium public keys.
type PublicKey struct {
	rho [32]byte
	t1  internal.VecK

	// Cached values
	t1p [common.PolyT1Size * internal.K]byte
	A   *internal.Mat
	tr  *[48]byte
}

// PrivateKey is the type of Dilithium private keys.
type PrivateKey struct {
	rho [32]byte
	key [32]byte
	s1  internal.VecL
	s2  internal.VecK
	t0  internal.VecK
	tr  [48]byte

	// Cached values
	A   internal.Mat  // ExpandA(ρ)
	s1h internal.VecL // NTT(s1)
	s2h internal.VecK // NTT(s2)
	t0h internal.VecK // NTT(t0)
}

type unpackedSignature struct {
	z    internal.VecL
	hint internal.VecK
	c    common.Poly
}

// Packs the signature into buf.
func (sig *unpackedSignature) Pack(buf []byte) {
	sig.z.PackLeGamma1(buf[:])
	sig.hint.PackHint(buf[internal.L*common.PolyLeGamma1Size:])
	sig.c.PackB60(buf[internal.L*common.PolyLeGamma1Size+internal.Omega+internal.K:])
}

// Sets sig to the signature encoded in the buffer.
//
// Returns whether buf contains a properly packed signature.
func (sig *unpackedSignature) Unpack(buf []byte) bool {
	if len(buf) < SignatureSize {
		return false
	}
	sig.z.UnpackLeGamma1(buf[:])
	if sig.z.Exceeds(common.Gamma1 - internal.Beta) {
		return false
	}
	if !sig.hint.UnpackHint(buf[internal.L*common.PolyLeGamma1Size:]) {
		return false
	}
	sig.c.UnpackB60(buf[internal.L*common.PolyLeGamma1Size+internal.Omega+internal.K:])
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
	pk.A = new(internal.Mat)
	pk.A.Derive(&pk.rho)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	pk.tr = new([48]byte)
	h := shake.NewShake256()
	_, _ = h.Write(buf[:])
	_, _ = h.Read(pk.tr[:])
}

// Packs the private key into buf.
func (sk *PrivateKey) Pack(buf *[PrivateKeySize]byte) {
	copy(buf[:32], sk.rho[:])
	copy(buf[32:64], sk.key[:])
	copy(buf[64:112], sk.tr[:])
	offset := 112
	sk.s1.PackLeqEta(buf[offset:])
	offset += internal.PolyLeqEtaSize * internal.L
	sk.s2.PackLeqEta(buf[offset:])
	offset += internal.PolyLeqEtaSize * internal.K
	sk.t0.PackT0(buf[offset:])
}

// Sets sk to the private key encoded in buf.
func (sk *PrivateKey) Unpack(buf *[PrivateKeySize]byte) {
	copy(sk.rho[:], buf[:32])
	copy(sk.key[:], buf[32:64])
	copy(sk.tr[:], buf[64:112])
	offset := 112
	sk.s1.UnpackLeqEta(buf[offset:])
	offset += internal.PolyLeqEtaSize * internal.L
	sk.s2.UnpackLeqEta(buf[offset:])
	offset += internal.PolyLeqEtaSize * internal.K
	sk.t0.UnpackT0(buf[offset:])

	// Cached values
	sk.A.Derive(&sk.rho)
	sk.t0h = sk.t0
	sk.t0h.NTT()
	sk.s1h = sk.s1
	sk.s1h.NTT()
	sk.s2h = sk.s2
	sk.s2h.NTT()
}

// GenerateKey generates a public/private key pair using entropy from rand.
// If rand is nil, crypto/rand.Reader will be used.
func GenerateKey(rand io.Reader) (*PublicKey, *PrivateKey, error) {
	var seed [common.SeedSize]byte
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

	copy(pk.rho[:], seed[:32])
	copy(sSeed[:], seed[32:64])
	copy(sk.key[:], seed[64:])
	copy(sk.rho[:], pk.rho[:])

	sk.A.Derive(&pk.rho)

	for i := uint16(0); i < internal.L; i++ {
		internal.PolyDeriveUniformLeqEta(&sk.s1[i], &sSeed, i)
	}

	for i := uint16(0); i < internal.K; i++ {
		internal.PolyDeriveUniformLeqEta(&sk.s2[i], &sSeed, i+internal.L)
	}

	sk.s1h = sk.s1
	sk.s1h.NTT()
	sk.s2h = sk.s2
	sk.s2h.NTT()

	sk.computeT0andT1(&sk.t0, &pk.t1)

	sk.t0h = sk.t0
	sk.t0h.NTT()

	// Complete public key far enough to be packed
	pk.t1.PackT1(pk.t1p[:])
	pk.A = &sk.A

	// Finish private key
	var packedPk [PublicKeySize]byte
	pk.Pack(&packedPk)

	// tr = CRH(ρ ‖ t1) = CRH(pk)
	h := shake.NewShake256()
	_, _ = h.Write(packedPk[:])
	_, _ = h.Read(sk.tr[:])

	// Finish cache of public key
	pk.tr = &sk.tr

	return &pk, &sk
}

// Computes t0 and t1 from sk.s1h, sk.s2 and sk.A.
func (sk *PrivateKey) computeT0andT1(t0, t1 *internal.VecK) {
	var t internal.VecK

	// Set t to A s1 + s2
	for i := 0; i < internal.K; i++ {
		internal.PolyDotHat(&t[i], &sk.A[i], &sk.s1h)
		t[i].ReduceLe2Q()
		t[i].InvNTT()
	}
	t.Add(&t, &sk.s2)
	t.Normalize()

	// Compute t0, t1 = Power2Round(t)
	t.Power2Round(t0, t1)
}

// NewKeyFromSeed derives a public/private key pair using the given seed.
func NewKeyFromSeed(seed *[common.SeedSize]byte) (*PublicKey, *PrivateKey) {
	var buf [96]byte
	h := shake.NewShake128()
	_, _ = h.Write(seed[:])
	_, _ = h.Read(buf[:])
	return NewKeyFromExpandedSeed(&buf)
}

// Verify checks whether the given signature by pk on msg is valid.
func Verify(pk *PublicKey, msg []byte, signature []byte) bool {
	var sig unpackedSignature
	var mu [48]byte
	var zh internal.VecL
	var Az, Az2dct1, w1 internal.VecK
	var ch, cp common.Poly

	// Note that Unpack() checked whether ‖z‖_∞ < γ_1 - β
	// and ensured that there at most ω ones in pk.hint.
	if !sig.Unpack(signature) {
		return false
	}

	// μ = CRH(tr ‖ msg)
	h := shake.NewShake256()
	_, _ = h.Write(pk.tr[:])
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])

	// Compute Az
	zh = sig.z
	zh.NTT()

	for i := 0; i < internal.K; i++ {
		internal.PolyDotHat(&Az[i], &pk.A[i], &zh)
	}

	// Next, we compute Az - 2^d·c·t1.
	// Note that the coefficients of t1 are bounded by 256 = 2^9,
	// so the coefficients of Az2dct1 will bounded by 2^{9+d} = 2^23 < 2q,
	// which is small enough for NTT().
	Az2dct1.MulBy2toD(&pk.t1)
	Az2dct1.NTT()
	ch = sig.c
	ch.NTT()
	for i := 0; i < internal.K; i++ {
		Az2dct1[i].MulHat(&Az2dct1[i], &ch)
	}
	Az2dct1.Sub(&Az, &Az2dct1)
	Az2dct1.ReduceLe2Q()
	Az2dct1.InvNTT()
	Az2dct1.NormalizeAssumingLe2Q()

	// UseHint(pk.hint, Az - 2^d·c·t1)
	//    = UseHint(pk.hint, w - c·s2 + c·t0)
	//    = UseHint(pk.hint, r + c·t0)
	//    = r1 = w1.
	w1.UseHint(&Az2dct1, &sig.hint)

	// c' = H(μ, w1)
	internal.PolyDeriveUniformB60(&cp, &mu, &w1)
	return sig.c == cp
}

// SignTo signs the given message and writes the signature into signature.
func SignTo(sk *PrivateKey, msg []byte, signature []byte) {
	var mu, rhop [48]byte
	var y, yh internal.VecL
	var w, w0, w1, w0mcs2, ct0, w0mcs2pct0 internal.VecK
	var ch common.Poly
	var yNonce uint16
	var sig unpackedSignature

	if len(signature) < SignatureSize {
		panic("Signature does not fit in that byteslice")
	}

	//  μ = CRH(tr ‖ msg)
	h := shake.NewShake256()
	_, _ = h.Write(sk.tr[:])
	_, _ = h.Write(msg)
	_, _ = h.Read(mu[:])

	// ρ' = CRH(μ ‖ key)
	h.Reset()
	_, _ = h.Write(sk.key[:])
	_, _ = h.Write(mu[:])
	_, _ = h.Read(rhop[:])

	// Main rejection loop
	for {
		// y = ExpandMask(ρ', key)
		for i := 0; i < internal.L; i++ {
			internal.PolyDeriveUniformLeGamma1(&y[i], &rhop, yNonce)
			yNonce++
		}

		// Set w to A y
		yh = y
		yh.NTT()
		for i := 0; i < internal.K; i++ {
			internal.PolyDotHat(&w[i], &sk.A[i], &yh)
			w[i].ReduceLe2Q()
			w[i].InvNTT()
		}

		// Decompose w into w0 and w1
		w.NormalizeAssumingLe2Q()
		w.Decompose(&w0, &w1)

		// c = H(μ, w1)
		internal.PolyDeriveUniformB60(&sig.c, &mu, &w1)
		ch = sig.c
		ch.NTT()

		// Ensure ‖ w0 - c·s2 ‖_∞ < γ2 - β.
		//
		// By Lemma 3 of the specification this is equivalent to checking that
		// both ‖ r0 ‖_∞ < γ2 - β and r1 = w1, for the decomposition
		// w - c·s2 = r1 α + r0 as computed by decompose().
		// See also §4.1 of the specification.
		for i := 0; i < internal.K; i++ {
			w0mcs2[i].MulHat(&ch, &sk.s2h[i])
			w0mcs2[i].InvNTT()
		}
		w0mcs2.Sub(&w0, &w0mcs2)
		w0mcs2.Normalize()

		if w0mcs2.Exceeds(common.Gamma2 - internal.Beta) {
			continue
		}

		// z = y + c·s1
		for i := 0; i < internal.L; i++ {
			sig.z[i].MulHat(&ch, &sk.s1h[i])
			sig.z[i].InvNTT()
		}
		sig.z.Add(&sig.z, &y)
		sig.z.Normalize()

		// Ensure  ‖z‖_∞ < γ1 - β
		if sig.z.Exceeds(common.Gamma1 - internal.Beta) {
			continue
		}

		// Compute c·t0
		for i := 0; i < internal.K; i++ {
			ct0[i].MulHat(&ch, &sk.t0h[i])
			ct0[i].InvNTT()
		}
		ct0.NormalizeAssumingLe2Q()

		// Ensure ‖c·t0‖_∞ < γ2.
		if ct0.Exceeds(common.Gamma2) {
			continue
		}

		// Create the hint to be able to reconstruct w1 from w - c·s2 + c·t0.
		// Note that we're not using makeHint() in the obvious way as we
		// do not know whether ‖ sc·s2 - c·t0 ‖_∞ < γ2.  Instead we note
		// that our makeHint() is actually the same as a makeHint for a
		// different decomposition:
		//
		// Earlier we ensured indirectly with a check that r1 = w1 where
		// r = w - c·s2.  Hence r0 = r - r1 α = w - c·s2 - w1 α = w0 - c·s2.
		// Thus  MakeHint(w0 - c·s2 + c·t0, w1) = MakeHint(r0 + c·t0, r1)
		// and UseHint(w - c·s2 + c·t0, w1) = UseHint(r + c·t0, r1).
		// As we just ensured that ‖ c·t0 ‖_∞ < γ2 our usage is correct.
		w0mcs2pct0.Add(&w0mcs2, &ct0)
		w0mcs2pct0.NormalizeAssumingLe2Q()
		hintPop := sig.hint.MakeHint(&w0mcs2pct0, &w1)
		if hintPop > internal.Omega {
			continue
		}

		break
	}

	sig.Pack(signature[:])
}

// Computes the public key corresponding to this private key.
//
// Returns a *PublicKey.  The type crypto.PublicKey is used to make
// PrivateKey implement the crypto.Signer interface.
func (sk *PrivateKey) Public() crypto.PublicKey {
	var t0 internal.VecK
	pk := &PublicKey{
		rho: sk.rho,
		A:   &sk.A,
		tr:  &sk.tr,
	}
	sk.computeT0andT1(&t0, &pk.t1)
	pk.t1.PackT1(pk.t1p[:])
	return pk
}

// Sign signs the given message.
//
// opts.HashFunc() must return zero, which can be achieved by passing
// crypto.Hash(0) for opts.  rand is ignored.  Will only return an error
// if opts.HashFunc() is non-zero.
//
// This function is used to make PrivateKey implement the crypto.Signer
// interface.  The package-level SignTo function might be more convenient
// to use.
func (sk *PrivateKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (
	signature []byte, err error) {
	var sig [SignatureSize]byte

	if opts.HashFunc() != crypto.Hash(0) {
		return nil, errors.New("dilithium: cannot sign hashed message")
	}

	SignTo(sk, msg, sig[:])
	return sig[:], nil
}

func (pk *PublicKey) Bytes() []byte {
	ret := [PublicKeySize]byte{}
	pk.Pack(&ret)
	return ret[:]
}

func (sk *PrivateKey) Bytes() []byte {
	ret := [PrivateKeySize]byte{}
	sk.Pack(&ret)
	return ret[:]
}
