// +build ignore

package main

import (
	. "github.com/mmcloughlin/avo/build"
	. "github.com/mmcloughlin/avo/operand"
	. "github.com/mmcloughlin/avo/reg"
)

func broadcast_imm32(c uint32, out Op) {
	tmp1 := GP32()
	tmp2 := XMM()
	MOVL(U32(c), tmp1)
	VMOVD(tmp1, tmp2)
	VPBROADCASTD(tmp2, out)
}

// Performs AND with an 64b immediate.
// See https://github.com/mmcloughlin/avo/issues/50
// XXX report bug
func and_imm64(c uint64, inout Op) {
	tmp := GP64()
	MOVQ(U64(c), tmp)
	ANDQ(tmp, inout)
}

// Executes the permutation (a[2] b[0]) (a[3] b[1])
func swapInner(a, b Op) {
	tmp := YMM()
	VPERM2I128(U8(32), b, a, tmp) // 0 + 2*16
	VPERM2I128(U8(49), b, a, b)   // 1 + 3*16
	VMOVDQA(tmp, a)
}

// Executes the permutation (a[1] b[0]) (a[3] b[2])
func oddCrossing(a, b Op) {
	tmp := YMM()
	VPUNPCKLQDQ(b, a, tmp)
	VPUNPCKHQDQ(b, a, b)
	VMOVDQA(tmp, a)
}

func main() {
	TEXT("ntt", 0, "func(p *[256]uint32)")
	p_ptr := Load(Param("p"), GP64())
	zetas_ptr := GP64()
	LEAQ(NewDataAddr(Symbol{Name: "·Zetas"}, 0), zetas_ptr)

	// We allocate a [256]uint64 on the stack aligned to 32 bytes to hold
	// "buf" which contains intermediate coefficients like "p" in the generic
	// algorithm, but then in uint64s instead of uint32s.
	buf_ptr := GP64()
	LEAQ(AllocLocal(256*8+32), buf_ptr) // +32 to be able to align

	and_imm64(0xffffffffffffffe0, buf_ptr)

	Q := uint32(8380417) // XXX

	q := YMM()
	broadcast_imm32(Q, q)
	doubleQ := YMM()
	broadcast_imm32(2*Q, doubleQ)
	qinv := YMM()
	broadcast_imm32(4236238847, qinv) // 4236238847 = -(q^-1) mod 2^32

	// Computes 4x4 Cooley--Tukey butterflies (a,b) |-> (a + ζb, a - ζb).
	butterfly := func(a1, b1, zeta1, a2, b2, zeta2, a3, b3, zeta3,
		a4, b4, zeta4 Op) {
		t := [4]Op{YMM(), YMM(), YMM(), YMM()}
		a := [4]Op{a1, a2, a3, a4}
		b := [4]Op{b1, b2, b3, b4}
		zeta := [4]Op{zeta1, zeta2, zeta3, zeta4}

		// Set b = bζ.
		for i := 0; i < 4; i++ {
			VPMULUDQ(b[i], zeta[i], b[i])
		}

		// Now we reduce b below 2Q with the method of reduceLe2Q():
		//
		//      t := ((b * 4236238847) & 0xffffffff) * uint64(Q)
		//      return uint32((b + t) >> 32)
		for i := 0; i < 4; i++ {
			// t = b * 4236238847.
			VPMULUDQ(qinv, b[i], t[i])
		}

		// t = (t & 0xffffffff) * Q.  The and is implicit as VPMULUDQ
		// is a parallel 32b x 32b -> 64b multiplication.
		for i := 0; i < 4; i++ {
			VPMULUDQ(q, t[i], t[i])
		}

		// t = b + t
		for i := 0; i < 4; i++ {
			VPADDQ(t[i], b[i], t[i])
		}

		// t = t >> 32
		for i := 0; i < 4; i++ {
			VPSRLQ(U8(32), t[i], t[i])
		}

		// b = a + 2Q
		for i := 0; i < 4; i++ {
			VPADDD(a[i], doubleQ, b[i])
		}

		// a += t
		for i := 0; i < 4; i++ {
			VPADDD(t[i], a[i], a[i])
		}

		// b = b - t
		for i := 0; i < 4; i++ {
			VPSUBD(t[i], b[i], b[i])
		}
	}

	zs := [4]Op{YMM(), YMM(), YMM(), YMM()}
	var xs [8]VecVirtual

	// With AVX2 we can compute 4*4 Cooley--Tukey butterflies at the same time.
	// As loading and storing from memory is expensive, we try to compute
	// as much at the same time.

	// First, second and third level.
	// The first butterfly at the third level is (0, 32).  To compute it, we
	// need to compute some butterflies on the second level and in turn
	// the butterflies (0, 128), (32, 160), (64, 192) and (96, 224) on the
	// first level.  As we need to compute them anyway, we compute the
	// butterflies (0, 32), (64, 96), (128, 160) and (192, 224) on the
	// third level at the same time.  Using the uint64x4 AVX2 registers,
	// we compute (0, 32), (1, 33), ..., (4, 36), (64, 96), (64, 97), ...
	// in one go.  This is one eighth of the third level.  We repeat another
	// seven times with a shifted offset to compute the third level.

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		// First level.
		// Load the coefficients.  First uint32s of xs[0], xs[1], ...
		// contains p[0], p[32], p[64], ..., p[224].
		for i := 0; i < 8; i++ {
			// Loads 4 32b coefficients at the same time; zeropads them to 64b
			// and puts them in xs[i].
			xs[i] = YMM()
			VPMOVZXDQ(Mem{Base: p_ptr, Disp: 4 * (32*i + 4*offset)}, xs[i])
		}

		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 1 * 4}, zs[0]) // Zetas[1]

		butterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Second level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 2 * 4}, zs[0]) // Zetas[2]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 3 * 4}, zs[1]) // Zetas[3]

		butterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Third level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 4 * 4}, zs[0]) // Zetas[4]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 5 * 4}, zs[1]) // Zetas[5]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 6 * 4}, zs[2]) // Zetas[6]
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: 7 * 4}, zs[3]) // Zetas[7]

		butterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		for i := 0; i < 8; i++ {
			VMOVDQA(xs[i], Mem{Base: buf_ptr, Disp: 8 * (32*i + 4*offset)})
		}
	}

	// Fourth, fifth, sixth, seventh and eighth level.
	// If we want to compute the butterfly (0, 1) in the eighth level, we need
	// to compute the first 2 butterflies in the seventh level; the first 4
	// of the sixth, ... and the first 16 in the fourth level which needs the
	// first 32 coefficients already computed in the third level.
	// Going forward again, we see that we can use these to compute the first
	// 32 coefficients.  As each level requires 16 butterflies, we can
	// conveniently perform these all in our YMM registers.
	// After that we repeat the same method for the next 32 coefficients and
	// continue for a total of eight times to finish the computation of
	// the NTT.

	// XXX should we really unroll this loop?
	for offset := 0; offset < 8; offset++ {
		// Load the first 32 coefficients from level 3.  Recall that buf_ptr
		// has 64 bits of space for each coefficient.
		for i := 0; i < 8; i++ {
			VMOVDQA(Mem{Base: buf_ptr, Disp: 8 * 4 * (8*offset + i)}, xs[i])
		}

		// Fourth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (8 + offset) * 4}, zs[0])
		butterfly(
			xs[0], xs[4], zs[0],
			xs[1], xs[5], zs[0],
			xs[2], xs[6], zs[0],
			xs[3], xs[7], zs[0],
		)

		// Fifth level
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (16 + offset*2) * 4}, zs[0])
		VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (16 + offset*2 + 1) * 4}, zs[1])
		butterfly(
			xs[0], xs[2], zs[0],
			xs[1], xs[3], zs[0],
			xs[4], xs[6], zs[1],
			xs[5], xs[7], zs[1],
		)

		// Sixth level
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (32 + offset*4 + i) * 4}, zs[i])
		}
		butterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Seventh level
		// Now things get a bit trickier.  We have to compute the butterflies
		// (0, 2), (1, 3), (4, 6), (5, 7), etc which don't fit our butterfly()
		// routine, which likes to have four consecutive butterflies.
		// To work around this, we swap 2 with 4 and 3 with 5, etc., which
		// allows us to use our old routine.

		tmp := YMM()
		// XXX optimize?  We might want to add a small extra table for just
		//     these zetas so that we don't have to blend them.
		for i := 0; i < 4; i++ {
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (64 + offset*8 + i*2) * 4}, tmp)
			VPBROADCASTD(Mem{Base: zetas_ptr, Disp: (64 + offset*8 + i*2 + 1) * 4}, zs[i])
			VPBLENDD(U8(240), zs[i], tmp, zs[i])
		}

		swapInner(xs[0], xs[1])
		swapInner(xs[2], xs[3])
		swapInner(xs[4], xs[5])
		swapInner(xs[6], xs[7])

		butterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Eighth level
		// Finally, we have to perform the butterflies (0, 1), (2, 3), etc.
		// Swapping 1 with 4 and 3 with 6 (etc.) will ensure that a
		// straight-forward call to our butterfly() routine will do the right
		// thing.
		oddCrossing(xs[0], xs[1])
		oddCrossing(xs[2], xs[3])
		oddCrossing(xs[4], xs[5])
		oddCrossing(xs[6], xs[7])

		for i := 0; i < 4; i++ {
			VPMOVZXDQ(Mem{Base: zetas_ptr, Disp: (128 + 4*i + offset*16) * 4}, zs[i])
		}

		butterfly(
			xs[0], xs[1], zs[0],
			xs[2], xs[3], zs[1],
			xs[4], xs[5], zs[2],
			xs[6], xs[7], zs[3],
		)

		// Packing.
		// Due to swapInner() and oddCrossing() our coefficients are laid out
		// as 0, 2, 4, 6, 1, 3, 5, 7, 8, 10, ... in xs[0], xs[1], ...
		// with junk 32b in between.  By shifting the odd xss 32b to the
		// left and merging them with the even xss, we get the desired
		// order 0, 1, 2, 3, ... without any padding, which can then be
		// moved out into memeory.

		VPSLLQ(U8(32), xs[1], xs[1])
		VPSLLQ(U8(32), xs[3], xs[3])
		VPSLLQ(U8(32), xs[5], xs[5])
		VPSLLQ(U8(32), xs[7], xs[7])

		VPBLENDD(U8(170), xs[1], xs[0], xs[0])
		VPBLENDD(U8(170), xs[3], xs[2], xs[2])
		VPBLENDD(U8(170), xs[5], xs[4], xs[4])
		VPBLENDD(U8(170), xs[7], xs[6], xs[6])

		for i := 0; i < 4; i++ {
			VMOVDQA(xs[2*i], Mem{Base: p_ptr, Disp: 8 * 4 * (4*offset + i)})
		}
	}

	RET()
	Generate()
}
