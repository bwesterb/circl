package internal

// Returns a y with y < 2q and y = x mod q.
// Note that in general *not*: reduceLe2Q(reduceLe2Q(x)) == x.
func reduceLe2Q(x uint32) uint32 {
	// Note 2^23 = 2^13 - 1 mod q. So, writing  x = x1 2^23 + x2 with x2 < 2^23
	// and x1 < 2^9, we have x = y (mod q) where
	// y = x2 + x1 2^13 - x1 ≤ 2^23 + 2^13 < 2q.
	x1 := x >> 23
	x2 := x & 0x7FFFFF // 2^23-1
	return x2 + (x1 << 13) - x1
}

// Returns x mod q.
func modQ(x uint32) uint32 {
	return le2qModQ(reduceLe2Q(x))
}

// For x R ≤ q 2^32, find y ≤ 2q with y = x mod q.
func montReduceLe2Q(x uint64) uint32 {
	// 4236238847 = -(q^-1) mod 2^32
	m := (x * 4236238847) & 0xffffffff
	return uint32((x + m*uint64(Q)) >> 32)
}

// Returns x mod q for 0 ≤ x < 2q.
func le2qModQ(x uint32) uint32 {
	x -= Q
	mask := uint32(int32(x) >> 31) // mask is 2^32-1 if x was neg.; 0 otherwise
	return x + (mask & Q)
}

// Splits 0 ≤ a < Q into a0 and a1 with a = a1*2^D + a0
// and -2^{D-1} < a0 < 2^{D-1}.  Returns a0 + Q and a1.
func power2round(a uint32) (a0plusQ, a1 uint32) {
	// We effectively compute a0 = a mod± 2^d
	//                    and a1 = (a - a0) / 2^d.
	a0 := a & ((1 << D) - 1) // a mod 2^d

	// a0 is one of  0, 1, ..., 2^{d-1}-1, 2^{d-1}, 2^{d-1}+1, ..., 2^d-1
	a0 -= (1 << (D - 1)) + 1
	// now a0 is     -2^{d-1}-1, -2^{d-1}, ..., -2, -1, 0, ..., 2^{d-1}-2
	// Next, we add 2^D to those a0 that are negative (seen as int32).
	a0 += uint32(int32(a0)>>31) & (1 << D)
	// now a0 is     2^{d-1}-1, 2^{d-1}, ..., 2^d-2, 2^d-1, 0, ..., 2^{d-1}-2
	a0 -= (1 << (D - 1)) - 1
	// now a0 id     0, 1, 2, ..., 2^{d-1}-1, 2^{d-1}-1, -2^{d-1}-1, ...
	// which is what we want.
	a0plusQ = Q + a0
	a1 = (a - a0) >> D
	return
}

// Splits 0 ≤ a < Q into a0 and a1 with a = a1*α + a0 with -α/2 < a0 ≤ α/2,
// except for when we would have a1 = (Q-1)/α = 16 in which case a1=0 is taken
// and -α/2 ≤ a0 < 0.  Returns a0 + Q.  Note 0 ≤ a1 ≤ 15.
// Note α = 2*γ2 = γ1 with the chosen parameters of Dilithium.
func decompose(a uint32) (a0plusQ, a1 uint32) {
	// Finds 0 ≤ t < 1.5α with t = a mod α.  (Recall α=2^19 - 2^9.)
	t := int32(a & 0x7ffff)
	t += (int32(a) >> 19) << 9

	// If 0 ≤ t < α, then the following computes a mod± α with the same
	// argument as in power2round().  If α ≤ t < 1.5α, then the following
	// subtracts α, which thus also computes a mod± α.
	t -= Alpha/2 + 1
	t += (t >> 31) & Alpha
	t -= Alpha/2 - 1

	a1 = a - uint32(t)

	// We want to divide α out of a1 (to get the proper value of a1).
	// As our values are relatively small and α=2^19-2^9, we can simply
	// divide by 2^19 and add one.  There is one corner case we have to deal
	// with: if a1=0 then 0/α=0≠1=0/2^19+1, so we need to get rid of the +1.
	u := ((a1 - 1) >> 31) & 1 // u=1 if a1=0
	a1 = (a1 >> 19) + 1
	a1 -= u // correct for the case a1=0

	a0plusQ = Q + uint32(t)

	// Now deal with the corner case of the definition, if a1=(Q-1)/α,
	// then we use a1=0.  Note (Q-1)/α=2^4.
	a0plusQ -= a1 >> 4 // to compensate, we only have to move the -1.
	a1 &= 15           // set a0=0 if a1=16
	return
}

// Assume 0 ≤ r, f < Q with ‖f‖_∞ ≤ α/2.  Decompose r as r = r1*α + r0 as
// computed by decompoes().  Write r' := r - f (mod Q).  Now, decompose
// r'=r-f again as  r' = r'1*α + r'0 using decompose().  As f is small, we
// have r'1 = r1 + h, where h ∈ {-1, 0, 1}.  makeHint() computes |h|
// given z0 := r0 - f (mod Q) and r1.  With |h|, which is called the hint,
// we can reconstruct r1 using only r' = r - f, which is done by useHint().
// To wit:
//
//     useHint( r - f, makeHint( r0 - f, r1 ) ) = r1.
//
// Assumes 0 ≤ z0 < Q.
func makeHint(z0, r1 uint32) uint32 {
	// If -α/2 < r0 - f ≤ α/2, then r1*α + r0 - f is a valid decomposition of r'
	// with the restrictions of decompose() and so r'1 = r1.  So the hint
	// should be 0. This is covered by the first two inequalities.
	// There is one other case: if r0 - f = -α/2, then r1*α + r0 - f is also
	// a valid decomposition if r1 = 0.  In the other cases a one is carried
	// and the hint should be 1.
	if z0 <= Gamma2 || z0 > Q-Gamma2 || (z0 == Q-Gamma2 && r1 == 0) {
		return 0
	}
	return 1
}

// Uses the hint created by makeHint() to reconstruct r1 from r'=r-f; see
// documentation of makeHint() for context.
// Assumes 0 ≤ r' < Q.
func useHint(rp uint32, hint uint32) uint32 {
	rp0plusQ, rp1 := decompose(rp)
	if hint == 0 {
		return rp1
	}
	if rp0plusQ > Q {
		return (rp1 + 1) & 15
	}
	return (rp1 - 1) & 15
}
