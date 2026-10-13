package raywire

import (
	"bytes"
	"encoding/hex"
	"io"
	"math"
	"math/big"
	mrand "math/rand/v2"
	"testing"
	"testing/iotest"

	"golang.org/x/crypto/curve25519"
)

// ellSource returns a deterministic byte stream for the tests.
func ellSource(seed byte) io.Reader {
	var s [32]byte
	s[0] = seed
	return mrand.NewChaCha8(s)
}

func ellRead(t *testing.T, src io.Reader, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := io.ReadFull(src, b); err != nil {
		t.Fatal(err)
	}
	return b
}

// ellField returns a uniform element of [0, p) in LE32.
func ellField(t *testing.T, src io.Reader) []byte {
	t.Helper()
	b := ellRead(t, src, 32)
	b[31] &= 0x7f
	return feToLE(new(big.Int).Mod(feFromLE(b), elliP))
}

// ellPoint returns a uniform curve point u, with g(u) a square, in LE32.
func ellPoint(t *testing.T, src io.Reader) []byte {
	t.Helper()
	for {
		u := ellField(t, src)
		if big.Jacobi(elliG(feFromLE(u)), elliP) == 1 {
			return u
		}
	}
}

// ellOnCurve reports whether u is a canonical point with g(u) a square or zero.
func ellOnCurve(u []byte) bool {
	if len(u) != 32 {
		return false
	}
	x := feFromLE(u)
	return x.Cmp(elliP) < 0 && big.Jacobi(elliG(x), elliP) != -1
}

// ellBranchOne reports whether r is a branch-1 preimage, that is F(r) = x1(r).
// Bit 255 of r is ignored.
func ellBranchOne(r []byte) bool {
	b := append([]byte(nil), r...)
	b[31] &= 0x7f
	x := new(big.Int).Mod(feFromLE(b), elliP)
	d := new(big.Int).Mul(x, x)
	d.Lsh(d, 1)
	d.Add(d, big.NewInt(1))
	d.Mod(d, elliP)
	x1 := new(big.Int).ModInverse(d, elliP)
	x1.Mul(x1, elliNegA)
	x1.Mod(x1, elliP)
	return x1.Cmp(elliForward(x)) == 0
}

// ellNeg returns -x mod p.
func ellNeg(x *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Neg(x), elliP)
}

func ellMustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestElligatorFieldFacts(t *testing.T) {
	if new(big.Int).Mod(elliP, big.NewInt(8)).Int64() != 5 {
		t.Fatal("p is not 5 mod 8, so 2 is a non-square as the map assumes")
	}
	if big.Jacobi(big.NewInt(2), elliP) != -1 {
		t.Fatal("2 is a square mod p")
	}
	// (p-1)/2 is -1/2 mod p. It must be a non-square, so 1+2r^2 is never zero.
	half := new(big.Int).Rsh(new(big.Int).Sub(elliP, big.NewInt(1)), 1)
	if big.Jacobi(half, elliP) != -1 {
		t.Fatal("-1/2 is a square mod p")
	}
}

func TestElligatorFOnCurve(t *testing.T) {
	src := ellSource(1)
	for range 10000 {
		r := ellField(t, src)
		if u := elligatorF(r); !ellOnCurve(u) {
			t.Fatalf("F(%x) = %x is not on the curve", r, u)
		}
	}
}

func TestElligatorFiberOfFour(t *testing.T) {
	// F(r) = F(-r) = F(1/(2r)) = F(-1/(2r)). wireForm picks among all four,
	// so each one must decode to the same point.
	src := ellSource(2)
	for range 200 {
		r := ellField(t, src)
		x := feFromLE(r)
		if x.Sign() == 0 {
			continue
		}
		u := elligatorF(r)
		twice := new(big.Int).Mod(new(big.Int).Lsh(x, 1), elliP)
		half := new(big.Int).ModInverse(twice, elliP)
		for _, s := range []*big.Int{x, ellNeg(x), half, ellNeg(half)} {
			if got := elligatorF(feToLE(s)); !bytes.Equal(got, u) {
				t.Fatalf("preimage %x of %x maps to %x", feToLE(s), u, got)
			}
		}
	}
}

func TestElligatorFZero(t *testing.T) {
	// F(0) is the low-order point 0, which X25519 rejects.
	zero := make([]byte, 32)
	if got := elligatorF(zero); !bytes.Equal(got, zero) {
		t.Fatalf("F(0) = %x, want 0", got)
	}
}

func TestElligatorFixedVectors(t *testing.T) {
	// Pinned from an independent Python implementation of the same map.
	for _, v := range []struct{ r, u string }{
		{"0100000000000000000000000000000000000000000000000000000000000000", "9cdb525555555555555555555555555555555555555555555555555555555555"},
		{"0200000000000000000000000000000000000000000000000000000000000000", "b349328ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388ee3388e63"},
		{"0300000000000000000000000000000000000000000000000000000000000000", "55c4aea1bc86f21aca6b28afa1bc86f21aca6b28afa1bc86f21aca6b28afa13c"},
		{"efcdab9078563412000000000000000000000000000000000000000000000000", "25f03fedeb07906bed8a8c5e79c739e37eddcd0b186b511f8ee71a8ff2dc6141"},
		{"f6ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff3f", "9cdb525555555555555555555555555555555555555555555555555555555555"},
	} {
		r := ellMustHex(t, v.r)
		u := ellMustHex(t, v.u)
		if got := elligatorF(r); !bytes.Equal(got, u) {
			t.Fatalf("F(%x) = %x, want %x", r, got, u)
		}
		back, ok := elligatorE(u)
		if !ok {
			t.Fatalf("E(%x) not encodable", u)
		}
		if got := elligatorF(back); !bytes.Equal(got, u) {
			t.Fatalf("F(E(%x)) = %x", u, got)
		}
	}
}

func TestElligatorEInverse(t *testing.T) {
	src := ellSource(3)
	const n = 10000
	encodable := 0
	for range n {
		u := ellPoint(t, src)
		r, ok := elligatorE(u)
		if !ok {
			continue
		}
		encodable++
		if got := elligatorF(r); !bytes.Equal(got, u) {
			t.Fatalf("F(E(%x)) = %x", u, got)
		}
		if !ellBranchOne(r) {
			t.Fatalf("E(%x) = %x is not a branch-1 preimage", u, r)
		}
	}
	if f := float64(encodable) / n; f < 0.45 || f > 0.55 {
		t.Fatalf("encodable fraction %.4f is outside [0.45, 0.55]", f)
	}
}

func TestElligatorERejects(t *testing.T) {
	src := ellSource(4)
	for off := 0; off < 200; {
		x := ellField(t, src)
		if big.Jacobi(elliG(feFromLE(x)), elliP) != -1 {
			continue
		}
		off++
		if _, ok := elligatorE(x); ok {
			t.Fatalf("off-curve %x was encodable", x)
		}
	}
	if _, ok := elligatorE(feToLE(elliP)); ok {
		t.Fatal("non-canonical u = p was accepted")
	}
	short := make([]byte, 31)
	if _, ok := elligatorE(short); ok {
		t.Fatal("31-byte u was accepted")
	}
	if elligatorF(short) != nil || elligatorDecode(short) != nil {
		t.Fatal("31-byte input did not return nil")
	}
}

func TestElligatorDecodeIgnoresTopBit(t *testing.T) {
	src := ellSource(5)
	for range 1000 {
		R := ellRead(t, src, 32)
		flipped := append([]byte(nil), R...)
		flipped[31] ^= 0x80
		if !bytes.Equal(elligatorDecode(R), elligatorDecode(flipped)) {
			t.Fatalf("bit 255 changes the point decoded from %x", R)
		}
	}
	// Values in [p, 2^255) are reduced mod p: 2^255-1 is 18 and p+5 is 5.
	ones := bytes.Repeat([]byte{0xff}, 32)
	if !bytes.Equal(elligatorDecode(ones), elligatorF(feToLE(big.NewInt(18)))) {
		t.Fatal("2^255-1 is not reduced to 18")
	}
	high := feToLE(new(big.Int).Add(elliP, big.NewInt(5)))
	if !bytes.Equal(elligatorDecode(high), elligatorF(feToLE(big.NewInt(5)))) {
		t.Fatal("p+5 is not reduced to 5")
	}
}

func TestWireFormCoversFiber(t *testing.T) {
	src := ellSource(6)
	for range 200 {
		u := ellPoint(t, src)
		r, ok := elligatorE(u)
		if !ok {
			continue
		}
		seen := make(map[string]bool)
		for _, b := range []byte{0, 1, 2, 3, 0x80, 0x81, 0x82, 0x83} {
			R := wireForm(r, bytes.NewReader([]byte{b}))
			if R == nil {
				t.Fatal("wireForm failed")
			}
			if !bytes.Equal(elligatorDecode(R), u) {
				t.Fatalf("wire form %x decodes to another point than %x", R, u)
			}
			if R[31]>>7 != b>>7 {
				t.Fatalf("bit 255 of %x is not the random bit of %#x", R, b)
			}
			body := append([]byte(nil), R...)
			body[31] &= 0x7f
			seen[string(body)] = true
		}
		if len(seen) != 4 {
			t.Fatalf("wire forms of %x cover %d representatives, want 4", u, len(seen))
		}
	}
}

func TestWireFormBalance(t *testing.T) {
	// Without the partner choice, every wire form would be a branch-1
	// preimage, and the branch-1 fraction would be 1.
	src := ellSource(7)
	const n = 4000
	samples, branchOne, bit254 := 0, 0, 0
	for range n {
		u := ellPoint(t, src)
		r, ok := elligatorE(u)
		if !ok {
			continue
		}
		R := wireForm(r, src)
		if R == nil {
			t.Fatal("wireForm failed")
		}
		samples++
		if ellBranchOne(R) {
			branchOne++
		}
		if R[31]&0x40 != 0 {
			bit254++
		}
	}
	for name, c := range map[string]int{"branch-1": branchOne, "bit 254": bit254} {
		if f := float64(c) / float64(samples); f < 0.45 || f > 0.55 {
			t.Fatalf("%s fraction %.4f is outside [0.45, 0.55]", name, f)
		}
	}
}

func TestWireFormRoundTrip(t *testing.T) {
	src := ellSource(8)
	for range 1000 {
		u := ellPoint(t, src)
		r, ok := elligatorE(u)
		if !ok {
			continue
		}
		R := wireForm(r, src)
		if R == nil {
			t.Fatal("wireForm failed")
		}
		back := elligatorDecode(R)
		if !bytes.Equal(back, u) {
			t.Fatalf("decode(wireForm(%x)) = %x, want %x", r, back, u)
		}
		j := ellRead(t, src, 32)
		want, err := curve25519.X25519(j, u)
		if err != nil {
			t.Fatal(err)
		}
		got, err := curve25519.X25519(j, back)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("X25519 differs after the wire round trip for %x", u)
		}
	}
}

func TestWireFormRejects(t *testing.T) {
	src := ellSource(9)
	if wireForm(make([]byte, 31), src) != nil {
		t.Fatal("31-byte r was accepted")
	}
	if wireForm(feToLE(elliP), src) != nil {
		t.Fatal("r = p was accepted")
	}
	if wireForm(make([]byte, 32), iotest.ErrReader(io.ErrUnexpectedEOF)) != nil {
		t.Fatal("a failing reader did not return nil")
	}
}

func TestEncodableKey(t *testing.T) {
	src := ellSource(10)
	for range 300 {
		k, u, r, err := encodableKey(src)
		if err != nil {
			t.Fatal(err)
		}
		pub, err := curve25519.X25519(k, curve25519.Basepoint)
		if err != nil || !bytes.Equal(pub, u) {
			t.Fatalf("public key %x does not belong to private key %x", u, k)
		}
		// r encodes u + T, and removing T gives back the subgroup point u.
		if got := canonicalPoint(elligatorF(r)); !bytes.Equal(got, u) {
			t.Fatalf("canonical(F(r)) = %x, want %x", got, u)
		}
	}
}

func TestEncodableKeyReadError(t *testing.T) {
	if _, _, _, err := encodableKey(iotest.ErrReader(io.ErrUnexpectedEOF)); err == nil {
		t.Fatal("a failing reader did not return an error")
	}
}

// ellRepeat returns the same key bytes on every read and counts the reads.
type ellRepeat struct {
	key   []byte
	reads int
}

func (r *ellRepeat) Read(p []byte) (int, error) {
	r.reads++
	return copy(p, r.key), nil
}

func TestEncodableKeyBound(t *testing.T) {
	// The torsion point is chosen by the key's first byte, because the reader
	// repeats it. A key is unusable when its shift by that point is not encodable.
	var key []byte
	for i := range 256 {
		k := make([]byte, 32)
		k[0] = byte(i)
		u, err := curve25519.X25519(k, curve25519.Basepoint)
		if err != nil {
			continue
		}
		shifted := torsionShift(u, i&7)
		if _, ok := elligatorE(shifted); shifted == nil || !ok {
			key = k
			break
		}
	}
	if key == nil {
		t.Fatal("no unusable key among the first 256 scalars")
	}
	src := &ellRepeat{key: key}
	if _, _, _, err := encodableKey(src); err == nil {
		t.Fatal("encodableKey succeeded with a reader that repeats an unusable key")
	}
	// Each attempt reads the key and then the torsion selector.
	if src.reads != 2*maxEncodableAttempts {
		t.Fatalf("encodableKey read %d times, want %d", src.reads, 2*maxEncodableAttempts)
	}
}

// ellInSubgroup reports whether the point with u-coordinate u is in the
// prime-order subgroup, that is whether [l]u is the point at infinity.
func ellInSubgroup(u []byte) bool {
	x := feFromLE(u)
	return x.Sign() != 0 && elliLadder(elliL, x) == nil
}

// ellSameAffine reports whether two affine points are equal. nil is infinity.
func ellSameAffine(P, Q *elliPoint) bool {
	if P == nil || Q == nil {
		return P == Q
	}
	return P.u.Cmp(Q.u) == 0 && P.v.Cmp(Q.v) == 0
}

// ellIn reports whether P is one of the points in set.
func ellIn(P *elliPoint, set []*elliPoint) bool {
	for _, Q := range set {
		if ellSameAffine(P, Q) {
			return true
		}
	}
	return false
}

// ellOnCurveAffine reports whether P satisfies v^2 = g(u), or is infinity.
func ellOnCurveAffine(P *elliPoint) bool {
	if P == nil {
		return true
	}
	lhs := new(big.Int).Mul(P.v, P.v)
	lhs.Mod(lhs, elliP)
	return lhs.Cmp(elliG(P.u)) == 0
}

// ellNegAffine returns -P.
func ellNegAffine(P *elliPoint) *elliPoint {
	if P == nil {
		return nil
	}
	return &elliPoint{u: P.u, v: new(big.Int).Sub(elliP, P.v)}
}

// ellMulAffine returns [k]P by double-and-add with the affine formulas.
func ellMulAffine(k *big.Int, P *elliPoint) *elliPoint {
	var R *elliPoint
	Q := P
	for i := range k.BitLen() {
		if k.Bit(i) == 1 {
			R = elliAdd(R, Q)
		}
		Q = elliAdd(Q, Q)
	}
	return R
}

// ellLiftRand returns a random point of the curve with its v-coordinate.
func ellLiftRand(t *testing.T, src io.Reader) *elliPoint {
	t.Helper()
	P := elliLift(feFromLE(ellPoint(t, src)))
	if P == nil {
		t.Fatal("a point with g(u) a square did not lift")
	}
	return P
}

func TestTorsionSubgroup(t *testing.T) {
	if len(elliTorsion) != 8 {
		t.Fatalf("torsion table holds %d points, want 8", len(elliTorsion))
	}
	// u = -1 is not on the curve, so the order-4 point has u = 1.
	if big.Jacobi(elliG(new(big.Int).Sub(elliP, big.NewInt(1))), elliP) == 1 {
		t.Fatal("u = -1 is on the curve, so the table would be incomplete")
	}
	orderOf := func(P *elliPoint) int {
		for _, m := range []int64{1, 2, 4, 8} {
			if ellMulAffine(big.NewInt(m), P) == nil {
				return int(m)
			}
		}
		return 0
	}
	orders := map[int]int{}
	for _, P := range elliTorsion {
		if !ellOnCurveAffine(P) {
			t.Fatalf("torsion point %v is not on the curve", P)
		}
		orders[orderOf(P)]++
	}
	// One identity, one point of order 2, two of order 4 and four of order 8.
	if orders[1] != 1 || orders[2] != 1 || orders[4] != 2 || orders[8] != 4 {
		t.Fatalf("orders of E[8] are %v", orders)
	}
	// The eight points close under addition.
	for _, P := range elliTorsion {
		for _, Q := range elliTorsion {
			if !ellIn(elliAdd(P, Q), elliTorsion) {
				t.Fatal("E[8] is not closed under addition")
			}
		}
	}
	// The table is the whole of E[8]: [l]P is in it for random points P.
	src := ellSource(16)
	for range 20 {
		if T := ellMulAffine(elliL, ellLiftRand(t, src)); !ellIn(T, elliTorsion) {
			t.Fatalf("[l]P = %v is not in the torsion table", T)
		}
	}
}

func TestAffineAdditionLaws(t *testing.T) {
	src := ellSource(15)
	for range 20 {
		P := ellLiftRand(t, src)
		Q := ellLiftRand(t, src)
		R := ellLiftRand(t, src)
		if !ellSameAffine(elliAdd(nil, P), P) || !ellSameAffine(elliAdd(P, nil), P) {
			t.Fatal("adding the point at infinity changed the point")
		}
		if elliAdd(P, ellNegAffine(P)) != nil {
			t.Fatal("P + (-P) is not the point at infinity")
		}
		PQ := elliAdd(P, Q)
		if !ellOnCurveAffine(PQ) {
			t.Fatal("P + Q is not on the curve")
		}
		if !ellSameAffine(PQ, elliAdd(Q, P)) {
			t.Fatal("addition is not commutative")
		}
		if !ellSameAffine(elliAdd(PQ, R), elliAdd(P, elliAdd(Q, R))) {
			t.Fatal("addition is not associative")
		}
		// The doubling branch agrees with the x-only ladder.
		D := elliAdd(P, P)
		if !ellOnCurveAffine(D) {
			t.Fatal("2P is not on the curve")
		}
		if got := elliLadder(big.NewInt(2), P.u); got == nil || got.Cmp(D.u) != 0 {
			t.Fatalf("ladder gives 2P = %x, affine gives %x", got, D.u)
		}
	}
	// Doubling a point of order 2 gives the identity, and doubling a point of
	// order 4 gives the point of order 2.
	order2 := elliTorsion[1]
	if elliAdd(order2, order2) != nil {
		t.Fatal("2 * (0,0) is not the point at infinity")
	}
	order4 := elliTorsion[2]
	if d := elliAdd(order4, order4); d == nil || d.u.Sign() != 0 {
		t.Fatal("2 * (order-4 point) is not (0, 0)")
	}
}

func TestLadderMatchesAffine(t *testing.T) {
	src := ellSource(14)
	scalars := []*big.Int{big.NewInt(0), big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(8), elliL}
	for range 6 {
		scalars = append(scalars, new(big.Int).SetBytes(ellRead(t, src, 32)))
	}
	for range 4 {
		P := ellLiftRand(t, src)
		for _, k := range scalars {
			want := ellMulAffine(k, P)
			got := elliLadder(k, P.u)
			if (want == nil) != (got == nil) || (want != nil && got.Cmp(want.u) != 0) {
				t.Fatalf("[%v]P: ladder %x, affine %v", k, got, want)
			}
		}
	}
}

func TestCanonicalPoint(t *testing.T) {
	src := ellSource(17)
	for range 20 {
		k := ellRead(t, src, 32)
		u, err := curve25519.X25519(k, curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		if !ellInSubgroup(u) {
			t.Fatalf("public key %x is not in the prime-order subgroup", u)
		}
		// A subgroup point is its own canonical point.
		if got := canonicalPoint(u); !bytes.Equal(got, u) {
			t.Fatalf("canonical(%x) = %x", u, got)
		}
	}
	// The canonical point of any curve point is in the subgroup.
	for range 20 {
		c := canonicalPoint(ellPoint(t, src))
		if c == nil || !ellInSubgroup(c) {
			t.Fatalf("canonical point %x is not in the subgroup", c)
		}
	}
	for _, bad := range [][]byte{make([]byte, 32), feToLE(elliP), make([]byte, 31)} {
		if canonicalPoint(bad) != nil {
			t.Fatalf("canonicalPoint accepted %x", bad)
		}
	}
}

// TestTorsionShiftRoundTrip checks the sender's encoding. For each key and each
// of the eight torsion points, the encoded point u + T round trips through the
// wire form, the receiver's canonical point is u, and X25519 by a clamped scalar
// gives the same value for u + T as for u.
func TestTorsionShiftRoundTrip(t *testing.T) {
	src := ellSource(18)
	encodable := 0
	for range 64 {
		u, err := curve25519.X25519(ellRead(t, src, 32), curve25519.Basepoint)
		if err != nil {
			t.Fatal(err)
		}
		for sel := range 8 {
			shifted := torsionShift(u, sel)
			if shifted == nil {
				t.Fatalf("shift %d of %x failed", sel, u)
			}
			r, ok := elligatorE(shifted)
			if !ok {
				continue
			}
			encodable++
			R := wireForm(r, src)
			if R == nil {
				t.Fatal("wireForm failed")
			}
			if !bytes.Equal(elligatorDecode(R), shifted) {
				t.Fatalf("wire form %x does not decode to %x", R, shifted)
			}
			if got := canonicalDecode(R); !bytes.Equal(got, u) {
				t.Fatalf("canonical(decode(%x)) = %x, want %x", R, got, u)
			}
			j := ellRead(t, src, 32)
			j[0] &= 248
			j[31] &= 127
			j[31] |= 64
			want, err := curve25519.X25519(j, u)
			if err != nil {
				t.Fatal(err)
			}
			got, err := curve25519.X25519(j, elligatorDecode(R))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatalf("X25519 differs between u and u + T (shift %d)", sel)
			}
		}
	}
	// About half of the 512 shifts are encodable.
	if encodable < 150 {
		t.Fatalf("only %d of 512 shifts were encodable", encodable)
	}
}

// TestSenderRepresentativesLeaveSubgroup checks the statistic that the original
// defect broke. A wire form decodes to u + T, and u + T is in the prime-order
// subgroup only when T is zero. T is uniform over E[8], so the rate is 1/8. Before
// the fix the sender's rate was 1.
//
// The count is Binomial(n, 1/8). The test accepts a count within 5 standard
// deviations of n/8 on either side, so a correct sender fails by chance with
// probability about 6e-7. Size trade-off: each sample costs about 1.6 ms (one key
// search and one subgroup ladder), so n = 8000 takes about 13 s, or about 70 s
// under -race. The size is
// set by power, not by the 5-sigma level. At n = 8000 the band is +-0.0185 in
// rate, and a sender biased to 0.15 is caught with power about 0.95. At n = 2000
// the band is +-0.037, and the same bias is caught with power about 0.07 for 3 s.
// Only the sender is sampled. Uniform bytes have the same 1/8 rate, and the
// sender side is the one the defect breaks.
func TestSenderRepresentativesLeaveSubgroup(t *testing.T) {
	const n = 8000
	const p = 1.0 / 8
	sigma := math.Sqrt(n * p * (1 - p))
	lo, hi := n*p-5*sigma, n*p+5*sigma

	savedEph := ephRand
	t.Cleanup(func() { ephRand = savedEph })
	ephRand = ellSource(19)

	sender := 0
	for range n {
		_, _, R, err := wireEphemeral()
		if err != nil {
			t.Fatal(err)
		}
		if ellInSubgroup(elligatorDecode(R)) {
			sender++
		}
	}
	t.Logf("sender count %d of %d, band [%.1f, %.1f]", sender, n, lo, hi)
	if c := float64(sender); c < lo || c > hi {
		t.Fatalf("sender representatives are in the subgroup %d times of %d, want %.1f to %.1f", sender, n, lo, hi)
	}
}

// BenchmarkCanonicalPoint measures one canonicalization, which is the receiver's
// extra cost for each ephemeral key.
func BenchmarkCanonicalPoint(b *testing.B) {
	src := ellSource(21)
	_, _, r, err := encodableKey(src)
	if err != nil {
		b.Fatal(err)
	}
	up := elligatorF(r)
	b.ResetTimer()
	for range b.N {
		if canonicalPoint(up) == nil {
			b.Fatal("canonicalPoint failed")
		}
	}
}
