package raywire

import (
	"io"
	"math/big"

	"github.com/xtls/xray-core/common/errors"
	"golang.org/x/crypto/curve25519"
)

// The Elligator2 map for Curve25519 makes an ephemeral public key look like
// 32 random bytes. The key is searched until it has a preimage r, and r goes
// on the wire instead of u.
//
// A clamped scalar is a multiple of 8, so u is in the prime-order subgroup L.
// Elligator2 decodes any 32 bytes to a point of the full curve, and a random
// string lands in L only one time in eight. A test for membership in L would
// therefore separate raywire from random bytes. The sender encodes u + T for
// a random point T of the 8-torsion subgroup. The receiver removes T with
// canonicalPoint. X25519 by a clamped scalar kills T, so the DH is the same for
// u and u + T. The server uses that to take the length DH from the raw point and
// canonicalizes only after the length check, since canonicalPoint costs about
// 1 ms.
//
// Only public values enter math/big. Private scalars go only to
// curve25519.X25519, which runs in constant time.

const (
	// elligatorA is the Montgomery coefficient of Curve25519.
	elligatorA = 486662

	// elligatorA24 is (A - 2) / 4, the constant of the x-only ladder.
	elligatorA24 = 121665

	// maxEncodableAttempts bounds the key search. About half of the shifted
	// points are encodable, so the bound is reached only when the reader is
	// broken.
	maxEncodableAttempts = 256
)

// elliTorsionHex are the u-coordinates of the points of E[8] that lie on the
// curve. They were found as [l]P for random points P of the curve, and they are
// checked in TestTorsionSubgroup. They are 0 (order 2), 1 (order 4) and two of
// order 8. The point with u = -1 is on the twist, not on the curve, so it is not
// listed. The other points of E[8] are negations of these, with the same u.
var elliTorsionHex = []string{
	"00",
	"01",
	"b8495f16056286fdb1329ceb8d09da6ac49ff1fae35616aeb8413b7c7aebe0",
	"57119fd0dd4e22d8868e1c58c45c44045bef839c55b1d0b1248c50a3bc959c5f",
}

var (
	// elliP is 2^255 - 19.
	elliP = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// elliNegA is -A mod p.
	elliNegA = new(big.Int).Sub(elliP, big.NewInt(elligatorA))
	// elliL is the order of the prime-order subgroup, 2^252 + 27742317777372353535851937790883648493.
	elliL = hexInt("1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed")
	// elliCanonScalar is 3l + 1. It is 1 mod l and 0 mod 8, and it is the unique
	// such value below 8l. Multiplying by it keeps the subgroup component of a
	// point and kills its torsion component.
	elliCanonScalar = new(big.Int).Add(new(big.Int).Mul(big.NewInt(3), elliL), big.NewInt(1))
	// elliTorsion is E[8] in affine form. The point at infinity is nil, and
	// the others are listed as (u, v) and (u, -v).
	elliTorsion = torsionTable()
)

// elliPoint is an affine point (u, v) of v^2 = u^3 + A u^2 + u. The point at
// infinity is represented by nil.
type elliPoint struct {
	u, v *big.Int
}

// hexInt parses a hex integer for the constants above. A bad constant is a
// programming error, so it panics at package init.
func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("raywire: bad hex constant " + s)
	}
	return n
}

// torsionTable returns E[8] in affine form. It panics if a listed u-coordinate
// is not on the curve, or if the table does not hold 8 points.
func torsionTable() []*elliPoint {
	pts := []*elliPoint{nil}
	for _, h := range elliTorsionHex {
		P := elliLift(hexInt(h))
		if P == nil {
			panic("raywire: torsion u-coordinate " + h + " is not on the curve")
		}
		pts = append(pts, P)
		if P.v.Sign() != 0 {
			pts = append(pts, &elliPoint{u: P.u, v: new(big.Int).Sub(elliP, P.v)})
		}
	}
	if len(pts) != 8 {
		panic("raywire: torsion table does not hold 8 points")
	}
	return pts
}

// feFromLE returns the integer with little-endian bytes b.
func feFromLE(b []byte) *big.Int {
	be := make([]byte, len(b))
	for i, c := range b {
		be[len(b)-1-i] = c
	}
	return new(big.Int).SetBytes(be)
}

// feToLE returns x as 32 little-endian bytes. x must be in [0, 2^256).
func feToLE(x *big.Int) []byte {
	be := x.FillBytes(make([]byte, 32))
	for i, j := 0, len(be)-1; i < j; i, j = i+1, j-1 {
		be[i], be[j] = be[j], be[i]
	}
	return be
}

// feMul, feAdd, feSub and feInv work mod p on public values.
func feMul(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Mul(a, b), elliP)
}

func feAdd(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Add(a, b), elliP)
}

func feSub(a, b *big.Int) *big.Int {
	return new(big.Int).Mod(new(big.Int).Sub(a, b), elliP)
}

func feInv(a *big.Int) *big.Int {
	return new(big.Int).ModInverse(a, elliP)
}

// elliG returns g(x) = x^3 + A x^2 + x mod p.
func elliG(x *big.Int) *big.Int {
	t := new(big.Int).Mul(x, x)
	t.Add(t, new(big.Int).Mul(big.NewInt(elligatorA), x))
	t.Add(t, big.NewInt(1))
	t.Mul(t, x)
	return t.Mod(t, elliP)
}

// elliLift returns the point with u-coordinate x, and nil if x is not on the
// curve. The sign of v is the one ModSqrt returns. Either sign gives the same u
// for the point and its negation.
func elliLift(x *big.Int) *elliPoint {
	v := new(big.Int).ModSqrt(elliG(x), elliP)
	if v == nil {
		return nil
	}
	return &elliPoint{u: x, v: v}
}

// elliAdd returns P + Q by the affine formulas, with u3 = lambda^2 - A - u1 - u2.
// A nil point is the point at infinity. The inputs must be on the curve.
func elliAdd(P, Q *elliPoint) *elliPoint {
	if P == nil {
		return Q
	}
	if Q == nil {
		return P
	}
	var lambda *big.Int
	if P.u.Cmp(Q.u) == 0 {
		// Q is P or -P. The sum is the point at infinity when v1 + v2 = 0, which
		// includes a point of order 2 (v = 0) added to itself.
		if feAdd(P.v, Q.v).Sign() == 0 {
			return nil
		}
		// Doubling: lambda = (3u^2 + 2Au + 1) / (2v).
		num := feMul(big.NewInt(3), feMul(P.u, P.u))
		num = feAdd(num, feMul(big.NewInt(2*elligatorA), P.u))
		num = feAdd(num, big.NewInt(1))
		lambda = feMul(num, feInv(feAdd(P.v, P.v)))
	} else {
		lambda = feMul(feSub(Q.v, P.v), feInv(feSub(Q.u, P.u)))
	}
	u3 := feSub(feSub(feSub(feMul(lambda, lambda), big.NewInt(elligatorA)), P.u), Q.u)
	v3 := feSub(feMul(lambda, feSub(P.u, u3)), P.v)
	return &elliPoint{u: u3, v: v3}
}

// elliLadder returns the u-coordinate of [k]Q, where Q has u-coordinate u, by the
// x-only Montgomery ladder of RFC 7748. It returns nil if [k]Q is the point at
// infinity. The ladder needs u != 0, which the callers check.
func elliLadder(k, u *big.Int) *big.Int {
	x1 := u
	x2, z2 := big.NewInt(1), big.NewInt(0)
	x3, z3 := new(big.Int).Set(u), big.NewInt(1)
	var prev uint
	for i := k.BitLen() - 1; i >= 0; i-- {
		// The two points swap when the bit changes, which is the same as a
		// conditional swap of each bit.
		bit := k.Bit(i)
		if bit != prev {
			x2, x3 = x3, x2
			z2, z3 = z3, z2
		}
		prev = bit

		// Differential addition and doubling of RFC 7748 section 5.
		a := feAdd(x2, z2)
		aa := feMul(a, a)
		b := feSub(x2, z2)
		bb := feMul(b, b)
		e := feSub(aa, bb)
		c := feAdd(x3, z3)
		d := feSub(x3, z3)
		da := feMul(d, a)
		cb := feMul(c, b)
		s := feAdd(da, cb)
		t := feSub(da, cb)
		x3 = feMul(s, s)
		z3 = feMul(x1, feMul(t, t))
		x2 = feMul(aa, bb)
		z2 = feMul(e, feAdd(aa, feMul(big.NewInt(elligatorA24), e)))
	}
	if prev == 1 {
		x2, x3 = x3, x2
		z2, z3 = z3, z2
	}
	if z2.Sign() == 0 {
		return nil
	}
	return feMul(x2, feInv(z2))
}

// canonicalPoint returns the u-coordinate of the prime-order component of the
// point with u-coordinate up. Multiplying by 3l + 1 keeps the subgroup part
// and kills the 8-torsion part. For a point u + T this gives u exactly.
//
// It returns nil for 0, for a value that is not below p, and for a torsion-only
// input, whose prime-order part is the identity. Such a value is not a key, so
// the caller must treat nil as a bad ephemeral key. The server runs the length
// DH on the raw point first, and X25519 fails on exactly the torsion-only inputs,
// so the server's nil check after the length check is a guard. The client checks
// nil on the responder's key before Noise uses it.
func canonicalPoint(up []byte) []byte {
	if len(up) != 32 {
		return nil
	}
	x := feFromLE(up)
	if x.Sign() == 0 || x.Cmp(elliP) >= 0 {
		return nil
	}
	y := elliLadder(elliCanonScalar, x)
	if y == nil {
		return nil
	}
	return feToLE(y)
}

// canonicalDecode returns the subgroup point u for a wire form R. It decodes R to
// u + T and then removes T. Noise mixes this value, the DH uses it and the replay
// filter keys on it. Returns nil if R does not decode to a usable point.
func canonicalDecode(R []byte) []byte {
	return canonicalPoint(elligatorDecode(R))
}

// torsionShift returns the u-coordinate of P + T, where P has u-coordinate u and
// T is the t-th point of E[8] for t in [0, 8). It returns nil if u is not on the
// curve or if the sum is the point at infinity.
func torsionShift(u []byte, t int) []byte {
	if len(u) != 32 {
		return nil
	}
	x := feFromLE(u)
	if x.Cmp(elliP) >= 0 {
		return nil
	}
	P := elliLift(x)
	if P == nil {
		return nil
	}
	R := elliAdd(P, elliTorsion[t])
	if R == nil {
		return nil
	}
	return feToLE(R.u)
}

// elligatorF is F(r) on a 32-byte little-endian r. It returns nil if r does
// not have 32 bytes.
func elligatorF(r []byte) []byte {
	if len(r) != 32 {
		return nil
	}
	u := elliForward(feFromLE(r))
	if u == nil {
		return nil
	}
	return feToLE(u)
}

// elliForward is the map F(r) for any integer r, reduced mod p first. It returns
// nil only if d has no inverse, which cannot happen.
func elliForward(r *big.Int) *big.Int {
	r = new(big.Int).Mod(r, elliP)

	// d = 1 + 2r^2 is never zero, because -1/2 is a non-square mod p.
	d := new(big.Int).Mul(r, r)
	d.Lsh(d, 1)
	d.Add(d, big.NewInt(1))
	d.Mod(d, elliP)
	inv := new(big.Int).ModInverse(d, elliP)
	if inv == nil {
		return nil
	}

	x1 := new(big.Int).Mul(elliNegA, inv)
	x1.Mod(x1, elliP)
	if big.Jacobi(elliG(x1), elliP) != -1 {
		return x1
	}
	u := new(big.Int).Sub(elliNegA, x1)
	return u.Mod(u, elliP)
}

// elligatorE returns a 32-byte preimage r of the point u, and false if u is
// not encodable. u must be a canonical 32-byte value.
func elligatorE(u []byte) ([]byte, bool) {
	if len(u) != 32 {
		return nil, false
	}
	x := feFromLE(u)
	if x.Cmp(elliP) >= 0 {
		return nil, false
	}
	r := elliInverse(x)
	if r == nil {
		return nil, false
	}
	return feToLE(r), true
}

// elliInverse returns a preimage r of u under elliForward, or nil if there is none.
// The first candidate gives a branch-1 preimage, and wireForm adds the others.
func elliInverse(u *big.Int) *big.Int {
	candidates := []*big.Int{new(big.Int).Set(u), new(big.Int).Sub(elliNegA, u)}
	for _, x := range candidates {
		x.Mod(x, elliP)
		if x.Sign() == 0 {
			continue
		}

		// r^2 = (-A - x) / (2x), for the candidate x = u or x = -A - u.
		num := new(big.Int).Sub(elliNegA, x)
		num.Mod(num, elliP)
		den := new(big.Int).Lsh(x, 1)
		den.Mod(den, elliP)
		inv := new(big.Int).ModInverse(den, elliP)
		if inv == nil {
			continue
		}
		t := num.Mul(num, inv)
		t.Mod(t, elliP)

		r := new(big.Int).ModSqrt(t, elliP)
		if r == nil {
			continue
		}
		// Checked, not assumed: a root of t does not always map back to u.
		if f := elliForward(r); f != nil && f.Cmp(u) == 0 {
			return r
		}
	}
	return nil
}

// elligatorDecode returns the point u' = F(R) for a wire form R. Bit 255 of R
// is ignored, because it carries no value. R is reduced mod p before the map.
// For a sender's wire form, u' is u + T and not the subgroup point. Use
// canonicalDecode for the point the protocol uses.
func elligatorDecode(R []byte) []byte {
	if len(R) != 32 {
		return nil
	}
	b := append([]byte(nil), R...)
	b[31] &= 0x7f
	return elligatorF(b)
}

// wireForm returns the 32-byte wire form of r, which must be below p. Each
// point has four preimages, ±r and ±1/(2r). The encoder always returns the
// branch-1 pair, so one random byte picks among all four: bit 0 picks the
// sign, bit 1 picks 1/(2r), and bit 7 sets bit 255. Without this, the wire
// would never show a branch-2 preimage. wireForm returns nil if r is
// malformed or rand fails.
func wireForm(r []byte, rand io.Reader) []byte {
	if len(r) != 32 {
		return nil
	}
	x := feFromLE(r)
	if x.Cmp(elliP) >= 0 {
		return nil
	}
	var b [1]byte
	if _, err := io.ReadFull(rand, b[:]); err != nil {
		return nil
	}
	if b[0]&2 != 0 && x.Sign() != 0 {
		twice := new(big.Int).Lsh(x, 1)
		twice.Mod(twice, elliP)
		if y := new(big.Int).ModInverse(twice, elliP); y != nil {
			// Only switch when both map to the same point, as they do for
			// every r off the 2-torsion points.
			fx, fy := elliForward(x), elliForward(y)
			if fx != nil && fy != nil && fx.Cmp(fy) == 0 {
				x = y
			}
		}
	}
	if b[0]&1 != 0 && x.Sign() != 0 {
		x.Sub(elliP, x)
	}
	out := feToLE(x)
	out[31] |= b[0] & 0x80
	return out
}

// encodableKey searches for an X25519 private key k whose public point u has a
// shifted point u + T that is encodable, with T a random point of E[8]. It
// returns k, u and r, where r is a preimage of u + T and not of u. Noise mixes
// u. The wire carries r, and the receiver removes T. About two keys are tried
// on average.
func encodableKey(rand io.Reader) (k, u, r []byte, err error) {
	var sel [1]byte
	for range maxEncodableAttempts {
		k = make([]byte, 32)
		if _, err = io.ReadFull(rand, k); err != nil {
			return nil, nil, nil, errors.New("raywire: failed to read key").Base(err)
		}
		// X25519 fails on an all-zero output, which is a low-order point.
		if u, err = curve25519.X25519(k, curve25519.Basepoint); err != nil {
			continue
		}
		if _, err = io.ReadFull(rand, sel[:]); err != nil {
			return nil, nil, nil, errors.New("raywire: failed to read torsion point").Base(err)
		}
		shifted := torsionShift(u, int(sel[0]&7))
		if shifted == nil {
			continue
		}
		var ok bool
		if r, ok = elligatorE(shifted); ok {
			return k, u, r, nil
		}
	}
	return nil, nil, nil, errors.New("raywire: no encodable key found")
}
