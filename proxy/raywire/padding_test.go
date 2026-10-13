package raywire

import (
	"io"
	mrand "math/rand/v2"
	"testing"
)

// padSource installs a deterministic pad source for the duration of the test.
func padSource(t *testing.T, seed byte) {
	t.Helper()
	var s [32]byte
	s[0] = seed
	saved := padRand
	padRand = mrand.NewChaCha8(s)
	t.Cleanup(func() { padRand = saved })
}

// padFailReader fails every read, to check that a broken source is fatal.
type padFailReader struct{}

func (padFailReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestDefaultPadPolicy(t *testing.T) {
	want := padPolicy{Handshake: 255, Frame: 32, Bucket: 0}
	if got := defaultPadPolicy(); got != want {
		t.Fatalf("defaultPadPolicy() = %+v, want %+v", got, want)
	}
	if err := defaultPadPolicy().validate(); err != nil {
		t.Fatal(err)
	}
}

func TestPadPolicyValidate(t *testing.T) {
	tests := []struct {
		name string
		pol  padPolicy
		ok   bool
	}{
		{"zero is off", padPolicy{}, true},
		{"handshake 0", padPolicy{Handshake: 0}, true},
		{"handshake 512", padPolicy{Handshake: 512}, true},
		{"handshake 513", padPolicy{Handshake: 513}, false},
		{"handshake -1", padPolicy{Handshake: -1}, false},
		{"frame 0", padPolicy{Frame: 0}, true},
		{"frame 1024", padPolicy{Frame: 1024}, true},
		{"frame 1025", padPolicy{Frame: 1025}, false},
		{"frame -1", padPolicy{Frame: -1}, false},
		{"bucket 0", padPolicy{Bucket: 0}, true},
		{"bucket 15", padPolicy{Bucket: 15}, false},
		{"bucket 16", padPolicy{Bucket: 16}, true},
		{"bucket 4096", padPolicy{Bucket: 4096}, true},
		{"bucket 4097", padPolicy{Bucket: 4097}, false},
		{"bucket -16", padPolicy{Bucket: -16}, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.pol.validate()
			if (err == nil) != tc.ok {
				t.Fatalf("validate(%+v) error = %v, want ok %v", tc.pol, err, tc.ok)
			}
		})
	}
}

func TestRoundUp(t *testing.T) {
	tests := []struct{ n, block, want int }{
		{0, 16, 0},
		{1, 16, 16},
		{16, 16, 16},
		{17, 16, 32},
		{65, 64, 128},
		{65532, 4096, 65536},
	}
	for _, tc := range tests {
		if got := roundUp(tc.n, tc.block); got != tc.want {
			t.Errorf("roundUp(%d, %d) = %d, want %d", tc.n, tc.block, got, tc.want)
		}
	}
}

func TestUniformIntBounds(t *testing.T) {
	padSource(t, 1)
	if got := uniformInt(0); got != 0 {
		t.Fatalf("uniformInt(0) = %d, want 0", got)
	}
	seen := make(map[int]bool)
	for range 2000 {
		v := uniformInt(3)
		if v < 0 || v > 3 {
			t.Fatalf("uniformInt(3) = %d, out of [0, 3]", v)
		}
		seen[v] = true
	}
	// With 2000 draws over four values, missing one is a bug, not chance.
	if len(seen) != 4 {
		t.Fatalf("uniformInt(3) produced %d distinct values, want 4", len(seen))
	}
}

func TestUniformIntUniform(t *testing.T) {
	padSource(t, 2)
	const (
		n     = 9 // values 0..9
		draws = 100000
	)
	var count [n + 1]int
	for range draws {
		count[uniformInt(n)]++
	}
	// Chi-square with 9 degrees of freedom. The 0.001 critical value is 27.88.
	// The source is seeded, so the result is the same on every run.
	expected := float64(draws) / (n + 1)
	chi := 0.0
	for _, c := range count {
		d := float64(c) - expected
		chi += d * d / expected
	}
	if chi > 27.88 {
		t.Fatalf("uniformInt chi-square = %.2f over %d draws, want <= 27.88 (counts %v)", chi, draws, count)
	}
}

func TestUniformIntFailsOnBrokenSource(t *testing.T) {
	saved := padRand
	padRand = padFailReader{}
	t.Cleanup(func() { padRand = saved })

	defer func() {
		if recover() == nil {
			t.Fatal("uniformInt did not panic on a failing source")
		}
	}()
	uniformInt(10)
}

func TestFrameBpBoundsDefault(t *testing.T) {
	padSource(t, 3)
	pol := padPolicy{Handshake: 255, Frame: 32}
	for _, n := range []int{0, 1, 13, 61, 8192, maxFramePayload - 1024} {
		seenMin, seenMax := 1<<30, -1
		for range 2000 {
			bp := frameBp(n, pol, false)
			if bp < frameHeaderSize+n || bp > frameHeaderSize+n+pol.Frame {
				t.Fatalf("frameBp(%d) = %d, want in [%d, %d]", n, bp, frameHeaderSize+n, frameHeaderSize+n+pol.Frame)
			}
			seenMin, seenMax = min(seenMin, bp), max(seenMax, bp)
		}
		if seenMin != frameHeaderSize+n || seenMax != frameHeaderSize+n+pol.Frame {
			t.Errorf("frameBp(%d) range [%d, %d] does not cover the full pad range", n, seenMin, seenMax)
		}
	}
}

func TestFrameBpFirstHandshakeUsesHandshakeRange(t *testing.T) {
	padSource(t, 4)
	pol := padPolicy{Handshake: 400, Frame: 8}
	maxSeen := 0
	for range 2000 {
		bp := frameBp(10, pol, true)
		if bp < 13 || bp > 13+400 {
			t.Fatalf("first frame Bp = %d, want in [13, 413]", bp)
		}
		maxSeen = max(maxSeen, bp)
	}
	if maxSeen <= 13+8 {
		t.Fatalf("first frame never used the handshake range, max %d", maxSeen)
	}
}

func TestFrameBpZeroPolicyIsExact(t *testing.T) {
	padSource(t, 5)
	for _, n := range []int{0, 1, 100, maxFramePayload} {
		if bp := frameBp(n, padPolicy{}, false); bp != frameHeaderSize+n {
			t.Errorf("zero policy frameBp(%d) = %d, want %d", n, bp, frameHeaderSize+n)
		}
		if bp := frameBp(n, padPolicy{}, true); bp != frameHeaderSize+n {
			t.Errorf("zero policy first frameBp(%d) = %d, want %d", n, bp, frameHeaderSize+n)
		}
	}
}

func TestFrameBpEndOfStreamBase(t *testing.T) {
	padSource(t, 6)
	// An end-of-stream frame has n = 0, so its body is 3 bytes plus the pad.
	pol := padPolicy{Frame: 32}
	for range 500 {
		bp := frameBp(0, pol, false)
		if bp < frameHeaderSize || bp > frameHeaderSize+32 {
			t.Fatalf("EOS Bp = %d, want in [3, 35]", bp)
		}
	}
}

func TestFrameBpClampsAtMaximum(t *testing.T) {
	padSource(t, 7)
	pol := padPolicy{Handshake: 512, Frame: 1024}
	for range 500 {
		for _, firstHS := range []bool{false, true} {
			bp := frameBp(maxFramePayload, pol, firstHS)
			if bp != maxFrameBody {
				t.Fatalf("frameBp(maxFramePayload, firstHS=%v) = %d, want %d", firstHS, bp, maxFrameBody)
			}
		}
	}
	// Bucket rounding can also reach past the limit.
	if bp := frameBp(maxFramePayload, padPolicy{Bucket: 4096}, false); bp != maxFrameBody {
		t.Fatalf("bucket frameBp(maxFramePayload) = %d, want %d", bp, maxFrameBody)
	}
}

func TestFrameBpBucket(t *testing.T) {
	padSource(t, 8)
	sizes := []int{0, 1, 13, 61, 64, 65, 8192, maxFramePayload}
	for _, block := range []int{16, 64, 256, 4096} {
		pol := padPolicy{Frame: 1024, Bucket: block}
		for _, n := range sizes {
			want := min(roundUp(frameHeaderSize+n, block), maxFrameBody)
			for range 50 {
				// The bucket ignores the random pad, so every draw is the same.
				bp := frameBp(n, pol, false)
				if bp != want {
					t.Fatalf("bucket %d frameBp(%d) = %d, want %d", block, n, bp, want)
				}
				if bp < frameHeaderSize+n {
					t.Fatalf("bucket %d frameBp(%d) = %d, below the payload", block, n, bp)
				}
			}
		}
	}
	// Spot values from the spec: 61 + 3 = 64 stays, 65 + 3 rounds to 128.
	if bp := frameBp(61, padPolicy{Bucket: 64}, false); bp != 64 {
		t.Errorf("frameBp(61, bucket 64) = %d, want 64", bp)
	}
	if bp := frameBp(65, padPolicy{Bucket: 64}, false); bp != 128 {
		t.Errorf("frameBp(65, bucket 64) = %d, want 128", bp)
	}
}

// TestMaxPayloadIsWholeBuckets checks that the largest payload in bucket mode rounds
// to a body that is a whole number of buckets within the 2-byte length. The
// next block up must not fit.
func TestMaxPayloadIsWholeBuckets(t *testing.T) {
	for _, block := range []int{16, 256, 4096} {
		pol := padPolicy{Bucket: block}
		body := pol.maxPayload() + frameHeaderSize
		if body%block != 0 || body > maxFrameBody || body+block <= maxFrameBody {
			t.Fatalf("bucket %d: largest body %d", block, body)
		}
	}
	if got := (padPolicy{}).maxPayload(); got != maxPlaintext {
		t.Fatalf("no bucket: largest payload %d, want %d", got, maxPlaintext)
	}
}
