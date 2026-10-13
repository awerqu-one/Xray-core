package raywire

import (
	"bytes"
	"math"
	"net"
	"os"
	"testing"
	"time"
)

// memConn is an in-memory net.Conn for running one side of a handshake or a
// frame reader without a peer. Reads come from the input and end with io.EOF,
// writes are kept in out, and n counts the bytes read. The embedded net.Conn
// is nil, so only the methods defined here may be called.
type memConn struct {
	net.Conn
	r   *bytes.Reader
	n   int
	out bytes.Buffer
}

func newMemConn(in []byte) *memConn {
	return &memConn{r: bytes.NewReader(in)}
}

func (c *memConn) Read(p []byte) (int, error) {
	m, err := c.r.Read(p)
	c.n += m
	return m, err
}

func (c *memConn) Write(p []byte) (int, error) {
	return c.out.Write(p)
}

func (c *memConn) SetDeadline(time.Time) error { return nil }

// The limits below reject a sample when the bytes are uniform with probability
// below about 1e-9. The samples come from fixed randomness, so the outcome is the
// same on every run. The limits were chosen as if the randomness were fresh.
//
// The failure bound depends on the degrees of freedom and on the z-score, not on
// n. Only the power depends on n. So a smaller default sample keeps every limit,
// and a smaller n only makes the tests less sensitive to small biases.
//
// chiSquareLimit is the upper 1e-9 point of chi-square with 255 degrees of
// freedom (256 cells, minus one), which is 414.6. The limit is rounded up to 422,
// where the upper tail is 2.2e-10. The pooled byte tests have 8n values over 256
// cells, so each cell needs 8n/256 >= 5, which holds at the default n.
const chiSquareLimit = 422

// groupedChiSquareLimit is the limit for the 8-bit histograms, which are grouped
// into 16 cells of 16 values. Ungrouped, a histogram over 256 cells needs n >=
// 1280 to give every cell an expected count of 5. The upper 1e-9 point of chi-square
// with 15 degrees of freedom is 73.6, rounded up to 75, where the tail is 5.7e-10.
const groupedChiSquareLimit = 75

// binomialLimit is the smallest deviation |X - n/2| that a bit test rejects,
// ceil(3.1 sqrt(n)). That is z = 6.2 for a binomial with variance n/4, at any n.
// The exact two-sided tail at the limit is 3.7e-10 for n = 256, 5.7e-10 for
// n = 400 and 5.6e-10 for n = 1e5, so it stays below 1e-9 across the sizes used.
func binomialLimit(n int) int {
	return int(math.Ceil(3.1 * math.Sqrt(float64(n))))
}

// chiSquare returns Pearson's statistic for counts against the uniform
// distribution over the cells. total is the sum of counts.
func chiSquare(counts []int, total int) float64 {
	expected := float64(total) / float64(len(counts))
	var stat float64
	for _, c := range counts {
		d := float64(c) - expected
		stat += d * d / expected
	}
	return stat
}

// groupCounts sums consecutive cells of counts in groups of width. The length of
// counts must be a multiple of width.
func groupCounts(counts []int, width int) []int {
	out := make([]int, len(counts)/width)
	for i, c := range counts {
		out[i/width] += c
	}
	return out
}

// uniformBytesStat returns the chi-square statistic of the bytes at offsets
// [lo, hi) of every value, pooled over the values.
func uniformBytesStat(values [][]byte, lo, hi int) float64 {
	var counts [256]int
	total := 0
	for _, v := range values {
		for _, b := range v[lo:hi] {
			counts[b]++
		}
		total += hi - lo
	}
	return chiSquare(counts[:], total)
}

// wireSample holds the first message of each side of one handshake, as an
// observer on the wire sees it.
type wireSample struct {
	msg1 []byte // client to server
	msg2 []byte // server to client
}

// collectSamples runs n handshakes with the default pad policy. The client runs
// against an empty reply, so it stops after writing msg1. The server then runs on
// that msg1, with the client's key authorized.
func collectSamples(t *testing.T, n int) []wireSample {
	t.Helper()

	clientKey, serverKey := fixedKeys(t)
	accept := func(pub []byte) bool { return bytes.Equal(pub, clientKey.Public) }
	samples := make([]wireSample, 0, n)
	for range n {
		cc := newMemConn(nil)
		if _, err := ClientHandshake(cc, clientKey, serverKey.Public, testKeys(), defaultPadPolicy()); err == nil {
			t.Fatal("client handshake succeeded without a server reply")
		}
		sc := newMemConn(cc.out.Bytes())
		if _, err := ServerHandshake(sc, serverKey, accept, NewReplayFilter(), nil, testHeadKeys(), defaultPadPolicy()); err != nil {
			t.Fatalf("server rejected a valid msg1: %v", err)
		}
		samples = append(samples, wireSample{msg1: cc.out.Bytes(), msg2: sc.out.Bytes()})
	}
	return samples
}

// TestWireStatistics checks that the public bytes of raywire/3 look uniform. The
// default is 256 handshakes, which takes about 5 s with -race and keeps the package
// under its time budget. RAYWIRE_LONG=1 runs 10^5, which takes roughly half an hour
// with -race. The limits do not depend on n, so the failure bound is the same at
// both sizes (see the constants above). Only the power differs.
func TestWireStatistics(t *testing.T) {
	fixRandomness(t)

	n := 256
	if os.Getenv("RAYWIRE_LONG") == "1" {
		n = 100000
	}
	samples := collectSamples(t, n)

	clientEph := make([][]byte, n)
	serverEph := make([][]byte, n)
	for i, s := range samples {
		clientEph[i] = s.msg1[:hsKeyLen]
		serverEph[i] = s.msg2[:hsKeyLen]
	}
	sides := []struct {
		name string
		eph  [][]byte
	}{{"client", clientEph}, {"server", serverEph}}

	t.Run("ephemeral bytes uniform by position", func(t *testing.T) {
		for _, side := range sides {
			// Four groups of eight bytes, so each group pools 8n values.
			for g := range 4 {
				stat := uniformBytesStat(side.eph, 8*g, 8*g+8)
				if stat > chiSquareLimit {
					t.Errorf("%s R bytes %d to %d: chi-square %.1f exceeds %d", side.name, 8*g, 8*g+7, stat, chiSquareLimit)
				}
			}
		}
	})

	t.Run("bit 255 uniform", func(t *testing.T) {
		limit := float64(binomialLimit(n))
		for _, side := range sides {
			ones := 0
			for _, r := range side.eph {
				ones += int(r[31] >> 7)
			}
			if dev := math.Abs(float64(ones) - float64(n)/2); dev >= limit {
				t.Errorf("%s R bit 255: %d ones of %d, deviation %.0f reaches %.0f", side.name, ones, n, dev, limit)
			}
		}
	})

	t.Run("first message length uniform", func(t *testing.T) {
		// msg1 is 122 + P1 bytes, and P1 is uniform in [0, 255] under the default pad.
		base := hsHeadLen + hsMinN1
		top := defaultPadPolicy().Handshake
		var counts [256]int
		for _, s := range samples {
			p1 := len(s.msg1) - base
			if p1 < 0 || p1 > top {
				t.Fatalf("msg1 is %d bytes, outside [%d, %d]", len(s.msg1), base, base+top)
			}
			counts[p1]++
		}
		if top+1 != len(counts) {
			t.Fatalf("default pad is %d, the histogram has %d cells", top, len(counts))
		}
		// Grouped into 16 cells, so each has an expected count of n/16.
		if stat := chiSquare(groupCounts(counts[:], 16), n); stat > groupedChiSquareLimit {
			t.Errorf("msg1 length: chi-square %.1f exceeds %d", stat, groupedChiSquareLimit)
		}
	})

	t.Run("tag bytes uniform", func(t *testing.T) {
		// T is 16 bytes at [34, 50). Two groups of eight bytes, each pooled over n
		// samples, as for R_e.
		tags := make([][]byte, n)
		for i, s := range samples {
			tags[i] = s.msg1[hsKeyLen+2 : hsHeadLen]
		}
		for g := range 2 {
			stat := uniformBytesStat(tags, 8*g, 8*g+8)
			if stat > chiSquareLimit {
				t.Errorf("T bytes %d to %d: chi-square %.1f exceeds %d", 8*g, 8*g+7, stat, chiSquareLimit)
			}
		}
	})

	t.Run("length word uniform", func(t *testing.T) {
		var hi, lo [256]int
		for _, s := range samples {
			w1 := s.msg1[hsKeyLen : hsKeyLen+2]
			hi[w1[0]]++
			lo[w1[1]]++
		}
		// W1 is 16 bits, and 65536 cells would be too sparse for n samples. Each
		// byte is tested on its own, grouped into 16 cells as the length is.
		if stat := chiSquare(groupCounts(hi[:], 16), n); stat > groupedChiSquareLimit {
			t.Errorf("W1 high byte: chi-square %.1f exceeds %d", stat, groupedChiSquareLimit)
		}
		if stat := chiSquare(groupCounts(lo[:], 16), n); stat > groupedChiSquareLimit {
			t.Errorf("W1 low byte: chi-square %.1f exceeds %d", stat, groupedChiSquareLimit)
		}
	})

	t.Run("client ephemeral avoids probe prefixes", func(t *testing.T) {
		for i, r := range clientEph {
			if hasPrefix2(r) || hasPrefix4(r) {
				t.Fatalf("handshake %d: R_e starts with a probe table entry: % x", i, r[:4])
			}
		}
	})
}

// TestStatisticsRejectBiasedInput checks that the limits do reject a clear bias,
// so that a passing run means something.
func TestStatisticsRejectBiasedInput(t *testing.T) {
	const m = 1000

	zeros := make([][]byte, m)
	for i := range zeros {
		zeros[i] = make([]byte, hsKeyLen)
	}
	if stat := uniformBytesStat(zeros, 0, hsKeyLen); stat <= chiSquareLimit {
		t.Fatalf("all-zero bytes gave chi-square %.1f, not above %d", stat, chiSquareLimit)
	}

	ones := m
	if dev := math.Abs(float64(ones) - float64(m)/2); dev < float64(binomialLimit(m)) {
		t.Fatalf("all-ones bit gave deviation %.0f, not above %d", dev, binomialLimit(m))
	}

	var lengths [256]int
	lengths[0] = m
	if stat := chiSquare(groupCounts(lengths[:], 16), m); stat <= groupedChiSquareLimit {
		t.Fatalf("constant length gave chi-square %.1f, not above %d", stat, groupedChiSquareLimit)
	}
}
