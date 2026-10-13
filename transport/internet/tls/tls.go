package tls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"math/big"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	utls "github.com/refraction-networking/utls"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/utils"
)

type Interface interface {
	net.Conn
	HandshakeContext(ctx context.Context) error
	VerifyHostname(host string) error
	HandshakeContextServerName(ctx context.Context) string
	NegotiatedProtocol() string
}

var (
	_ buf.Writer = (*Conn)(nil)
	_ Interface  = (*Conn)(nil)
)

type Conn struct {
	*tls.Conn
	suppressCloseNotify atomic.Bool
	socket              net.Conn    // the connection passed to Client or Server; set once
	rec                 *recordConn // set once by Server; nil for a client connection
}

const tlsCloseTimeout = 250 * time.Millisecond

func (c *Conn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *Conn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *Conn) WriteMultiBuffer(mb buf.MultiBuffer) error {
	mb = buf.Compact(mb)
	mb, err := buf.WriteMultiBuffer(c, mb)
	buf.ReleaseMulti(mb)
	return err
}

func (c *Conn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

func (c *Conn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

// Client initiates a TLS client handshake on the given connection.
func Client(c net.Conn, config *tls.Config) net.Conn {
	tlsConn := tls.Client(c, config)
	return &Conn{Conn: tlsConn, socket: c}
}

// Server initiates a TLS server handshake on the given connection. The bytes the handshake
// reads from c are kept until it ends, so that a caller can relay them after a failure (see
// PreHandshakeRecord).
func Server(c net.Conn, config *tls.Config) net.Conn {
	rec := &recordConn{Conn: c, started: time.Now()}
	rec.active.Store(true)
	return &Conn{Conn: tls.Server(rec, config), socket: c, rec: rec}
}

// preHandshakeRecordCap is the most bytes a server connection keeps from its socket before its
// handshake ends. A larger read drops the recording, because a prefix with its beginning
// missing would not be the prober's stream.
const preHandshakeRecordCap = 16 * 1024

// recordConn is the socket under the TLS layer of a server connection. While the handshake runs
// it keeps the bytes read from the socket and whether the TLS layer wrote to it.
type recordConn struct {
	net.Conn             // the socket; Read and Write go through it
	started  time.Time   // accept time: the idle clock of a probe that never sends a byte
	active   atomic.Bool // true until settle; recording and wrote tracking run only while true
	wrote    atomic.Bool // set by Write while active: the TLS layer sent bytes before the handshake ended
	mu       sync.Mutex  // guards overflow, buf, last, failed and taken, and the decision in record and settle
	overflow bool        // true once more than preHandshakeRecordCap bytes were read
	buf      []byte      // bytes read while active; nil after success, overflow, or the accessor
	last     time.Time   // time of the last read that returned bytes while active
	failed   bool        // set by settle when the handshake ended with an error
	taken    bool        // set by the first PreHandshakeRecord call that returned ok
}

// Read reads the socket and records what it returns while active.
func (r *recordConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	if n > 0 && r.active.Load() {
		r.record(p[:n])
	}
	return n, err
}

// Write records that the TLS layer wrote while active, then writes.
func (r *recordConn) Write(p []byte) (int, error) {
	if r.active.Load() {
		r.wrote.Store(true)
	}
	return r.Conn.Write(p)
}

// record appends b under mu. It checks active under mu, so a read that started before settle
// cannot append after settle has cleared buf.
func (r *recordConn) record(b []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active.Load() {
		return
	}
	r.last = time.Now()
	if r.overflow {
		return
	}
	if len(r.buf)+len(b) > preHandshakeRecordCap {
		r.overflow = true
		r.buf = nil
		return
	}
	r.buf = append(r.buf, b...)
}

// NetConn returns the socket under the TLS layer, not the recorder, so that UnwrapRawConn and
// the raywire socket walk reach the TCP connection as they did before recording was added.
func (c *Conn) NetConn() net.Conn { return c.socket }

// settle ends recording once. It runs after every call that can drive the handshake. A
// successful handshake drops the recording; a failed one keeps it for PreHandshakeRecord.
func (c *Conn) settle() {
	if c.rec == nil || !c.rec.active.Load() {
		return // a client connection, or the fast path after the first settle
	}
	// Read the state before r.mu is taken: ConnectionState waits for the handshake mutex, which
	// a handshake in another goroutine holds while it waits in record for r.mu.
	complete := c.Conn.ConnectionState().HandshakeComplete
	r := c.rec
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.active.Load() {
		return // another caller settled first
	}
	r.active.Store(false)
	if complete {
		r.buf = nil
		r.overflow = false
	} else {
		r.failed = true
	}
}

// handshakeFirst runs the handshake as a call of its own while recording, so that the recorder
// never sees application data. After a successful handshake it is one atomic load.
func (c *Conn) handshakeFirst() error {
	if c.rec == nil || !c.rec.active.Load() {
		return nil
	}
	err := c.Conn.Handshake()
	c.settle()
	return err
}

func (c *Conn) Read(b []byte) (int, error) {
	if err := c.handshakeFirst(); err != nil {
		return 0, err
	}
	return c.Conn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	if err := c.handshakeFirst(); err != nil {
		return 0, err
	}
	return c.Conn.Write(b)
}

func (c *Conn) Handshake() error {
	err := c.Conn.Handshake()
	c.settle()
	return err
}

func (c *Conn) HandshakeContext(ctx context.Context) error {
	err := c.Conn.HandshakeContext(ctx)
	c.settle()
	return err
}

// PreHandshakeRecord describes a TLS handshake that failed on this connection. It returns ok = false
// while the handshake is in progress, after a successful handshake, and on any call after the first
// one that returned ok = true. When ok is true, prefix holds the bytes read from the socket (nil after
// an overflow), last is the time of the last read that returned bytes (the accept time if none),
// socket is the connection under the TLS layer, wrote is true if the TLS layer wrote to the socket
// before the failure, and overflow is true if more than preHandshakeRecordCap bytes were read.
// The caller owns prefix.
func (c *Conn) PreHandshakeRecord() (prefix []byte, last time.Time, socket net.Conn, wrote, overflow, ok bool) {
	r := c.rec
	if r == nil {
		return nil, time.Time{}, nil, false, false, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.active.Load() || !r.failed || r.taken {
		return nil, time.Time{}, nil, false, false, false
	}
	r.taken = true
	prefix, r.buf = r.buf, nil
	last = r.last
	if last.IsZero() {
		last = r.started
	}
	return prefix, last, c.socket, r.wrote.Load(), r.overflow, true
}

type UConn struct {
	*utls.UConn
	suppressCloseNotify atomic.Bool
}

var _ Interface = (*UConn)(nil)

func (c *UConn) SuppressCloseNotify() {
	c.suppressCloseNotify.Store(true)
}

func (c *UConn) Close() error {
	if c.suppressCloseNotify.Load() {
		return c.Conn.NetConn().Close()
	}
	timer := time.AfterFunc(tlsCloseTimeout, func() {
		c.Conn.NetConn().Close()
	})
	defer timer.Stop()
	return c.Conn.Close()
}

func (c *UConn) HandshakeContextServerName(ctx context.Context) string {
	if err := c.HandshakeContext(ctx); err != nil {
		return ""
	}
	return c.ConnectionState().ServerName
}

// WebsocketHandshakeContext basically calls UConn.Handshake inside it but it will try
// to build outer ALPN to `http/1.1` or `h2 http/1.1` (if manually specified for camouflage)
func (c *UConn) WebsocketHandshakeContext(ctx context.Context) error {
	config := *utils.AccessField[*utls.Config](c, "config")
	ALPN := slices.Clone(config.NextProtos)
	// set other kinds of ALPN to http/1.1
	if !slices.Equal(ALPN, []string{"h2", "http/1.1"}) {
		ALPN = []string{"http/1.1"}
	}
	// Build the handshake state. This will apply every variable of the TLS of the
	// fingerprint in the UConn
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	// Do not modify outer ALPN if ECH is used
	// Outer ALPN will be h2,http/1.1, and real http/1.1 in config will be hidden in ECH
	if config.EncryptedClientHelloConfigList != nil {
		config.NextProtos = []string{"http/1.1"}
		return c.HandshakeContext(ctx)
	}
	// Iterate over extensions and check for utls.ALPNExtension
	hasALPNExtension := false
	for _, extension := range c.Extensions {
		if alpn, ok := extension.(*utls.ALPNExtension); ok {
			hasALPNExtension = true
			alpn.AlpnProtocols = ALPN
			break
		}
	}
	if !hasALPNExtension { // Append extension if doesn't exists
		c.Extensions = append(c.Extensions, &utls.ALPNExtension{AlpnProtocols: ALPN})
	}
	// Rebuild the client hello and do the handshake
	if err := c.BuildHandshakeState(); err != nil {
		return err
	}
	return c.HandshakeContext(ctx)
}

func (c *UConn) NegotiatedProtocol() string {
	state := c.ConnectionState()
	return state.NegotiatedProtocol
}

func UClient(c net.Conn, config *tls.Config, fingerprint *utls.ClientHelloID) net.Conn {
	utlsConn := utls.UClient(c, copyConfig(config), *fingerprint)
	return &UConn{UConn: utlsConn}
}

func GeneraticUClient(c net.Conn, config *tls.Config) *utls.UConn {
	return utls.UClient(c, copyConfig(config), utls.HelloChrome_Auto)
}

func copyConfig(c *tls.Config) *utls.Config {
	config := &utls.Config{
		Rand:                           c.Rand,
		RootCAs:                        c.RootCAs,
		ServerName:                     c.ServerName,
		InsecureSkipVerify:             c.InsecureSkipVerify,
		VerifyPeerCertificate:          c.VerifyPeerCertificate,
		KeyLogWriter:                   c.KeyLogWriter,
		EncryptedClientHelloConfigList: c.EncryptedClientHelloConfigList,
		NextProtos:                     c.NextProtos,
	}
	if c.GetClientCertificate != nil {
		config.GetClientCertificate = func(info *utls.CertificateRequestInfo) (*utls.Certificate, error) {
			schemes := make([]tls.SignatureScheme, len(info.SignatureSchemes))
			for i, s := range info.SignatureSchemes {
				schemes[i] = tls.SignatureScheme(s)
			}
			cert, err := c.GetClientCertificate(&tls.CertificateRequestInfo{
				AcceptableCAs:    info.AcceptableCAs,
				SignatureSchemes: schemes,
				Version:          info.Version,
			})
			if err != nil || cert == nil {
				return &utls.Certificate{}, err
			}
			return &utls.Certificate{Certificate: cert.Certificate, PrivateKey: cert.PrivateKey, Leaf: cert.Leaf}, nil
		}
	}
	return config
}

func init() {
	bigInt, _ := rand.Int(rand.Reader, big.NewInt(int64(len(ModernFingerprints))))
	stopAt := int(bigInt.Int64())
	i := 0
	for _, v := range ModernFingerprints {
		if i == stopAt {
			PresetFingerprints["random"] = v
			break
		}
		i++
	}
	weights := utls.DefaultWeights
	weights.TLSVersMax_Set_VersionTLS13 = 1
	weights.FirstKeyShare_Set_CurveP256 = 0
	randomized := utls.HelloRandomizedALPN
	randomized.Seed, _ = utls.NewPRNGSeed()
	randomized.Weights = &weights
	randomizednoalpn := utls.HelloRandomizedNoALPN
	randomizednoalpn.Seed, _ = utls.NewPRNGSeed()
	randomizednoalpn.Weights = &weights
	PresetFingerprints["randomized"] = &randomized
	PresetFingerprints["randomizednoalpn"] = &randomizednoalpn
}

func GetFingerprint(name string) (fingerprint *utls.ClientHelloID) {
	if name == "" {
		return &utls.HelloChrome_Auto
	}
	if fingerprint = PresetFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = ModernFingerprints[name]; fingerprint != nil {
		return
	}
	if fingerprint = OtherFingerprints[name]; fingerprint != nil {
		return
	}
	return
}

var PresetFingerprints = map[string]*utls.ClientHelloID{
	// Recommended preset options in GUI clients
	"chrome":           &utls.HelloChrome_Auto,
	"firefox":          &utls.HelloFirefox_Auto,
	"safari":           &utls.HelloSafari_Auto,
	"ios":              &utls.HelloIOS_Auto,
	"android":          &utls.HelloAndroid_11_OkHttp,
	"edge":             &utls.HelloEdge_Auto,
	"360":              &utls.Hello360_Auto,
	"qq":               &utls.HelloQQ_Auto,
	"random":           nil,
	"randomized":       nil,
	"randomizednoalpn": nil,
	"unsafe":           nil,
}

var ModernFingerprints = map[string]*utls.ClientHelloID{
	// One of these will be chosen as `random` at startup
	"hellofirefox_120": &utls.HelloFirefox_120,
	"hellofirefox_148": &utls.HelloFirefox_148,
	"hellochrome_120":  &utls.HelloChrome_120,
	"hellochrome_131":  &utls.HelloChrome_131,
	"hellochrome_133":  &utls.HelloChrome_133,
	"helloios_13":      &utls.HelloIOS_13,
	"helloios_14":      &utls.HelloIOS_14,
	"helloedge_106":    &utls.HelloEdge_106,
	"hellosafari_26_3": &utls.HelloSafari_26_3,
	"hello360_11_0":    &utls.Hello360_11_0,
	"helloqq_11_1":     &utls.HelloQQ_11_1,
}

var OtherFingerprints = map[string]*utls.ClientHelloID{
	// Golang, randomized, auto, and fingerprints that are too old
	"hellogolang":             &utls.HelloGolang,
	"hellorandomized":         &utls.HelloRandomized,
	"hellorandomizedalpn":     &utls.HelloRandomizedALPN,
	"hellorandomizednoalpn":   &utls.HelloRandomizedNoALPN,
	"hellofirefox_auto":       &utls.HelloFirefox_Auto,
	"hellofirefox_55":         &utls.HelloFirefox_55,
	"hellofirefox_56":         &utls.HelloFirefox_56,
	"hellofirefox_63":         &utls.HelloFirefox_63,
	"hellofirefox_65":         &utls.HelloFirefox_65,
	"hellofirefox_99":         &utls.HelloFirefox_99,
	"hellofirefox_102":        &utls.HelloFirefox_102,
	"hellofirefox_105":        &utls.HelloFirefox_105,
	"hellochrome_auto":        &utls.HelloChrome_Auto,
	"hellochrome_58":          &utls.HelloChrome_58,
	"hellochrome_62":          &utls.HelloChrome_62,
	"hellochrome_70":          &utls.HelloChrome_70,
	"hellochrome_72":          &utls.HelloChrome_72,
	"hellochrome_83":          &utls.HelloChrome_83,
	"hellochrome_87":          &utls.HelloChrome_87,
	"hellochrome_96":          &utls.HelloChrome_96,
	"hellochrome_100":         &utls.HelloChrome_100,
	"hellochrome_102":         &utls.HelloChrome_102,
	"hellochrome_106_shuffle": &utls.HelloChrome_106_Shuffle,
	"helloios_auto":           &utls.HelloIOS_Auto,
	"helloios_11_1":           &utls.HelloIOS_11_1,
	"helloios_12_1":           &utls.HelloIOS_12_1,
	"helloandroid_11_okhttp":  &utls.HelloAndroid_11_OkHttp,
	"helloedge_85":            &utls.HelloEdge_85,
	"helloedge_auto":          &utls.HelloEdge_Auto,
	"hellosafari_16_0":        &utls.HelloSafari_16_0,
	"hellosafari_auto":        &utls.HelloSafari_Auto,
	"hello360_auto":           &utls.Hello360_Auto,
	"hello360_7_5":            &utls.Hello360_7_5,
	"helloqq_auto":            &utls.HelloQQ_Auto,

	// Chrome betas
	"hellochrome_100_psk":              &utls.HelloChrome_100_PSK,
	"hellochrome_112_psk_shuf":         &utls.HelloChrome_112_PSK_Shuf,
	"hellochrome_114_padding_psk_shuf": &utls.HelloChrome_114_Padding_PSK_Shuf,
	"hellochrome_115_pq":               &utls.HelloChrome_115_PQ,
	"hellochrome_115_pq_psk":           &utls.HelloChrome_115_PQ_PSK,
	"hellochrome_120_pq":               &utls.HelloChrome_120_PQ,
}
