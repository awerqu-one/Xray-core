package raywire

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/mux"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/pipe"
)

// tcpDest is the request destination that processAs uses.
var tcpDest = xnet.TCPDestination(xnet.ParseAddress("192.0.2.10"), 80)

// recordingDispatcher gives the server one link, which stands for the
// destination. It also records what the server had set on the request when it
// called Dispatch: the inbound user and the access message.
type recordingDispatcher struct {
	link   *transport.Link
	called bool
	user   *protocol.MemoryUser
	access *log.AccessMessage
}

func (d *recordingDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *recordingDispatcher) Start() error      { return nil }
func (d *recordingDispatcher) Close() error      { return nil }

func (d *recordingDispatcher) Dispatch(ctx context.Context, _ xnet.Destination) (*transport.Link, error) {
	d.called = true
	if inbound := session.InboundFromContext(ctx); inbound != nil {
		d.user = inbound.User
	}
	d.access = log.AccessMessageFromContext(ctx)
	return d.link, nil
}

func (d *recordingDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("DispatchLink is not used by these tests")
}

// processAs runs one client through Process on its own connection, sending
// payload after the request header. The destination ends its output at once, so
// Process returns when the client has read the end of the stream. It returns the
// inbound session that Process filled in.
func processAs(t *testing.T, srv *Server, clientKey noise.DHKey, payload []byte) *session.Inbound {
	t.Helper()
	inbound, _ := processTo(t, srv, clientKey, tcpDest, payload)
	return inbound
}

// processTo is processAs for any destination. It returns the inbound session and
// the recorder that the dispatch wrote to.
func processTo(t *testing.T, srv *Server, clientKey noise.DHKey, dest xnet.Destination, payload []byte) (*session.Inbound, *recordingDispatcher) {
	t.Helper()
	inbound := &session.Inbound{}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	_, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	downW.Close()
	rec := &recordingDispatcher{link: &transport.Link{Reader: downR, Writer: upW}}

	client, server := tcpPair(t)
	served := make(chan error, 1)
	go func() {
		served <- srv.Process(ctx, xnet.Network_TCP, server, rec)
	}()

	rc, err := ClientHandshake(client, clientKey, srv.privateKey.Public, testKeys(), defaultPadPolicy())
	if err != nil {
		t.Fatal(err)
	}
	header, err := encodeHeader(dest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write(header); err != nil {
		t.Fatal(err)
	}
	if len(payload) > 0 {
		if _, err := rc.Write(payload); err != nil {
			t.Fatal(err)
		}
	}
	if err := rc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if err := rc.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(rc); err != nil {
		t.Fatalf("client read: %v", err)
	}
	select {
	case err := <-served:
		if err != nil {
			t.Fatalf("Process: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return")
	}
	return inbound, rec
}

// TestProcessSetsUserFromAuthenticatedClient checks that each connection is counted
// under the email of the client that authenticated. Connections alternate between
// two clients, so a user left by one connection would show up in the next.
func TestProcessSetsUserFromAuthenticatedClient(t *testing.T) {
	alice, bob := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice, bob)
	srv.clients[string(alice.Public)].Email = "alice@example.com"
	srv.clients[string(bob.Public)].Email = "bob@example.com"

	for _, tc := range []struct {
		name  string
		key   noise.DHKey
		email string
	}{
		{"alice", alice, "alice@example.com"},
		{"bob", bob, "bob@example.com"},
		{"alice again", alice, "alice@example.com"},
	} {
		inbound := processAs(t, srv, tc.key, nil)
		if inbound.User == nil {
			t.Fatalf("%s: User is nil, want email %q", tc.name, tc.email)
		}
		if inbound.User.Email != tc.email || inbound.User.Level != 0 {
			t.Fatalf("%s: User = {Email: %q, Level: %d}, want {Email: %q, Level: 0}",
				tc.name, inbound.User.Email, inbound.User.Level, tc.email)
		}
	}
}

// TestProcessSetsEmptyUserWithoutEmail checks that a client configured without an
// email gets a user with an empty email, for TCP and UDP, and that a client with
// an email on the same server gets its own. The user must not be nil: the mux
// path reads inbound.User.Email without a nil check. The empty email is not
// counted, because the dispatcher counts only a non-empty email.
func TestProcessSetsEmptyUserWithoutEmail(t *testing.T) {
	alice, carol := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice, carol)
	srv.clients[string(alice.Public)].Email = "alice@example.com"

	for _, tc := range []struct {
		name string
		dest xnet.Destination
	}{
		{"tcp", xnet.TCPDestination(xnet.ParseAddress("192.0.2.10"), 80)},
		{"udp", xnet.UDPDestination(xnet.ParseAddress("192.0.2.10"), 53)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound, rec := processTo(t, srv, carol, tc.dest, nil)
			if rec.user == nil || rec.user.Email != "" {
				t.Fatalf("user at Dispatch = %+v for a client without an email, want an empty email", rec.user)
			}
			if inbound.User == nil || inbound.User.Email != "" {
				t.Fatalf("User = %+v for a client without an email, want an empty email", inbound.User)
			}
		})
	}
	if inbound := processAs(t, srv, alice, nil); inbound.User == nil || inbound.User.Email != "alice@example.com" {
		t.Fatalf("User = %+v for a client with an email, want alice@example.com", inbound.User)
	}
}

// muxCoolDest is the destination that a mux client sends first. The server then
// runs a mux worker for the sub-sessions that follow.
var muxCoolDest = xnet.TCPDestination(xnet.DomainAddress("v1.mux.cool"), 9527)

// muxSubDispatcher stands for the destinations that a mux session reaches. Each
// one gets a link that ends at once.
type muxSubDispatcher struct {
	called atomic.Bool
}

func (d *muxSubDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *muxSubDispatcher) Start() error      { return nil }
func (d *muxSubDispatcher) Close() error      { return nil }

func (d *muxSubDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("DispatchLink is not used by these tests")
}

func (d *muxSubDispatcher) Dispatch(context.Context, xnet.Destination) (*transport.Link, error) {
	d.called.Store(true)
	_, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	downW.Close()
	return &transport.Link{Reader: downR, Writer: upW}, nil
}

// muxDispatcher stands for the raywire dispatch of the mux address. It builds the
// mux worker the way mux.Server.Dispatch does, with the session's context.
type muxDispatcher struct {
	sub *muxSubDispatcher
}

func (d *muxDispatcher) Type() interface{} { return routing.DispatcherType() }
func (d *muxDispatcher) Start() error      { return nil }
func (d *muxDispatcher) Close() error      { return nil }

func (d *muxDispatcher) DispatchLink(context.Context, xnet.Destination, *transport.Link) error {
	return errors.New("DispatchLink is not used by these tests")
}

func (d *muxDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	uplinkR, uplinkW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	if _, err := mux.NewServerWorker(ctx, d.sub, &transport.Link{Reader: uplinkR, Writer: downW}); err != nil {
		return nil, err
	}
	return &transport.Link{Reader: downR, Writer: uplinkW}, nil
}

// TestMuxSessionWithoutEmailKeepsUser checks the mux path for a client without an
// email. The first mux frame of a session reads the inbound user, and it must
// find a user with an empty email, not a nil user that stops the server.
func TestMuxSessionWithoutEmailKeepsUser(t *testing.T) {
	alice, carol := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice, carol)
	srv.clients[string(alice.Public)].Email = "alice@example.com"

	sub := &muxSubDispatcher{}
	inbound := &session.Inbound{Source: xnet.TCPDestination(xnet.ParseAddress("198.51.100.7"), 40000)}
	ctx := session.ContextWithInbound(context.Background(), inbound)

	client, server := tcpPair(t)
	served := make(chan error, 1)
	go func() {
		served <- srv.Process(ctx, xnet.Network_TCP, server, &muxDispatcher{sub: sub})
	}()

	rc, err := ClientHandshake(client, carol, srv.privateKey.Public, testKeys(), defaultPadPolicy())
	if err != nil {
		t.Fatal(err)
	}
	header, err := encodeHeader(muxCoolDest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write(header); err != nil {
		t.Fatal(err)
	}
	// A New frame without data opens one sub-session to the target.
	frame := buf.New()
	defer frame.Release()
	meta := mux.FrameMetadata{
		Target:        xnet.TCPDestination(xnet.ParseAddress("192.0.2.10"), 80),
		SessionID:     1,
		SessionStatus: mux.SessionStatusNew,
	}
	if err := meta.WriteTo(frame); err != nil {
		t.Fatal(err)
	}
	if _, err := rc.Write(frame.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := rc.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	// The mux worker ends the session by interrupting the downlink, so Process
	// returns an error here. The test only needs the session to end, and the
	// inbound closes the connection after that, as the test does here.
	select {
	case <-served:
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return")
	}
	server.Close()
	if !sub.called.Load() {
		t.Fatal("the mux sub-session was not dispatched")
	}
	if inbound.User == nil || inbound.User.Email != "" {
		t.Fatalf("User = %+v after the mux session, want an empty email", inbound.User)
	}
}

// TestNewServerCarriesEmailToUser checks the whole path from the typed config:
// the email of a ServerConfig client reaches the account that the handshake
// authorizes, and from there the user of the inbound. The other test users are
// built by hand, so this is the only check of the copy in NewServer.
func TestNewServerCarriesEmailToUser(t *testing.T) {
	server, alice, carol := newKey(t), newKey(t), newKey(t)
	config := &ServerConfig{
		PrivateKey: server.Private,
		Psk:        testPSK,
		Clients: []*Account{
			{PublicKey: alice.Public, Email: "alice@example.com"},
			{PublicKey: carol.Public},
		},
		Fallback: "127.0.0.1:8443",
	}
	srv, err := NewServer(coreContext(t), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	// Core's default policy has zero timeouts, which would end the session at
	// once. The policy is not part of what this test checks.
	srv.policyManager = fakePolicy{}

	account, ok := srv.authorize(alice.Public)
	if !ok || account.Email != "alice@example.com" {
		t.Fatalf("authorize(alice) = %+v, %v; want alice@example.com and true", account, ok)
	}
	if inbound := processAs(t, srv, alice, nil); inbound.User == nil || inbound.User.Email != "alice@example.com" {
		t.Fatalf("User = %+v for alice, want alice@example.com", inbound.User)
	}
	if inbound := processAs(t, srv, carol, nil); inbound.User == nil || inbound.User.Email != "" {
		t.Fatalf("User = %+v for carol, want an empty email", inbound.User)
	}
}

// TestEmailIgnoresPeerData checks that the user comes from the authenticated key
// alone. The client sends another client's email as request data, and the user
// stays its own.
func TestEmailIgnoresPeerData(t *testing.T) {
	alice, bob := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice, bob)
	srv.clients[string(alice.Public)].Email = "alice@example.com"
	srv.clients[string(bob.Public)].Email = "bob@example.com"

	inbound := processAs(t, srv, alice, []byte("user=bob@example.com email=bob@example.com"))
	if inbound.User == nil || inbound.User.Email != "alice@example.com" {
		t.Fatalf("User = %+v, want alice@example.com", inbound.User)
	}
}

// TestAuthorizeReturnsAccount checks the lookup that the handshake makes after
// Noise has authenticated the key: a configured key gets its account, and any
// other key is refused with no account.
func TestAuthorizeReturnsAccount(t *testing.T) {
	alice, stranger := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice)
	srv.clients[string(alice.Public)].Email = "alice@example.com"

	account, ok := srv.authorize(alice.Public)
	if !ok || account == nil || account.Email != "alice@example.com" {
		t.Fatalf("authorize(alice) = %v, %v; want her account and true", account, ok)
	}
	account, ok = srv.authorize(stranger.Public)
	if ok || account != nil {
		t.Fatalf("authorize(stranger) = %v, %v; want nil and false", account, ok)
	}
}

// TestUserIsSetBeforeDispatch checks that the stats user is in place when the
// request is dispatched, for TCP and for UDP. The stats read the user during
// dispatch, so a user set after it would leave the connection uncounted.
func TestUserIsSetBeforeDispatch(t *testing.T) {
	alice := newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice)
	srv.clients[string(alice.Public)].Email = "alice@example.com"

	for _, tc := range []struct {
		name string
		dest xnet.Destination
	}{
		{"tcp", xnet.TCPDestination(xnet.ParseAddress("192.0.2.10"), 80)},
		{"udp", xnet.UDPDestination(xnet.ParseAddress("192.0.2.10"), 53)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inbound, rec := processTo(t, srv, alice, tc.dest, nil)
			if !rec.called {
				t.Fatal("Dispatch was not called")
			}
			if rec.user == nil || rec.user.Email != "alice@example.com" {
				t.Fatalf("user at Dispatch = %+v, want alice@example.com", rec.user)
			}
			if inbound.User == nil || inbound.User.Email != "alice@example.com" {
				t.Fatalf("user after Process = %+v, want alice@example.com", inbound.User)
			}
		})
	}
}

// TestAccessMessageCarriesEmail checks that the access log of an accepted
// connection names the authenticated client. A client without an email gets an
// access message with no email in it.
func TestAccessMessageCarriesEmail(t *testing.T) {
	alice, carol := newKey(t), newKey(t)
	srv := newProbeServer(t, xnet.Destination{}, alice, carol)
	srv.clients[string(alice.Public)].Email = "alice@example.com"

	for _, tc := range []struct {
		name      string
		key       noise.DHKey
		wantEmail string
	}{
		{"alice", alice, "alice@example.com"},
		{"carol without an email", carol, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, rec := processTo(t, srv, tc.key, tcpDest, nil)
			if rec.access == nil {
				t.Fatal("no access message when Dispatch was called")
			}
			if rec.access.Status != log.AccessAccepted {
				t.Fatalf("access status = %v, want accepted", rec.access.Status)
			}
			if rec.access.Email != tc.wantEmail {
				t.Fatalf("access email = %q, want %q", rec.access.Email, tc.wantEmail)
			}
			line := rec.access.String()
			if tc.wantEmail == "" {
				if strings.Contains(line, "email:") {
					t.Fatalf("access line %q names an email, want none", line)
				}
			} else if !strings.HasSuffix(line, " email: "+tc.wantEmail) {
				t.Fatalf("access line %q does not end with the email", line)
			}
		})
	}
}
