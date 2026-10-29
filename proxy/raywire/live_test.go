package raywire

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common/buf"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/pipe"
)

func TestLiveSessionsConcurrentCap(t *testing.T) {
	var live liveSessions
	var accepted [2]atomic.Int32
	var attempts, finished sync.WaitGroup
	start, releaseAll := make(chan struct{}), make(chan struct{})
	for user := range accepted {
		for range 100 {
			attempts.Add(1)
			finished.Add(1)
			go func() {
				defer finished.Done()
				<-start
				release, ok := live.TryAcquire([]byte{byte(user)})
				if ok {
					accepted[user].Add(1)
				}
				attempts.Done()
				<-releaseAll
				if ok {
					release()
					release() // Repeated cleanup must not give back a second slot.
				}
			}()
		}
	}
	close(start)
	attempts.Wait()
	close(releaseAll)
	finished.Wait()
	for user := range accepted {
		if got := accepted[user].Load(); got != maxLivePerClient {
			t.Fatalf("user %d: admitted %d, want %d", user, got, maxLivePerClient)
		}
	}
	if len(live.perClient) != 0 {
		t.Fatal("ended sessions left client buckets behind")
	}
}

type liveDispatcher struct {
	recordingDispatcher
	entered chan struct{}
	err     error
}

func (d *liveDispatcher) Dispatch(ctx context.Context, dest xnet.Destination) (*transport.Link, error) {
	link, _ := d.recordingDispatcher.Dispatch(ctx, dest)
	close(d.entered)
	return link, d.err
}

type liveAttempt struct {
	rc     *Conn
	d      *liveDispatcher
	down   *pipe.Writer
	done   chan struct{}
	err    error // Read only after done closes.
	cancel context.CancelFunc
}

func startLiveAttempt(t *testing.T, srv *Server, key noise.DHKey, wrap func(stat.Connection) stat.Connection, dispatchErr error) *liveAttempt {
	t.Helper()
	client, server := tcpPair(t)
	var conn stat.Connection = server
	if wrap != nil {
		conn = wrap(conn)
	}
	upR, upW := pipe.New(pipe.WithoutSizeLimit())
	downR, downW := pipe.New(pipe.WithoutSizeLimit())
	ctx, cancel := context.WithCancel(context.Background())
	a := &liveAttempt{
		d: &liveDispatcher{
			recordingDispatcher: recordingDispatcher{link: &transport.Link{Reader: downR, Writer: upW}},
			entered:             make(chan struct{}), err: dispatchErr,
		},
		down: downW, done: make(chan struct{}), cancel: cancel,
	}
	go func() {
		a.err = srv.Process(ctx, xnet.Network_TCP, conn, a.d)
		conn.Close() // The inbound worker also closes after Process returns.
		close(a.done)
	}()
	t.Cleanup(func() {
		cancel()
		client.Close()
		server.Close()
		upR.Interrupt()
		downW.Close()
		a.wait(t)
	})
	rc, err := ClientHandshake(client, key, srv.privateKey.Public, testKeys(), defaultPadPolicy())
	if err != nil {
		t.Fatal(err)
	}
	a.rc = rc
	return a
}

func (a *liveAttempt) wait(t *testing.T) {
	t.Helper()
	select {
	case <-a.done:
	case <-time.After(5 * time.Second):
		t.Fatal("Process did not return")
	}
}

func (a *liveAttempt) request(t *testing.T, dest xnet.Destination) {
	t.Helper()
	header, err := encodeHeader(dest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.rc.Write(header); err != nil {
		t.Fatal(err)
	}
	select {
	case <-a.d.entered:
	case <-a.done:
		if !a.d.called {
			t.Fatalf("Process ended before dispatch: %v", a.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("request was not dispatched")
	}
}

func TestProcessLiveSessionCap(t *testing.T) {
	alice, bob := newKey(t), newKey(t)
	// Both users have an empty email and the same source IP.
	srv := newProbeServer(t, xnet.Destination{}, alice, bob)
	var sessions []*liveAttempt
	for i := 0; i < maxLivePerClient; i++ {
		a := startLiveAttempt(t, srv, alice, nil, nil)
		dest := tcpDest
		if i%2 == 0 {
			dest.Network = xnet.Network_UDP
		}
		a.request(t, dest)
		sessions = append(sessions, a)
	}
	refused := startLiveAttempt(t, srv, alice, nil, nil)
	// No request header: the live cap must reject even a client that stalls here.
	refused.wait(t)
	if refused.err != nil || refused.d.called {
		t.Fatalf("over-cap session: error %v, dispatched %v", refused.err, refused.d.called)
	}
	if data, err := readUntilEOF(refused.rc, time.Second); len(data) != 0 || err == nil {
		// Conn requires an authenticated end frame; a refused connection closes raw.
		t.Fatalf("refused connection was not closed without data: %d bytes, %v", len(data), err)
	} else if timeout, ok := err.(interface{ Timeout() bool }); ok && timeout.Timeout() {
		t.Fatal("refused connection remained open")
	}

	// Refusing the 33rd must leave the 32nd able to carry traffic.
	last := sessions[len(sessions)-1]
	if err := last.down.WriteMultiBuffer(buf.MultiBuffer{buf.FromBytes([]byte("alive"))}); err != nil {
		t.Fatal(err)
	}
	last.rc.SetReadDeadline(time.Now().Add(5 * time.Second))
	got := make([]byte, 5)
	if _, err := io.ReadFull(last.rc, got); err != nil || string(got) != "alive" {
		t.Fatalf("32nd session lost traffic: %q, %v", got, err)
	}
	other := startLiveAttempt(t, srv, bob, nil, nil)
	other.request(t, tcpDest)

	// Clean EOF frees a slot; the next connection for the same key succeeds.
	sessions[0].rc.CloseWrite()
	sessions[0].down.Close()
	sessions[0].wait(t)
	if sessions[0].err != nil {
		t.Fatal(sessions[0].err)
	}
	replacement := startLiveAttempt(t, srv, alice, nil, nil)
	replacement.request(t, tcpDest)
}

type liveDeadlineFailure struct {
	stat.Connection
	failAt, calls int
}

func (c *liveDeadlineFailure) SetReadDeadline(deadline time.Time) error {
	c.calls++
	if c.calls == c.failAt {
		return errors.New("injected deadline failure")
	}
	return c.Connection.SetReadDeadline(deadline)
}

func TestProcessLiveSlotReleasedOnError(t *testing.T) {
	for _, mode := range []string{"set deadline", "clear deadline", "header", "dispatch", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			key := newKey(t)
			srv := newProbeServer(t, xnet.Destination{}, key)
			var wrap func(stat.Connection) stat.Connection
			if mode == "set deadline" || mode == "clear deadline" {
				wrap = func(conn stat.Connection) stat.Connection {
					at := 1
					if mode == "clear deadline" {
						at = 2
					}
					return &liveDeadlineFailure{Connection: conn, failAt: at}
				}
			}
			var dispatchErr error
			if mode == "dispatch" {
				dispatchErr = errors.New("injected dispatch failure")
			}
			a := startLiveAttempt(t, srv, key, wrap, dispatchErr)
			switch mode {
			case "header":
				a.rc.CloseWrite()
			case "clear deadline":
				header, _ := encodeHeader(tcpDest)
				a.rc.Write(header)
			case "dispatch", "cancel":
				a.request(t, tcpDest)
				if mode == "cancel" {
					a.cancel()
				}
			}
			a.wait(t)
			if a.err == nil {
				t.Fatal("expected Process error")
			}
			srv.live.mu.Lock()
			remaining := len(srv.live.perClient)
			srv.live.mu.Unlock()
			if remaining != 0 {
				t.Fatal("failed session retained its slot")
			}
			processAs(t, srv, key, nil)
		})
	}
}
