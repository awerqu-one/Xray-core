package conf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xtls/xray-core/proxy/raywire"
	"google.golang.org/protobuf/proto"
)

// assertRaywireEmail checks an accepted client email against the rules of the
// stats key, written out here rather than shared with the product code.
func assertRaywireEmail(t *testing.T, email string) {
	t.Helper()
	if len(email) > 128 || !utf8.ValidString(email) {
		t.Fatalf("accepted the email %q", email)
	}
	for _, r := range email {
		if unicode.IsControl(r) || (r != ' ' && unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs)) {
			t.Fatalf("accepted the invisible or control character in %q", email)
		}
	}
	if strings.TrimSpace(email) != email || strings.Contains(email, ">>>") || strings.HasSuffix(email, ">") {
		t.Fatalf("accepted the email %q", email)
	}
}

// assertRaywirePadding checks the padding ranges that the documentation gives.
func assertRaywirePadding(t *testing.T, p *raywire.Padding) {
	t.Helper()
	if p == nil {
		t.Fatal("accepted a config without a padding message")
	}
	if p.Handshake > 512 || p.Frame > 1024 || (p.Bucket != 0 && (p.Bucket < 16 || p.Bucket > 4096)) {
		t.Fatalf("accepted padding %+v", p)
	}
}

// assertRaywireKey checks a 32-byte key that is not all zero.
func assertRaywireKey(t *testing.T, key []byte, field string) {
	t.Helper()
	if len(key) != 32 || bytes.Equal(key, make([]byte, 32)) {
		t.Fatalf("accepted %s of %d bytes", field, len(key))
	}
}

// checkRaywireServer runs the server config path on one JSON input. An error must
// come with no message. An accepted config must hold only what the server would
// accept, and building it again must give the same message.
func checkRaywireServer(t *testing.T, input []byte) {
	t.Helper()
	c := new(RaywireServerConfig)
	if err := json.Unmarshal(input, c); err != nil {
		return
	}
	msg, err := c.Build()
	if err != nil {
		if msg != nil {
			t.Fatalf("Build failed with %v but returned a message", err)
		}
		return
	}
	cfg, ok := msg.(*raywire.ServerConfig)
	if !ok {
		t.Fatalf("Build returned %T", msg)
	}
	assertRaywireKey(t, cfg.PrivateKey, "privateKey")
	assertRaywireKey(t, cfg.Psk, "psk")
	if base64.RawURLEncoding.EncodeToString(cfg.Psk) != c.Psk {
		t.Fatalf("accepted the psk %q, which is not canonical", c.Psk)
	}
	// previousPsk and its expiry are both set or both unset, and an accepted
	// previousPsk is a canonical key that differs from psk and has not expired past
	// the 14-day limit.
	if (cfg.PreviousPsk == nil) != (cfg.PreviousPskUntil == 0) {
		t.Fatalf("accepted previousPsk %v with previousPskUntil %d", cfg.PreviousPsk != nil, cfg.PreviousPskUntil)
	}
	if cfg.PreviousPsk != nil {
		assertRaywireKey(t, cfg.PreviousPsk, "previousPsk")
		if bytes.Equal(cfg.PreviousPsk, cfg.Psk) {
			t.Fatal("accepted a previousPsk equal to psk")
		}
		if base64.RawURLEncoding.EncodeToString(cfg.PreviousPsk) != c.PreviousPsk {
			t.Fatalf("accepted the previousPsk %q, which is not canonical", c.PreviousPsk)
		}
		if time.Unix(cfg.PreviousPskUntil, 0).After(time.Now().Add(raywire.MaxPreviousPskOverlap)) {
			t.Fatalf("accepted previousPskUntil %d more than 14 days ahead", cfg.PreviousPskUntil)
		}
	}
	if len(cfg.Clients) == 0 {
		t.Fatal("accepted a server without clients")
	}
	if err := raywire.ValidateAccounts(cfg.Clients); err != nil {
		t.Fatalf("accepted accounts that the server refuses: %v", err)
	}
	for _, account := range cfg.Clients {
		assertRaywireKey(t, account.PublicKey, "client public key")
		assertRaywireEmail(t, account.Email)
	}
	assertRaywirePadding(t, cfg.Padding)
	if cfg.Fallback == "" {
		if !cfg.AllowSilentClose {
			t.Fatal("accepted a server with no fallback and no allowSilentClose")
		}
	} else {
		dest, err := raywire.ParseFallback(cfg.Fallback)
		if err != nil {
			t.Fatalf("accepted the fallback %q: %v", cfg.Fallback, err)
		}
		if dest.Address.Family().IsIP() && dest.Address.IP().IsUnspecified() {
			t.Fatalf("accepted the wildcard fallback %q", cfg.Fallback)
		}
	}

	again, err := c.Build()
	if err != nil || !proto.Equal(msg, again) {
		t.Fatalf("building again gives %v and %v", err, again)
	}
}

// checkRaywireClient runs the client config path on one JSON input, with the same
// rules as checkRaywireServer.
func checkRaywireClient(t *testing.T, input []byte) {
	t.Helper()
	c := new(RaywireClientConfig)
	if err := json.Unmarshal(input, c); err != nil {
		return
	}
	msg, err := c.Build()
	if err != nil {
		if msg != nil {
			t.Fatalf("Build failed with %v but returned a message", err)
		}
		return
	}
	cfg, ok := msg.(*raywire.ClientConfig)
	if !ok {
		t.Fatalf("Build returned %T", msg)
	}
	if cfg.Port == 0 || cfg.Port > 65535 {
		t.Fatalf("accepted port %d", cfg.Port)
	}
	assertRaywireKey(t, cfg.PrivateKey, "privateKey")
	assertRaywireKey(t, cfg.ServerPublicKey, "serverPublicKey")
	assertRaywireKey(t, cfg.Psk, "psk")
	if base64.RawURLEncoding.EncodeToString(cfg.Psk) != c.Psk {
		t.Fatalf("accepted the psk %q, which is not canonical", c.Psk)
	}
	assertRaywirePadding(t, cfg.Padding)
}

// FuzzRaywireConfig feeds arbitrary JSON to the raywire config builders, the server
// one when server is set and the client one otherwise. A malformed document must be
// refused with an error and no message. An accepted document must yield a config
// that the server or client would accept at run time.
func FuzzRaywireConfig(f *testing.F) {
	priv := raywireTestKey(0x01)
	pub := raywireTestKey(0x02)
	// Expiries are built from the current time, so the seeds keep their meaning when
	// the fuzz target runs later: a 48-hour expiry is inside the 14-day limit.
	future := time.Now().Add(48 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
	tooFar := time.Now().Add(14*24*time.Hour + time.Hour).UTC().Format(time.RFC3339)
	noZone := time.Now().Add(48 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	prevServer := func(psk, prev, until string) string {
		return `{"privateKey":"` + priv + `","psk":"` + psk + `","previousPsk":"` + prev + `","previousPskUntil":"` + until + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"203.0.113.9:443"}`
	}
	for _, seed := range []struct {
		server bool
		input  string
	}{
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `","email":"alice@example.com"}],"fallback":"203.0.113.9:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `"}],"allowSilentClose":true}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"example.com:443","padding":{"handshake":512,"frame":1024,"bucket":4096}}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `","email":"a>>>b"}],"fallback":"example.com:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[],"fallback":"example.com:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"0.0.0.0:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"[fe80::1%lo]:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"example.com:443","padding":{"bucket":15}}`},
		{false, `{"address":"203.0.113.10","port":443,"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","serverPublicKey":"` + pub + `"}`},
		{false, `{"address":"example.com","port":443,"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","serverPublicKey":"` + pub + `","padding":{"handshake":513}}`},
		{false, `{"address":"example.com","port":0,"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","serverPublicKey":"` + pub + `"}`},
		{false, `{"address":"example.com","port":443,"privateKey":"` + raywireTestKey(0) + `","psk":"` + raywireTestPSK + `","serverPublicKey":"` + pub + `"}`},
		{false, `{"address":"example.com","port":443,"privateKey":"` + priv + `","psk":"` + raywireTestPSK + `","serverPublicKey":"AAAA"}`},
		{true, `{"privateKey":"` + priv + `","clients":[{"publicKey":"` + pub + `"}],"fallback":"203.0.113.9:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK[:42] + `N","clients":[{"publicKey":"` + pub + `"}],"fallback":"203.0.113.9:443"}`},
		{true, `{"privateKey":"` + priv + `","psk":"` + raywireTestPSK[:42] + `O","clients":[{"publicKey":"` + pub + `"}],"fallback":"203.0.113.9:443"}`},
		{false, `{"address":"example.com","port":443,"privateKey":"` + priv + `","psk":"` + raywireTestPSK[:42] + `P","serverPublicKey":"` + pub + `"}`},
		{false, `{"address":"203.0.113.10","port":443,"privateKey":"` + priv + `","psk":"AAAA","serverPublicKey":"` + pub + `"}`},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04), future)},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04), past)},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04), tooFar)},
		{true, prevServer(raywireTestPSK, raywireTestPSK, future)},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04), noZone)},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04), "")},
		{true, prevServer(raywireTestPSK, "", future)},
		{true, prevServer("AAAA", raywireTestKey(0x04), future)},
		{true, prevServer(raywireTestPSK, strings.Repeat("A", 43), future)},
		{true, prevServer(raywireTestPSK, raywireTestKey(0x04)+"=", future)},
		{false, `{}`},
		{false, `null`},
	} {
		f.Add(seed.server, []byte(seed.input))
	}

	f.Fuzz(func(t *testing.T, server bool, input []byte) {
		if server {
			checkRaywireServer(t, input)
		} else {
			checkRaywireClient(t, input)
		}
	})
}
