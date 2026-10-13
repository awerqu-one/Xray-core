package raywire

import (
	"bytes"
	"strings"
	"testing"
)

// TestParseFallbackRefusesUnsafeHosts checks the hosts that would make the relay
// dial this inbound, or that the system resolver may read as one.
func TestParseFallbackRefusesUnsafeHosts(t *testing.T) {
	for _, tc := range []struct {
		addr    string
		wantErr string
	}{
		{"0.0.0.0:443", `"fallback" must not be a wildcard address`},
		{"[::]:443", `"fallback" must not be a wildcard address`},
		{"[::ffff:0.0.0.0]:443", `"fallback" must not be a wildcard address`},
		{"[::%lo]:443", `"fallback" host must not have a zone`},
		{"[fe80::1%25eth0]:443", `"fallback" host must not have a zone`},
		{"0.0.0.0%lo:443", `"fallback" host must not have a zone`},
		{"0:443", `"fallback" host must be a canonical IP address or a domain name`},
		{"0.0:443", `"fallback" host must be a canonical IP address or a domain name`},
		{"0x0:443", `"fallback" host must be a canonical IP address or a domain name`},
		{"00:443", `"fallback" host must be a canonical IP address or a domain name`},
		{"127.1:443", `"fallback" host must be a canonical IP address or a domain name`},
		{"0.0.0.0.:443", `"fallback" host must be a canonical IP address or a domain name`},
	} {
		t.Run(tc.addr, func(t *testing.T) {
			_, err := ParseFallback(tc.addr)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ParseFallback(%q) error = %v, want containing %q", tc.addr, err, tc.wantErr)
			}
		})
	}
}

// TestParseFallbackAcceptsNamedHosts checks that canonical IPs and domains pass,
// including a domain whose first label looks like a hex number.
func TestParseFallbackAcceptsNamedHosts(t *testing.T) {
	for _, addr := range []string{
		"127.0.0.1:443",
		"[::1]:443",
		"example.com:443",
		"localhost:8443",
		"dead.example:443",
	} {
		d, err := ParseFallback(addr)
		if err != nil {
			t.Fatalf("ParseFallback(%q): %v", addr, err)
		}
		if !d.IsValid() {
			t.Fatalf("ParseFallback(%q) returned an invalid destination", addr)
		}
	}
}

// TestLooksNumeric checks the hosts that inet_aton reads as numbers. A host that
// starts with a letter is a name even when it holds only hex letters.
func TestLooksNumeric(t *testing.T) {
	for host, want := range map[string]bool{
		"0":            true,
		"0x0":          true,
		"127.1":        true,
		"0XFF.0":       true,
		"dead":         false,
		"cafe.example": false,
		"":             false,
		"example.com":  false,
	} {
		if got := looksNumeric(host); got != want {
			t.Errorf("looksNumeric(%q) = %v, want %v", host, got, want)
		}
	}
}

// TestValidateAccounts checks the client list rules that both config paths share.
func TestValidateAccounts(t *testing.T) {
	key := func(b byte) []byte { return bytes.Repeat([]byte{b}, 32) }
	account := func(b byte, email string) *Account {
		return &Account{PublicKey: key(b), Email: email}
	}
	for _, tc := range []struct {
		name     string
		accounts []*Account
		wantErr  string // empty when the list must be accepted
	}{
		{"empty emails may repeat", []*Account{account(1, ""), account(2, "")}, ""},
		{"emails that differ in case", []*Account{account(1, "Alice@example.com"), account(2, "alice@example.com")}, ""},
		{"duplicate key", []*Account{account(1, ""), account(1, "")}, `"clients[1].publicKey" duplicates "clients[0].publicKey"`},
		{"duplicate email", []*Account{account(1, "a@example.com"), account(2, "a@example.com")}, `"clients[1].email" duplicates "clients[0].email"`},
		{"email with a control character", []*Account{account(1, "a\x00b@example.com")}, `"clients[0].email" must not contain control characters`},
		{"email with a leading space", []*Account{account(1, " a@example.com")}, `"clients[0].email" must not have leading or trailing spaces`},
		{"email longer than 128 bytes", []*Account{account(1, strings.Repeat("a", 129))}, `"clients[0].email" must be at most 128 bytes, got 129`},
		{"email that is not UTF-8", []*Account{account(1, "a\xff@example.com")}, `"clients[0].email" must be valid UTF-8`},
		{"email with the stats separator", []*Account{account(1, "alice>>>bob@example.com")}, `"clients[0].email" must not contain ">>>"`},
		{"email ending in an angle bracket", []*Account{account(1, "alice>@example.com>")}, `"clients[0].email" must not end with ">"`},
		{"email with a single angle bracket", []*Account{account(1, "alice>bob@example.com")}, ""},
		{"email with two angle brackets", []*Account{account(1, "alice>>bob@example.com")}, ""},
		{"email with a zero-width space", []*Account{account(1, "alice@example.com\u200b")}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"email with a BOM", []*Account{account(1, "\ufeffalice@example.com")}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"email with an RTL override", []*Account{account(1, "alice\u202eexample.com")}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"email with a no-break space", []*Account{account(1, "alice\u00a0bob@example.com")}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"email with an ideographic space", []*Account{account(1, "alice\u3000bob@example.com")}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"email with a plain space inside", []*Account{account(1, "alice bob@example.com")}, ""},
		{"email with a combining mark", []*Account{account(1, "a\u0301lice@example.com")}, ""},
		{"email with a non-ASCII letter", []*Account{account(1, "José@example.com")}, ""},
		{"key of the wrong length", []*Account{{PublicKey: make([]byte, 31)}}, "client 0 public key must be 32 bytes"},
		{"all-zero key", []*Account{{PublicKey: make([]byte, 32)}}, `"clients[0].publicKey" is an invalid all-zero key`},
		{"nil entry", []*Account{nil}, "client 0 is nil"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateAccounts(tc.accounts)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateAccounts: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("ValidateAccounts error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewServerRejectsInvalidAccounts checks that the typed config path runs the
// same client checks as the JSON path.
func TestNewServerRejectsInvalidAccounts(t *testing.T) {
	ctx := coreContext(t)
	alice, bob := newKey(t), newKey(t)
	for _, tc := range []struct {
		name    string
		clients []*Account
		wantErr string
	}{
		{"duplicate public key", []*Account{{PublicKey: alice.Public}, {PublicKey: alice.Public}}, `"clients[1].publicKey" duplicates "clients[0].publicKey"`},
		{"duplicate email", []*Account{{PublicKey: alice.Public, Email: "a@example.com"}, {PublicKey: bob.Public, Email: "a@example.com"}}, `"clients[1].email" duplicates "clients[0].email"`},
		{"email with a control character", []*Account{{PublicKey: alice.Public, Email: "a\tb@example.com"}}, `"clients[0].email" must not contain control characters`},
		{"email with a trailing space", []*Account{{PublicKey: alice.Public, Email: "a@example.com "}}, `"clients[0].email" must not have leading or trailing spaces`},
		{"email longer than 128 bytes", []*Account{{PublicKey: alice.Public, Email: strings.Repeat("a", 129)}}, `"clients[0].email" must be at most 128 bytes, got 129`},
		{"email with the stats separator", []*Account{{PublicKey: alice.Public, Email: "alice>>>bob"}}, `"clients[0].email" must not contain ">>>"`},
		{"email with a zero-width space", []*Account{{PublicKey: alice.Public, Email: "a@example.com\u200b"}}, `"clients[0].email" must not contain invisible or non-ASCII space characters`},
		{"all-zero public key", []*Account{{PublicKey: make([]byte, 32)}}, `"clients[0].publicKey" is an invalid all-zero key`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := serverConfig(t)
			config.Clients = tc.clients
			_, err := NewServer(ctx, config)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewServer error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}

	// Two clients without an email are not a duplicate, so NewServer accepts them.
	config := serverConfig(t)
	config.Clients = []*Account{{PublicKey: alice.Public}, {PublicKey: bob.Public}}
	if _, err := NewServer(ctx, config); err != nil {
		t.Fatalf("NewServer with two clients without an email: %v", err)
	}
}
