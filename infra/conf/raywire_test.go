package conf

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/proxy/raywire"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// raywireTestBytes returns 32 copies of b.
func raywireTestBytes(b byte) []byte {
	key := make([]byte, 32)
	for i := range key {
		key[i] = b
	}
	return key
}

// raywireTestKey returns the unpadded base64url encoding of raywireTestBytes(b).
func raywireTestKey(b byte) string {
	return base64.RawURLEncoding.EncodeToString(raywireTestBytes(b))
}

// raywireTestPSK is the pre-shared key of the valid fixtures. It decodes to
// raywireTestBytes(0x03).
var raywireTestPSK = raywireTestKey(0x03)

// raywireDefaultPadding is the padding filled in when a config has none.
func raywireDefaultPadding() *raywire.Padding {
	return &raywire.Padding{Handshake: 255, Frame: 32, Bucket: 0}
}

func buildRaywireClient(input string) (proto.Message, error) {
	c := new(RaywireClientConfig)
	if err := json.Unmarshal([]byte(input), c); err != nil {
		return nil, err
	}
	return c.Build()
}

func buildRaywireServer(input string) (proto.Message, error) {
	c := new(RaywireServerConfig)
	if err := json.Unmarshal([]byte(input), c); err != nil {
		return nil, err
	}
	return c.Build()
}

func TestRaywireClientConfig(t *testing.T) {
	priv := raywireTestKey(0x01)
	server := raywireTestKey(0x02)

	tests := []struct {
		name    string
		input   string
		want    proto.Message
		wantErr string
	}{
		{
			name: "valid",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `"
			}`,
			want: &raywire.ClientConfig{
				Address:         "example.com",
				Port:            443,
				PrivateKey:      raywireTestBytes(0x01),
				Psk:             raywireTestBytes(0x03),
				ServerPublicKey: raywireTestBytes(0x02),
				Padding:         raywireDefaultPadding(),
			},
		},
		{
			name: "explicit padding",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `",
				"padding": {"handshake": 0, "frame": 0, "bucket": 256}
			}`,
			want: &raywire.ClientConfig{
				Address:         "example.com",
				Port:            443,
				PrivateKey:      raywireTestBytes(0x01),
				Psk:             raywireTestBytes(0x03),
				ServerPublicKey: raywireTestBytes(0x02),
				Padding:         &raywire.Padding{Handshake: 0, Frame: 0, Bucket: 256},
			},
		},
		{
			name: "partial padding fills defaults",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `",
				"padding": {"frame": 100}
			}`,
			want: &raywire.ClientConfig{
				Address:         "example.com",
				Port:            443,
				PrivateKey:      raywireTestBytes(0x01),
				Psk:             raywireTestBytes(0x03),
				ServerPublicKey: raywireTestBytes(0x02),
				Padding:         &raywire.Padding{Handshake: 255, Frame: 100, Bucket: 0},
			},
		},
		{
			name: "nil address",
			input: `{
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `"
			}`,
			wantErr: `"address" is not set`,
		},
		{
			name: "port zero",
			input: `{
				"address": "example.com",
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `"
			}`,
			wantErr: `"port" is not set`,
		},
		{
			name: "missing private key",
			input: `{
				"address": "example.com",
				"port": 443,
				"serverPublicKey": "` + server + `"
			}`,
			wantErr: `"privateKey" is not set`,
		},
		{
			name: "bad base64 private key",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "not*base64!",
				"serverPublicKey": "` + server + `"
			}`,
			wantErr: `"privateKey" is not valid unpadded base64url`,
		},
		{
			name: "padded server public key",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + server + `=="
			}`,
			wantErr: `"serverPublicKey" is not valid unpadded base64url`,
		},
		{
			name: "short server public key",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + base64.RawURLEncoding.EncodeToString(make([]byte, 31)) + `"
			}`,
			wantErr: `"serverPublicKey" must decode to 32 bytes, got 31`,
		},
		{
			name: "all-zero server public key",
			input: `{
				"address": "example.com",
				"port": 443,
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"serverPublicKey": "` + raywireTestKey(0x00) + `"
			}`,
			wantErr: `"serverPublicKey" is an invalid all-zero key`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildRaywireClient(tc.input)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !proto.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRaywireServerConfig(t *testing.T) {
	priv := raywireTestKey(0x01)
	client := raywireTestKey(0x02)

	tests := []struct {
		name    string
		input   string
		want    proto.Message
		wantErr string
	}{
		{
			name: "valid",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:8443"
			}`,
			want: &raywire.ServerConfig{
				PrivateKey: raywireTestBytes(0x01),
				Psk:        raywireTestBytes(0x03),
				Clients: []*raywire.Account{
					{PublicKey: raywireTestBytes(0x02)},
				},
				Padding:  raywireDefaultPadding(),
				Fallback: "127.0.0.1:8443",
			},
		},
		{
			name: "silent close without fallback",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"allowSilentClose": true
			}`,
			want: &raywire.ServerConfig{
				PrivateKey: raywireTestBytes(0x01),
				Psk:        raywireTestBytes(0x03),
				Clients: []*raywire.Account{
					{PublicKey: raywireTestBytes(0x02)},
				},
				Padding:          raywireDefaultPadding(),
				AllowSilentClose: true,
			},
		},
		{
			name: "fallback with domain and silent close",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "decoy.example:443",
				"allowSilentClose": true,
				"padding": {"handshake": 512, "frame": 1024, "bucket": 4096}
			}`,
			want: &raywire.ServerConfig{
				PrivateKey: raywireTestBytes(0x01),
				Psk:        raywireTestBytes(0x03),
				Clients: []*raywire.Account{
					{PublicKey: raywireTestBytes(0x02)},
				},
				Padding:          &raywire.Padding{Handshake: 512, Frame: 1024, Bucket: 4096},
				Fallback:         "decoy.example:443",
				AllowSilentClose: true,
			},
		},
		{
			name: "missing clients",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"clients" must contain at least one client`,
		},
		{
			name: "empty clients",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"clients" must contain at least one client`,
		},
		{
			name: "missing private key",
			input: `{
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"privateKey" is not set`,
		},
		{
			name: "bad base64 private key",
			input: `{
				"privateKey": "%%%",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"privateKey" is not valid unpadded base64url`,
		},
		{
			name: "all-zero private key",
			input: `{
				"privateKey": "` + raywireTestKey(0x00) + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"privateKey" is an invalid all-zero key`,
		},
		{
			name: "wrong length client public key",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [
					{"publicKey": "` + client + `"},
					{"publicKey": "` + base64.RawURLEncoding.EncodeToString(make([]byte, 33)) + `"}
				],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"clients[1].publicKey" must decode to 32 bytes, got 33`,
		},
		{
			name: "all-zero client public key",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + raywireTestKey(0x00) + `"}],
				"fallback": "127.0.0.1:8443"
			}`,
			wantErr: `"clients[0].publicKey" is an invalid all-zero key`,
		},
		{
			name: "fallback missing without silent close",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}]
			}`,
			wantErr: `"fallback" is required unless "allowSilentClose" is set`,
		},
		{
			name: "fallback empty with silent close false",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "",
				"allowSilentClose": false
			}`,
			wantErr: `"fallback" is required unless "allowSilentClose" is set`,
		},
		{
			name: "fallback without port",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1"
			}`,
			wantErr: `"fallback" must be host:port`,
		},
		{
			name: "fallback port zero",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:0"
			}`,
			wantErr: `"fallback" port must be between 1 and 65535`,
		},
		{
			name: "fallback port too large",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:65536"
			}`,
			wantErr: `"fallback" port must be between 1 and 65535`,
		},
		{
			name: "fallback port not a number",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:http"
			}`,
			wantErr: `"fallback" port must be between 1 and 65535`,
		},
		{
			name: "padding handshake out of range",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.0.0.1:8443",
				"padding": {"handshake": 513}
			}`,
			wantErr: `"padding.handshake" must be at most 512, got 513`,
		},
		{
			name: "fallback without host",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": ":443"
			}`,
			wantErr: `"fallback" must name a host`,
		},
		{
			name: "fallback IPv4 wildcard",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "0.0.0.0:443"
			}`,
			wantErr: `"fallback" must not be a wildcard address`,
		},
		{
			name: "fallback IPv6 wildcard",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "[::]:443"
			}`,
			wantErr: `"fallback" must not be a wildcard address`,
		},
		{
			name: "fallback IPv4-mapped wildcard",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "[::ffff:0.0.0.0]:443"
			}`,
			wantErr: `"fallback" must not be a wildcard address`,
		},
		{
			name: "fallback IPv6 wildcard with a zone",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "[::%lo]:443"
			}`,
			wantErr: `"fallback" host must not have a zone`,
		},
		{
			name: "fallback host with a zone",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "[fe80::1%25eth0]:443"
			}`,
			wantErr: `"fallback" host must not have a zone`,
		},
		{
			name: "fallback bare zero host",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "0:443"
			}`,
			wantErr: `"fallback" host must be a canonical IP address or a domain name`,
		},
		{
			name: "fallback zero host with dots",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "0.0:443"
			}`,
			wantErr: `"fallback" host must be a canonical IP address or a domain name`,
		},
		{
			name: "fallback hex zero host",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "0x0:443"
			}`,
			wantErr: `"fallback" host must be a canonical IP address or a domain name`,
		},
		{
			name: "fallback leading-zero zero host",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "00:443"
			}`,
			wantErr: `"fallback" host must be a canonical IP address or a domain name`,
		},
		{
			name: "fallback short IPv4 form",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "127.1:443"
			}`,
			wantErr: `"fallback" host must be a canonical IP address or a domain name`,
		},
		{
			name: "fallback domain starting with a hex-like word is a name",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "dead.example:443"
			}`,
			want: &raywire.ServerConfig{
				PrivateKey: raywireTestBytes(0x01),
				Psk:        raywireTestBytes(0x03),
				Clients: []*raywire.Account{
					{PublicKey: raywireTestBytes(0x02)},
				},
				Padding:  raywireDefaultPadding(),
				Fallback: "dead.example:443",
			},
		},
		{
			name: "fallback loopback is allowed",
			input: `{
				"privateKey": "` + priv + `",
				"psk": "` + raywireTestPSK + `",
				"clients": [{"publicKey": "` + client + `"}],
				"fallback": "[::1]:8443"
			}`,
			want: &raywire.ServerConfig{
				PrivateKey: raywireTestBytes(0x01),
				Psk:        raywireTestBytes(0x03),
				Clients: []*raywire.Account{
					{PublicKey: raywireTestBytes(0x02)},
				},
				Padding:  raywireDefaultPadding(),
				Fallback: "[::1]:8443",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := buildRaywireServer(tc.input)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !proto.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

// TestRaywirePaddingRanges checks each padding limit on both the client and
// the server. The limits are inclusive, and 0 is valid for each field.
func TestRaywirePaddingRanges(t *testing.T) {
	priv := raywireTestKey(0x01)
	peer := raywireTestKey(0x02)

	tests := []struct {
		field string
		value uint32
		ok    bool
	}{
		{"handshake", 0, true},
		{"handshake", 512, true},
		{"handshake", 513, false},
		{"frame", 0, true},
		{"frame", 1024, true},
		{"frame", 1025, false},
		{"bucket", 0, true},
		{"bucket", 15, false},
		{"bucket", 16, true},
		{"bucket", 4096, true},
		{"bucket", 4097, false},
	}

	for _, tc := range tests {
		padding := fmt.Sprintf(`{%q: %d}`, tc.field, tc.value)
		client := `{
			"address": "example.com",
			"port": 443,
			"privateKey": "` + priv + `",
			"psk": "` + raywireTestPSK + `",
			"serverPublicKey": "` + peer + `",
			"padding": ` + padding + `
		}`
		server := `{
			"privateKey": "` + priv + `",
			"psk": "` + raywireTestPSK + `",
			"clients": [{"publicKey": "` + peer + `"}],
			"fallback": "127.0.0.1:8443",
			"padding": ` + padding + `
		}`
		for _, side := range []struct {
			name  string
			build func(string) (proto.Message, error)
			input string
		}{
			{"client", buildRaywireClient, client},
			{"server", buildRaywireServer, server},
		} {
			t.Run(fmt.Sprintf("%s %s=%d %s", side.name, tc.field, tc.value, map[bool]string{true: "ok", false: "rejected"}[tc.ok]), func(t *testing.T) {
				_, err := side.build(side.input)
				if tc.ok && err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if !tc.ok && err == nil {
					t.Fatal("expected an error")
				}
			})
		}
	}
}

// TestRaywireServerAccountEmail checks the optional email of each client and the
// rules that keep the emails and the keys unique.
func TestRaywireServerAccountEmail(t *testing.T) {
	a := raywireTestKey(0x0a)
	b := raywireTestKey(0x0b)
	// config puts the given client entries into an otherwise valid server config.
	config := func(clients string) string {
		return `{"privateKey": "` + raywireTestKey(0x01) + `", "psk": "` + raywireTestPSK + `", "fallback": "127.0.0.1:8443", "clients": [` + clients + `]}`
	}

	tests := []struct {
		name    string
		clients string
		want    []string // expected emails in order, when wantErr is empty
		wantErr string
	}{
		{
			name:    "no email",
			clients: `{"publicKey": "` + a + `"}`,
			want:    []string{""},
		},
		{
			name:    "empty email means none",
			clients: `{"publicKey": "` + a + `", "email": ""}`,
			want:    []string{""},
		},
		{
			name:    "email",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com"}`,
			want:    []string{"alice@example.com"},
		},
		{
			name:    "128 bytes",
			clients: `{"publicKey": "` + a + `", "email": "` + strings.Repeat("a", 128) + `"}`,
			want:    []string{strings.Repeat("a", 128)},
		},
		{
			name:    "129 bytes",
			clients: `{"publicKey": "` + a + `", "email": "` + strings.Repeat("a", 129) + `"}`,
			wantErr: `"clients[0].email" must be at most 128 bytes, got 129`,
		},
		{
			// The limit counts bytes: 64 runes of two bytes each are 128 bytes.
			name:    "128 bytes of two-byte runes",
			clients: `{"publicKey": "` + a + `", "email": "` + strings.Repeat("é", 64) + `"}`,
			want:    []string{strings.Repeat("é", 64)},
		},
		{
			name:    "130 bytes of two-byte runes",
			clients: `{"publicKey": "` + a + `", "email": "` + strings.Repeat("é", 65) + `"}`,
			wantErr: `"clients[0].email" must be at most 128 bytes, got 130`,
		},
		{
			name:    "tab",
			clients: `{"publicKey": "` + a + `", "email": "alice\texample.com"}`,
			wantErr: `"clients[0].email" must not contain control characters`,
		},
		{
			name:    "newline",
			clients: `{"publicKey": "` + a + `", "email": "alice\nexample.com"}`,
			wantErr: `"clients[0].email" must not contain control characters`,
		},
		{
			name:    "leading space",
			clients: `{"publicKey": "` + a + `", "email": " alice@example.com"}`,
			wantErr: `"clients[0].email" must not have leading or trailing spaces`,
		},
		{
			name:    "trailing space",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com "}`,
			wantErr: `"clients[0].email" must not have leading or trailing spaces`,
		},
		{
			name:    "only spaces",
			clients: `{"publicKey": "` + a + `", "email": "   "}`,
			wantErr: `"clients[0].email" must not have leading or trailing spaces`,
		},
		{
			name:    "stats separator",
			clients: `{"publicKey": "` + a + `", "email": "alice>>>bob@example.com"}`,
			wantErr: `"clients[0].email" must not contain ">>>"`,
		},
		{
			name:    "trailing angle bracket",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com>"}`,
			wantErr: `"clients[0].email" must not end with ">"`,
		},
		{
			name:    "zero-width space",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com\u200b"}`,
			wantErr: `"clients[0].email" must not contain invisible or non-ASCII space characters`,
		},
		{
			name:    "byte order mark",
			clients: `{"publicKey": "` + a + `", "email": "\ufeffalice@example.com"}`,
			wantErr: `"clients[0].email" must not contain invisible or non-ASCII space characters`,
		},
		{
			name:    "no-break space",
			clients: `{"publicKey": "` + a + `", "email": "alice\u00a0bob@example.com"}`,
			wantErr: `"clients[0].email" must not contain invisible or non-ASCII space characters`,
		},
		{
			name:    "plain space inside",
			clients: `{"publicKey": "` + a + `", "email": "alice bob@example.com"}`,
			want:    []string{"alice bob@example.com"},
		},
		{
			name: "duplicate email",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com"},
				{"publicKey": "` + b + `", "email": "alice@example.com"}`,
			wantErr: `"clients[1].email" duplicates "clients[0].email"`,
		},
		{
			// Emails are compared exactly, so a case change makes a different user.
			name: "emails differ only in case",
			clients: `{"publicKey": "` + a + `", "email": "Alice@example.com"},
				{"publicKey": "` + b + `", "email": "alice@example.com"}`,
			want: []string{"Alice@example.com", "alice@example.com"},
		},
		{
			name: "duplicate public key",
			clients: `{"publicKey": "` + a + `", "email": "alice@example.com"},
				{"publicKey": "` + a + `", "email": "bob@example.com"}`,
			wantErr: `"clients[1].publicKey" duplicates "clients[0].publicKey"`,
		},
		{
			name: "bad email on the second client",
			clients: `{"publicKey": "` + a + `"},
				{"publicKey": "` + b + `", "email": "` + strings.Repeat("a", 129) + `"}`,
			wantErr: `"clients[1].email" must be at most 128 bytes, got 129`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := buildRaywireServer(config(tc.clients))
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			clients := msg.(*raywire.ServerConfig).Clients
			if len(clients) != len(tc.want) {
				t.Fatalf("got %d clients, want %d", len(clients), len(tc.want))
			}
			for i, client := range clients {
				if client.Email != tc.want[i] {
					t.Fatalf("clients[%d].Email = %q, want %q", i, client.Email, tc.want[i])
				}
			}
		})
	}
}

// TestRaywireAccountEmailUTF8 checks the UTF-8 rule on the struct. JSON decoding
// replaces invalid UTF-8 with U+FFFD, so the input cannot reach the rule from JSON.
func TestRaywireAccountEmailUTF8(t *testing.T) {
	c := &RaywireServerConfig{
		PrivateKey: raywireTestKey(0x01),
		Psk:        raywireTestPSK,
		Clients:    []RaywireAccount{{PublicKey: raywireTestKey(0x0a), Email: "al\xffice"}},
		Fallback:   "127.0.0.1:8443",
	}
	_, err := c.Build()
	if err == nil || !strings.Contains(err.Error(), `"clients[0].email" must be valid UTF-8`) {
		t.Fatalf("error = %v, want invalid UTF-8 rejection", err)
	}
}

// raywirePSKSample is a canonical psk in the form that the generation command
// prints. Its last character has the two unused bits clear.
const raywirePSKSample = "RRCyo0VROxPyio9qPrKqZEdJ3aZYRb1Wp8gHFQRA5Xk"

// raywirePSKClient puts psk, as raw JSON text, into an otherwise valid client config.
func raywirePSKClient(psk string) string {
	return `{
		"address": "example.com",
		"port": 443,
		"privateKey": "` + raywireTestKey(0x01) + `",
		"serverPublicKey": "` + raywireTestKey(0x02) + `",
		"psk": "` + psk + `"
	}`
}

// raywirePSKServer puts psk, as raw JSON text, into an otherwise valid server config.
func raywirePSKServer(psk string) string {
	return `{
		"privateKey": "` + raywireTestKey(0x01) + `",
		"clients": [{"publicKey": "` + raywireTestKey(0x02) + `"}],
		"fallback": "127.0.0.1:8443",
		"psk": "` + psk + `"
	}`
}

// TestRaywirePSKRequiredClient checks that a client config without a psk is refused
// with the raywire/3 message. An empty psk counts as missing.
func TestRaywirePSKRequiredClient(t *testing.T) {
	const want = `"psk" is not set; raywire requires a pre-shared key`
	missing := `{
		"address": "example.com",
		"port": 443,
		"privateKey": "` + raywireTestKey(0x01) + `",
		"serverPublicKey": "` + raywireTestKey(0x02) + `"
	}`
	for _, input := range []string{missing, raywirePSKClient("")} {
		_, err := buildRaywireClient(input)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want containing %q", err, want)
		}
	}
}

// TestRaywirePSKRequiredServer checks that a server config without a psk is refused
// with the raywire/3 message. An empty psk counts as missing.
func TestRaywirePSKRequiredServer(t *testing.T) {
	const want = `"psk" is not set; raywire requires a pre-shared key`
	missing := `{
		"privateKey": "` + raywireTestKey(0x01) + `",
		"clients": [{"publicKey": "` + raywireTestKey(0x02) + `"}],
		"fallback": "127.0.0.1:8443"
	}`
	for _, input := range []string{missing, raywirePSKServer("")} {
		_, err := buildRaywireServer(input)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("error = %v, want containing %q", err, want)
		}
	}
}

// TestRaywirePSKMalformed checks each refusal of a malformed psk on both sides. Each
// case names the first check of the documentation that fails.
func TestRaywirePSKMalformed(t *testing.T) {
	const notBase64 = `"psk" is not valid unpadded base64url`
	tests := []struct {
		name    string
		psk     string // raw JSON text
		wantErr string
	}{
		{"padded to 44 characters", raywirePSKSample + "=", notBase64},
		{"plus sign", "+" + raywirePSKSample[1:], notBase64},
		{"slash", "/" + raywirePSKSample[1:], notBase64},
		{"space", " " + raywirePSKSample[1:], notBase64},
		{"newline escape", raywirePSKSample + `\n`, notBase64},
		{"41 characters", raywirePSKSample[:41], notBase64},
		{"too short", raywirePSKSample[:40], `"psk" must decode to 32 bytes, got 30`},
		{"too long", raywirePSKSample + "A", `"psk" must decode to 32 bytes, got 33`},
		{"all zero", strings.Repeat("A", 43), `"psk" is an invalid all-zero key`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := buildRaywireClient(raywirePSKClient(tc.psk)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("client error = %v, want containing %q", err, tc.wantErr)
			}
			if _, err := buildRaywireServer(raywirePSKServer(tc.psk)); err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("server error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestRaywirePSKNonCanonical checks that a 43-character psk with an unused bit set
// is refused, even though a lenient decoder reads the same key from it. A 43-character
// value has two unused low bits in its last character, so each of the three non-zero
// settings of those bits is tried: bit 0, bit 1, and both.
func TestRaywirePSKNonCanonical(t *testing.T) {
	const want = `"psk" is not in canonical base64url form`
	sampleKey, err := base64.RawURLEncoding.DecodeString(raywirePSKSample)
	if err != nil || len(sampleKey) != 32 {
		t.Fatalf("sample does not decode to 32 bytes: %v", err)
	}
	zeroKey := make([]byte, 32)
	tests := []struct {
		name string
		psk  string
		key  []byte // what the lenient decoder reads from psk
	}{
		// The sample ends in k, which has both unused bits clear.
		{"sample with last character l, bit 0", raywirePSKSample[:42] + "l", sampleKey},
		{"sample with last character m, bit 1", raywirePSKSample[:42] + "m", sampleKey},
		{"sample with last character n, bits 0 and 1", raywirePSKSample[:42] + "n", sampleKey},
		// All zero with a set unused bit: the canonical check comes before the all-zero check.
		{"all A with last character B, bit 0", strings.Repeat("A", 42) + "B", zeroKey},
		{"all A with last character C, bit 1", strings.Repeat("A", 42) + "C", zeroKey},
		{"all A with last character D, bits 0 and 1", strings.Repeat("A", 42) + "D", zeroKey},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			lenient, err := base64.RawURLEncoding.DecodeString(tc.psk)
			if err != nil || !bytes.Equal(lenient, tc.key) {
				t.Fatalf("lenient decode = %x, %v; the test value must read the key %x", lenient, err, tc.key)
			}
			if _, err := buildRaywireClient(raywirePSKClient(tc.psk)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("client error = %v, want containing %q", err, want)
			}
			if _, err := buildRaywireServer(raywirePSKServer(tc.psk)); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("server error = %v, want containing %q", err, want)
			}
		})
	}
}

// TestRaywirePSKAccepted checks that a canonical psk from the generation command is
// accepted on both sides and decodes to its 32 bytes.
func TestRaywirePSKAccepted(t *testing.T) {
	want, err := base64.RawURLEncoding.DecodeString(raywirePSKSample)
	if err != nil || len(want) != 32 {
		t.Fatalf("sample does not decode to 32 bytes: %v", err)
	}
	client, err := buildRaywireClient(raywirePSKClient(raywirePSKSample))
	if err != nil {
		t.Fatalf("client: unexpected error: %v", err)
	}
	if got := client.(*raywire.ClientConfig).Psk; !bytes.Equal(got, want) {
		t.Fatalf("client psk = %x, want %x", got, want)
	}
	server, err := buildRaywireServer(raywirePSKServer(raywirePSKSample))
	if err != nil {
		t.Fatalf("server: unexpected error: %v", err)
	}
	if got := server.(*raywire.ServerConfig).Psk; !bytes.Equal(got, want) {
		t.Fatalf("server psk = %x, want %x", got, want)
	}
}

// TestRaywirePSKCheckOrder pins where the psk check sits in Build: after the private
// key or the server public key, and before padding.
func TestRaywirePSKCheckOrder(t *testing.T) {
	tests := []struct {
		name    string
		build   func(string) (proto.Message, error)
		input   string
		wantErr string
	}{
		{
			name:  "server private key is checked before psk",
			build: buildRaywireServer,
			input: `{"privateKey": "%%%", "clients": [{"publicKey": "` + raywireTestKey(0x02) + `"}],
				"fallback": "127.0.0.1:8443", "psk": "AAAA"}`,
			wantErr: `"privateKey" is not valid unpadded base64url`,
		},
		{
			name:  "server psk is checked before padding",
			build: buildRaywireServer,
			input: `{"privateKey": "` + raywireTestKey(0x01) + `", "clients": [{"publicKey": "` + raywireTestKey(0x02) + `"}],
				"fallback": "127.0.0.1:8443", "psk": "AAAA", "padding": {"handshake": 513}}`,
			wantErr: `"psk" must decode to 32 bytes, got 3`,
		},
		{
			name:  "client server public key is checked before psk",
			build: buildRaywireClient,
			input: `{"address": "example.com", "port": 443, "privateKey": "` + raywireTestKey(0x01) + `",
				"serverPublicKey": "%%%", "psk": "AAAA"}`,
			wantErr: `"serverPublicKey" is not valid unpadded base64url`,
		},
		{
			name:  "client psk is checked before padding",
			build: buildRaywireClient,
			input: `{"address": "example.com", "port": 443, "privateKey": "` + raywireTestKey(0x01) + `",
				"serverPublicKey": "` + raywireTestKey(0x02) + `", "psk": "AAAA", "padding": {"handshake": 513}}`,
			wantErr: `"psk" must decode to 32 bytes, got 3`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.build(tc.input)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestRaywirePSKProtoRoundTrip checks that psk is field 6 of both messages, and that
// it survives a marshal and unmarshal.
func TestRaywirePSKProtoRoundTrip(t *testing.T) {
	psk := raywireTestBytes(0x03)
	field := protowire.AppendBytes(protowire.AppendTag(nil, 6, protowire.BytesType), psk)
	client, err := buildRaywireClient(raywirePSKClient(raywireTestPSK))
	if err != nil {
		t.Fatal(err)
	}
	server, err := buildRaywireServer(raywirePSKServer(raywireTestPSK))
	if err != nil {
		t.Fatal(err)
	}
	for _, msg := range []proto.Message{client, server} {
		wire, err := proto.Marshal(msg)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(wire, field) {
			t.Fatalf("%T: wire %x has no psk at field 6", msg, wire)
		}
		back := msg.ProtoReflect().New().Interface()
		if err := proto.Unmarshal(wire, back); err != nil {
			t.Fatal(err)
		}
		if !proto.Equal(back, msg) {
			t.Fatalf("%T: round trip gave %v, want %v", msg, back, msg)
		}
	}
}

// raywirePreviousServer is a valid server config as raw JSON text. The three values
// are sent as they are, so an empty string is an empty JSON string.
func raywirePreviousServer(psk, previousPsk, previousPskUntil string) string {
	return `{
		"privateKey": "` + raywireTestKey(0x01) + `",
		"clients": [{"publicKey": "` + raywireTestKey(0x02) + `"}],
		"fallback": "127.0.0.1:8443",
		"psk": "` + psk + `",
		"previousPsk": "` + previousPsk + `",
		"previousPskUntil": "` + previousPskUntil + `"
	}`
}

// raywireFieldNumbers returns the field numbers of a wire message, in order.
func raywireFieldNumbers(t *testing.T, wire []byte) []protowire.Number {
	t.Helper()
	var out []protowire.Number
	for len(wire) > 0 {
		num, typ, n := protowire.ConsumeTag(wire)
		if n < 0 {
			t.Fatalf("bad tag in %x: %v", wire, protowire.ParseError(n))
		}
		wire = wire[n:]
		m := protowire.ConsumeFieldValue(num, typ, wire)
		if m < 0 {
			t.Fatalf("bad field %d in %x: %v", num, wire, protowire.ParseError(m))
		}
		out = append(out, num)
		wire = wire[m:]
	}
	return out
}

// TestRaywirePreviousPSK checks each branch of previousPsk and previousPskUntil in
// the order of the documentation. A success gives the decoded key and the expiry in
// Unix seconds. An error gives the exact message, and the message holds no key.
func TestRaywirePreviousPSK(t *testing.T) {
	now := time.Now()
	unixOf := func(s string) int64 {
		ts, err := time.Parse(time.RFC3339, s)
		if err != nil {
			t.Fatalf("test value %q: %v", s, err)
		}
		return ts.Unix()
	}
	prev := raywireTestKey(0x04)
	future := now.Add(48 * time.Hour).UTC().Format(time.RFC3339)
	tooFar := now.Add(14*24*time.Hour + time.Hour).UTC().Format(time.RFC3339)
	noZone := now.Add(48 * time.Hour).UTC().Format("2006-01-02T15:04:05")
	const notBase64 = `"previousPsk" is not valid unpadded base64url`
	const noExpiry = `"previousPskUntil" must be an RFC 3339 time with a zone when "previousPsk" is set`
	tests := []struct {
		name      string
		input     string
		wantErr   string
		wantPrev  []byte
		wantUntil int64
	}{
		{name: "both empty is unset", input: raywirePreviousServer(raywireTestPSK, "", "")},
		{name: "fields absent is unset", input: raywirePSKServer(raywireTestPSK)},
		{
			name:      "valid with a future expiry",
			input:     raywirePreviousServer(raywireTestPSK, prev, future),
			wantPrev:  raywireTestBytes(0x04),
			wantUntil: unixOf(future),
		},
		{
			name:      "expiry with a zone offset",
			input:     raywirePreviousServer(raywireTestPSK, prev, now.Add(48*time.Hour).In(time.FixedZone("plus one", 3600)).Format(time.RFC3339)),
			wantPrev:  raywireTestBytes(0x04),
			wantUntil: now.Add(48 * time.Hour).Unix(),
		},
		{
			name:      "expiry in the past is accepted",
			input:     raywirePreviousServer(raywireTestPSK, prev, now.Add(-time.Hour).UTC().Format(time.RFC3339)),
			wantPrev:  raywireTestBytes(0x04),
			wantUntil: now.Add(-time.Hour).Truncate(time.Second).Unix(),
		},
		{name: "expiry without previousPsk", input: raywirePreviousServer(raywireTestPSK, "", future), wantErr: `"previousPskUntil" is set without "previousPsk"`},
		{name: "previousPsk without expiry", input: raywirePreviousServer(raywireTestPSK, prev, ""), wantErr: noExpiry},
		{name: "expiry without a zone", input: raywirePreviousServer(raywireTestPSK, prev, noZone), wantErr: noExpiry},
		{name: "expiry that is not a time", input: raywirePreviousServer(raywireTestPSK, prev, "tomorrow"), wantErr: noExpiry},
		{name: "expiry more than 14 days ahead", input: raywirePreviousServer(raywireTestPSK, prev, tooFar), wantErr: `"previousPskUntil" is more than 14 days ahead`},
		{name: "expiry at the Unix epoch", input: raywirePreviousServer(raywireTestPSK, prev, "1970-01-01T00:00:00Z"), wantErr: `"previousPskUntil" must not be the Unix epoch`},
		{name: "previousPsk equal to psk", input: raywirePreviousServer(raywireTestPSK, raywireTestPSK, future), wantErr: `"previousPsk" must differ from "psk"`},
		{name: "equal to psk is checked before the expiry", input: raywirePreviousServer(raywireTestPSK, raywireTestPSK, ""), wantErr: `"previousPsk" must differ from "psk"`},
		{name: "character outside the alphabet", input: raywirePreviousServer(raywireTestPSK, "%%%", future), wantErr: notBase64},
		{name: "padded to 44 characters", input: raywirePreviousServer(raywireTestPSK, prev+"=", future), wantErr: notBase64},
		{name: "too short", input: raywirePreviousServer(raywireTestPSK, prev[:40], future), wantErr: `"previousPsk" must decode to 32 bytes, got 30`},
		{name: "not canonical", input: raywirePreviousServer(raywireTestPSK, raywirePSKSample[:42]+"l", future), wantErr: `"previousPsk" is not in canonical base64url form`},
		{name: "all zero", input: raywirePreviousServer(raywireTestPSK, strings.Repeat("A", 43), future), wantErr: `"previousPsk" is an invalid all-zero key`},
		{name: "invalid psk is reported first", input: raywirePreviousServer("AAAA", prev, future), wantErr: `"psk" must decode to 32 bytes, got 3`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg, err := buildRaywireServer(tc.input)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want containing %q", err, tc.wantErr)
				}
				for _, secret := range []string{prev, raywireTestPSK, raywirePSKSample} {
					if strings.Contains(err.Error(), secret) {
						t.Fatalf("error %q echoes a key", err)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			cfg := msg.(*raywire.ServerConfig)
			if !bytes.Equal(cfg.PreviousPsk, tc.wantPrev) {
				t.Fatalf("previous psk = %x, want %x", cfg.PreviousPsk, tc.wantPrev)
			}
			if cfg.PreviousPskUntil != tc.wantUntil {
				t.Fatalf("previous psk until = %d, want %d", cfg.PreviousPskUntil, tc.wantUntil)
			}
		})
	}
}

// TestRaywirePreviousPSKProtoRoundTrip checks that previousPsk is field 7 and its
// expiry is field 8 of ServerConfig, and that both survive a marshal and unmarshal.
// An unset pair adds neither field to the wire, so a config without them encodes as
// it did before.
func TestRaywirePreviousPSKProtoRoundTrip(t *testing.T) {
	until := time.Now().Add(48 * time.Hour).Unix()
	set, err := buildRaywireServer(raywirePreviousServer(raywireTestPSK, raywireTestKey(0x04), time.Unix(until, 0).UTC().Format(time.RFC3339)))
	if err != nil {
		t.Fatal(err)
	}
	unset, err := buildRaywireServer(raywirePSKServer(raywireTestPSK))
	if err != nil {
		t.Fatal(err)
	}
	wire, err := proto.Marshal(set)
	if err != nil {
		t.Fatal(err)
	}
	fields := raywireFieldNumbers(t, wire)
	if !slices.Contains(fields, 7) || !slices.Contains(fields, 8) {
		t.Fatalf("fields %v, want 7 and 8 for previous_psk and previous_psk_until", fields)
	}
	back := new(raywire.ServerConfig)
	if err := proto.Unmarshal(wire, back); err != nil {
		t.Fatal(err)
	}
	if !proto.Equal(back, set) || back.PreviousPskUntil != until {
		t.Fatalf("round trip gave %v, want %v", back, set)
	}
	wire, err = proto.Marshal(unset)
	if err != nil {
		t.Fatal(err)
	}
	if fields := raywireFieldNumbers(t, wire); slices.Contains(fields, 7) || slices.Contains(fields, 8) {
		t.Fatalf("unset config has fields %v, want none of 7 and 8", fields)
	}
}
