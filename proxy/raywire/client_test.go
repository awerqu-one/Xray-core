package raywire

import (
	"strings"
	"testing"
)

// clientConfig returns a configuration that NewClient accepts, with no padding
// section. A test changes one field of it.
func clientConfig(t *testing.T) *ClientConfig {
	t.Helper()
	return &ClientConfig{
		Address:         "203.0.113.10",
		Port:            443,
		PrivateKey:      newKey(t).Private,
		ServerPublicKey: newKey(t).Public,
		Psk:             testPSK,
	}
}

// TestNewClientValidation checks each configuration rule that NewClient applies.
// The padding limits are inclusive.
func TestNewClientValidation(t *testing.T) {
	ctx := coreContext(t)
	cases := []struct {
		name    string
		edit    func(*ClientConfig)
		wantErr string // empty when NewClient must accept the configuration
	}{
		{"padding handshake above the limit", func(c *ClientConfig) {
			c.Padding = &Padding{Handshake: 513}
		}, "padding handshake must be between 0 and 512"},
		{"padding frame above the limit", func(c *ClientConfig) {
			c.Padding = &Padding{Frame: 1025}
		}, "padding frame must be between 0 and 1024"},
		{"padding bucket below the minimum", func(c *ClientConfig) {
			c.Padding = &Padding{Bucket: 15}
		}, "padding bucket must be 0 or between 16 and 4096"},
		{"padding bucket above the maximum", func(c *ClientConfig) {
			c.Padding = &Padding{Bucket: 4097}
		}, "padding bucket must be 0 or between 16 and 4096"},
		{"padding at the limits", func(c *ClientConfig) {
			c.Padding = &Padding{Handshake: 512, Frame: 1024, Bucket: 4096}
		}, ""},
		{"empty server address", func(c *ClientConfig) {
			c.Address = ""
		}, "server address is not set"},
		{"port zero", func(c *ClientConfig) {
			c.Port = 0
		}, "invalid server port"},
		{"port too large", func(c *ClientConfig) {
			c.Port = 65536
		}, "invalid server port"},
		{"private key of the wrong length", func(c *ClientConfig) {
			c.PrivateKey = make([]byte, 31)
		}, "private key must be 32 bytes"},
		{"server public key of the wrong length", func(c *ClientConfig) {
			c.ServerPublicKey = make([]byte, 31)
		}, "server public key must be 32 bytes"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			config := clientConfig(t)
			tc.edit(config)
			_, err := NewClient(ctx, config)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("NewClient: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewClient error = %v, want containing %q", err, tc.wantErr)
			}
		})
	}
}

// TestNewClientNilPaddingUsesDefaults checks that a missing padding section
// means the defaults, and that an explicit zero stays off.
func TestNewClientNilPaddingUsesDefaults(t *testing.T) {
	ctx := coreContext(t)

	c, err := NewClient(ctx, clientConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if c.pad != defaultPadPolicy() {
		t.Fatalf("pad = %+v, want the defaults %+v", c.pad, defaultPadPolicy())
	}

	off := clientConfig(t)
	off.Padding = &Padding{}
	c, err = NewClient(ctx, off)
	if err != nil {
		t.Fatal(err)
	}
	if c.pad != (padPolicy{}) {
		t.Fatalf("explicit zero padding gave %+v, want all off", c.pad)
	}
}
