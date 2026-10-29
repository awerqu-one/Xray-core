package raywire

import (
	"bytes"
	"testing"
)

func TestDecodeHeaderRejectsControlInAddress(t *testing.T) {
	rejected := []string{
		"a.com\nforged\nx",
		"a.com\r\nx",
		"a.com\x00x",
		"example.com\t",
		"ex\x1bample.com",
		"ex\x7fample.com",
		"\nexample.com",
		"example.com\n",
	}
	for _, addr := range rejected {
		_, err := decodeHeader(bytes.NewReader(headerWire(networkTCP, 443, addr)))
		if err == nil {
			t.Fatalf("accepted header address %q", addr)
		}
		if _, err := parseDatagramAddress(addr); err == nil {
			t.Fatalf("accepted datagram address %q", addr)
		}
	}

	accepted := []struct {
		addr    string
		network byte
		port    uint16
	}{
		{"example.com", networkTCP, 443},
		{"example.com.", networkTCP, 80},
		{"sub.example.com", networkTCP, 443},
		{"my-host.example", networkUDP, 53},
		{"_sip._tcp.example.com", networkTCP, 5060},
		{"2001:db8::1", networkTCP, 443},
		{"[2001:db8::1]", networkUDP, 853},
		{"192.0.2.10", networkTCP, 80},
		{"::1", networkTCP, 443},
		{"::ffff:192.0.2.1", networkUDP, 53},
	}
	for _, tc := range accepted {
		dest, err := decodeHeader(bytes.NewReader(headerWire(tc.network, tc.port, tc.addr)))
		if err != nil {
			t.Fatalf("rejected %q: %v", tc.addr, err)
		}
		if uint16(dest.Port) != tc.port {
			t.Fatalf("%q port = %d, want %d", tc.addr, dest.Port, tc.port)
		}
		if dest.Address == nil || dest.Address.String() == "" {
			t.Fatalf("%q decoded to an empty address", tc.addr)
		}
		if hasASCIIControl(dest.Address.String()) {
			t.Fatalf("%q kept a control: %q", tc.addr, dest.Address.String())
		}
		got, err := parseDatagramAddress(tc.addr)
		if err != nil {
			t.Fatalf("datagram rejected %q: %v", tc.addr, err)
		}
		if got.String() != dest.Address.String() {
			t.Fatalf("datagram address %q = %q, header stored %q", tc.addr, got.String(), dest.Address.String())
		}
	}
}
