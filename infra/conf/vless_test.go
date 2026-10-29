package conf_test

import (
	"strings"
	"testing"

	xerrors "github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	"github.com/xtls/xray-core/common/serial"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/proxy/vless"
	"github.com/xtls/xray-core/proxy/vless/inbound"
	"github.com/xtls/xray-core/proxy/vless/outbound"
)

func TestVLessOutbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessOutboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"vnext": [{
					"address": "example.com",
					"port": 443,
					"users": [
						{
							"id": "27848739-7e62-4138-9fd3-098a63964b6b",
							"flow": "xtls-rprx-vision-udp443",
							"encryption": "none",
							"level": 0
						}
					]
				}]
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
		{
			Input: `{
				"address": "example.com",
				"port": 443,
				"id": "27848739-7e62-4138-9fd3-098a63964b6b",
				"flow": "xtls-rprx-vision-udp443",
				"encryption": "none",
				"level": 0
			}`,
			Parser: loadJSON(creator),
			Output: &outbound.Config{
				Vnext: &protocol.ServerEndpoint{
					Address: &net.IPOrDomain{
						Address: &net.IPOrDomain_Domain{
							Domain: "example.com",
						},
					},
					Port: 443,
					User: &protocol.User{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow:       "xtls-rprx-vision-udp443",
							Encryption: "none",
						}),
						Level: 0,
					},
				},
			},
		},
	})
}

func TestVLessInbound(t *testing.T) {
	creator := func() Buildable {
		return new(VLessInboundConfig)
	}

	runMultiTestCase(t, []TestCase{
		{
			Input: `{
				"clients": [
					{
						"id": "27848739-7e62-4138-9fd3-098a63964b6b",
						"flow": "xtls-rprx-vision",
						"level": 0,
						"email": "love@example.com"
					}
				],
				"decryption": "none",
				"fallbacks": [
					{
						"dest": 80
					},
					{
						"alpn": "h2",
						"dest": "@/dev/shm/domain.socket",
						"xver": 2
					},
					{
						"path": "/innerws",
						"dest": "serve-ws-none"
					}
				]
			}`,
			Parser: loadJSON(creator),
			Output: &inbound.Config{
				Users: []*protocol.User{
					{
						Account: serial.ToTypedMessage(&vless.Account{
							Id:   "27848739-7e62-4138-9fd3-098a63964b6b",
							Flow: "xtls-rprx-vision",
						}),
						Level: 0,
						Email: "love@example.com",
					},
				},
				Decryption: "none",
				Fallbacks: []*inbound.Fallback{
					{
						Alpn: "",
						Path: "",
						Type: "tcp",
						Dest: "localhost:80",
						Xver: 0,
					},
					{
						Alpn: "h2",
						Path: "",
						Type: "unix",
						Dest: "@/dev/shm/domain.socket",
						Xver: 2,
					},
					{
						Alpn: "",
						Path: "/innerws",
						Type: "serve",
						Dest: "serve-ws-none",
						Xver: 0,
					},
				},
			},
		},
	})
}

func TestUnsupportedVLESSDecryptionOmitsValue(t *testing.T) {
	const token = "SECRETTOKEN"
	cases := []string{
		token,
		"mlkem768x25519plus.nativ.600s." + token,
		"mlkem768x25519plus.native.600s." + strings.Repeat(token, 2),
	}
	for _, decryption := range cases {
		_, err := (&VLessInboundConfig{Decryption: decryption}).Build()
		if err == nil {
			t.Fatal("unsupported decryption was accepted")
		}
		if _, ok := err.(*xerrors.Error); !ok {
			t.Fatalf("unsupported decryption error type changed: %T", err)
		}
		message := err.Error()
		if !strings.Contains(message, `unsupported "decryption"`) ||
			strings.Contains(message, token) {
			t.Fatal("unsupported decryption error should name the failure and omit the value")
		}
	}
}

func TestUnsupportedVLESSEncryptionOmitsValue(t *testing.T) {
	const token = "SECRETTOKEN"
	address := new(Address)
	if err := address.UnmarshalJSON([]byte(`"example.com"`)); err != nil {
		t.Fatal(err)
	}
	cases := []string{
		token,
		"mlkem768x25519plus.native.600s." + token,
	}
	for _, encryption := range cases {
		_, err := (&VLessOutboundConfig{
			Address:    address,
			Port:       443,
			Id:         "27848739-7e62-4138-9fd3-098a63964b6b",
			Encryption: encryption,
		}).Build()
		if err == nil {
			t.Fatal("unsupported encryption was accepted")
		}
		if _, ok := err.(*xerrors.Error); !ok {
			t.Fatalf("unsupported encryption error type changed: %T", err)
		}
		message := err.Error()
		if !strings.Contains(message, `unsupported "encryption"`) ||
			strings.Contains(message, token) {
			t.Fatal("unsupported encryption error should name the failure and omit the value")
		}
	}
}
