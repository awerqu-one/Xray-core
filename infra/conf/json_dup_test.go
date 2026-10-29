package conf_test

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/core"
	. "github.com/xtls/xray-core/infra/conf"
	"github.com/xtls/xray-core/infra/conf/serial"

	_ "github.com/xtls/xray-core/app/dispatcher"
	_ "github.com/xtls/xray-core/app/proxyman/inbound"
	_ "github.com/xtls/xray-core/app/proxyman/outbound"
	_ "github.com/xtls/xray-core/proxy/freedom"
	_ "github.com/xtls/xray-core/proxy/socks"
)

func TestDupPortJSON(t *testing.T) {
	mustDup := func(t *testing.T, raw, key string) {
		t.Helper()
		want := "duplicate key " + strconv.Quote(key)
		for name, decode := range map[string]func(string) (*Config, error){
			"json":   func(s string) (*Config, error) { return serial.DecodeJSONConfig(strings.NewReader(s)) },
			"strict": func(s string) (*Config, error) { return serial.DecodeJSONConfigStrict(strings.NewReader(s)) },
		} {
			t.Run(name, func(t *testing.T) {
				cfg, err := decode(raw)
				if err == nil || cfg != nil || !strings.Contains(err.Error(), want) {
					t.Fatalf("decode = (%v, %v), want %s", cfg, err, want)
				}
				if name == "json" && !strings.Contains(err.Error(), "line ") {
					t.Fatalf("missing location: %v", err)
				}
			})
		}
	}

	t.Run("two ports", func(t *testing.T) {
		mustDup(t, `{
			"inbounds": [{
				"listen": "127.0.0.1",
				"protocol": "socks",
				"port": 18081,
				"port": 18082
			}]
		}`, "port")
	})

	t.Run("same port twice", func(t *testing.T) {
		mustDup(t, `{"inbounds":[{"protocol":"socks","port":18083,"port":18083}]}`, "port")
	})

	t.Run("string ports", func(t *testing.T) {
		mustDup(t, `{"inbounds":[{"protocol":"socks","port":"18081","port":"18082"}]}`, "port")
	})

	t.Run("comment between ports", func(t *testing.T) {
		raw := `{
			"inbounds": [{
				"protocol": "socks",
				"port": 18081,
				// second listen must not be opened
				"port": 18082
			}]
		}`
		cfg, err := serial.DecodeJSONConfig(strings.NewReader(raw))
		if err == nil || cfg != nil || !strings.Contains(err.Error(), `duplicate key "port"`) {
			t.Fatalf("decode = (%v, %v), want duplicate key error", cfg, err)
		}
	})

	t.Run("escaped port name", func(t *testing.T) {
		mustDup(t, `{"inbounds":[{"protocol":"socks","port":18081,"\u0070ort":18082}]}`, "port")
	})

	t.Run("listen protocol tag", func(t *testing.T) {
		mustDup(t, `{
			"inbounds": [{
				"listen": "127.0.0.1",
				"listen": "127.0.0.2",
				"protocol": "socks",
				"protocol": "dokodemo-door",
				"tag": "first",
				"tag": "second",
				"port": 1
			}]
		}`, "listen")
	})

	t.Run("settings port", func(t *testing.T) {
		mustDup(t, `{
			"inbounds": [{
				"protocol": "dokodemo-door",
				"port": 1,
				"settings": {"address": "127.0.0.1", "port": 9, "port": 19}
			}]
		}`, "port")
	})

	t.Run("unique keys", func(t *testing.T) {
		raw := `{
			"inbounds": [
				{"protocol": "socks", "tag": "range", "port": "1-3"},
				{"protocol": "socks", "tag": "list", "port": "80,443"},
				{"protocol": "socks", "tag": "one", "port": 1080, "listen": "127.0.0.1"}
			]
		}`
		for _, decode := range []func(string) (*Config, error){
			func(s string) (*Config, error) { return serial.DecodeJSONConfig(strings.NewReader(s)) },
			func(s string) (*Config, error) { return serial.DecodeJSONConfigStrict(strings.NewReader(s)) },
		} {
			cfg, err := decode(raw)
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.InboundConfigs) != 3 {
				t.Fatalf("inbounds: %d", len(cfg.InboundConfigs))
			}
			rangePort := cfg.InboundConfigs[0].PortList
			if rangePort == nil || len(rangePort.Range) != 1 || rangePort.Range[0].From != 1 || rangePort.Range[0].To != 3 {
				t.Fatalf("port range: %+v", rangePort)
			}
			listPort := cfg.InboundConfigs[1].PortList
			if listPort == nil || len(listPort.Range) != 2 ||
				listPort.Range[0].From != 80 || listPort.Range[0].To != 80 ||
				listPort.Range[1].From != 443 || listPort.Range[1].To != 443 {
				t.Fatalf("port list: %+v", listPort)
			}
			one := cfg.InboundConfigs[2].PortList
			if one == nil || len(one.Range) != 1 || one.Range[0].From != 1080 || one.Range[0].To != 1080 {
				t.Fatalf("single port: %+v", one)
			}
		}
	})

	t.Run("port array is not a repeated key", func(t *testing.T) {
		cfg, err := serial.DecodeJSONConfig(strings.NewReader(`{"inbounds":[{"protocol":"socks","port":[80,443]}]}`))
		if err != nil {
			if strings.Contains(err.Error(), "duplicate") {
				t.Fatalf("port array rejected as a duplicate key: %v", err)
			}
			return
		}
		pl := cfg.InboundConfigs[0].PortList
		if pl == nil || len(pl.Range) != 2 || pl.Range[0].From != 80 || pl.Range[1].From != 443 {
			t.Fatalf("port array: %+v", pl)
		}
	})

	t.Run("unique config starts", func(t *testing.T) {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}

		raw := `{
			"inbounds": [{
				"listen": "127.0.0.1",
				"port": ` + strconv.Itoa(port) + `,
				"protocol": "socks",
				"tag": "in"
			}],
			"outbounds": [{"protocol": "freedom", "tag": "direct"}]
		}`
		cfg, err := serial.LoadJSONConfig(strings.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		server, err := core.New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		if err := server.Start(); err != nil {
			t.Fatal(err)
		}
		defer server.Close()

		conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), 2*time.Second)
		if err != nil {
			t.Fatal(err)
		}
		conn.Close()
	})
}
