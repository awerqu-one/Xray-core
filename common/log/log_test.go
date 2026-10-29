package log_test

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

type testLogger struct {
	value string
}

func (l *testLogger) Handle(msg log.Message) {
	l.value = msg.String()
}

func TestLogRecord(t *testing.T) {
	var logger testLogger
	log.RegisterHandler(&logger)

	ip := "8.8.8.8"
	log.Record(&log.GeneralMessage{
		Severity: log.Severity_Error,
		Content:  net.ParseAddress(ip),
	})

	if diff := cmp.Diff("[Error] "+ip, logger.value); diff != "" {
		t.Error(diff)
	}
}

func TestAccessMessageCleanHostUnchanged(t *testing.T) {
	msg := &log.AccessMessage{
		From:   "127.0.0.1:1234",
		To:     net.TCPDestination(net.ParseAddress("example.com"), 443),
		Status: log.AccessAccepted,
		Detour: "direct",
		Email:  "user@example.com",
	}
	const want = "from 127.0.0.1:1234 accepted tcp:example.com:443 [direct] email: user@example.com"
	if got := msg.String(); got != want {
		t.Fatalf("clean access line changed: got %q want %q", got, want)
	}

	v6 := &log.AccessMessage{
		From:   "127.0.0.1:1234",
		To:     net.TCPDestination(net.ParseAddress("2001:db8::1"), 443),
		Status: log.AccessAccepted,
	}
	const want6 = "from 127.0.0.1:1234 accepted tcp:[2001:db8::1]:443"
	if got := v6.String(); got != want6 {
		t.Fatalf("IPv6 access line changed: got %q want %q", got, want6)
	}
}

func TestAccessMessageNewlineStaysOneLine(t *testing.T) {
	msg := &log.AccessMessage{
		From:   "203.0.113.8:40000",
		To:     net.TCPDestination(net.DomainAddress("a.com\nforged line\rx"), 443),
		Status: log.AccessAccepted,
		Reason: "because\n",
		Email:  "user\nname@example.com",
		Detour: "out\x00bound",
	}
	line := msg.String()
	if strings.ContainsAny(line, "\r\n") || strings.IndexByte(line, 0) >= 0 || strings.IndexByte(line, 0x7F) >= 0 {
		t.Fatalf("access line contains an ASCII control: %q", line)
	}
	if strings.Count(line, "\n") != 0 {
		t.Fatalf("host newline produced more than one line: %q", line)
	}
	if !strings.Contains(line, "a.com") || !strings.Contains(line, "forged line") || !strings.Contains(line, "x:443") {
		t.Fatalf("host was dropped or split: %q", line)
	}
	if !strings.Contains(line, "from 203.0.113.8:40000 accepted ") {
		t.Fatalf("field separator changed: %q", line)
	}
}
