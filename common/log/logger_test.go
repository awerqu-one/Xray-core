package log_test

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	. "github.com/xtls/xray-core/common/log"
	"github.com/xtls/xray-core/common/net"
)

func TestFileLogger(t *testing.T) {
	f, err := os.CreateTemp("", "vtest")
	common.Must(err)
	path := f.Name()
	common.Must(f.Close())
	defer os.Remove(path)

	creator, err := CreateFileLogWriter(path)
	common.Must(err)

	handler := NewLogger(creator)
	handler.Handle(&GeneralMessage{Content: "Test Log"})
	time.Sleep(2 * time.Second)

	common.Must(common.Close(handler))

	f, err = os.Open(path)
	common.Must(err)
	defer f.Close()

	b, err := buf.ReadAllToBytes(f)
	common.Must(err)
	if !strings.Contains(string(b), "Test Log") {
		t.Fatal("Expect log text contains 'Test Log', but actually: ", string(b))
	}
}

func TestAccessMessageHostNewlineIsOneFileLine(t *testing.T) {
	f, err := os.CreateTemp("", "access-newline")
	common.Must(err)
	path := f.Name()
	common.Must(f.Close())
	defer os.Remove(path)

	creator, err := CreateFileLogWriter(path)
	common.Must(err)
	handler := NewLogger(creator)
	defer common.Close(handler)

	handler.Handle(&AccessMessage{
		From:   "203.0.113.8:40000",
		To:     net.TCPDestination(net.DomainAddress("a.com\nforged line\rx"), 443),
		Status: AccessAccepted,
		Reason: "because\n",
		Email:  "user\nname@example.com",
		Detour: "out\nbound",
	})

	deadline := time.Now().Add(5 * time.Second)
	var body []byte
	for {
		body, err = os.ReadFile(path)
		common.Must(err)
		if len(body) > 0 || time.Now().After(deadline) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(body) == 0 {
		t.Fatal("access log was not written")
	}
	text := string(body)
	if strings.Count(text, "\n") != 1 {
		t.Fatalf("newline in the host produced %d log lines: %q", strings.Count(text, "\n"), text)
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c != '\n' && (c < ' ' || c == 0x7F) {
			t.Fatalf("access log contains an ASCII control: %q", text)
		}
	}
	if !strings.Contains(text, "a.com") || !strings.Contains(text, "forged line") || !strings.Contains(text, "x:443") {
		t.Fatalf("host was not kept on the one line: %q", text)
	}
}
