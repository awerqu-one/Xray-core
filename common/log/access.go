package log

import (
	"context"
	"strings"

	"github.com/xtls/xray-core/common/serial"
)

type logKey int

const (
	accessMessageKey logKey = iota
)

type AccessStatus string

const (
	AccessAccepted = AccessStatus("accepted")
	AccessRejected = AccessStatus("rejected")
)

type AccessMessage struct {
	From   interface{}
	To     interface{}
	Status AccessStatus
	Reason interface{}
	Email  string
	Detour string
}

func (m *AccessMessage) String() string {
	builder := strings.Builder{}
	builder.WriteString("from")
	builder.WriteByte(' ')
	builder.WriteString(sanitizeLogField(serial.ToString(m.From)))
	builder.WriteByte(' ')
	builder.WriteString(sanitizeLogField(string(m.Status)))
	builder.WriteByte(' ')
	builder.WriteString(sanitizeLogField(serial.ToString(m.To)))

	if len(m.Detour) > 0 {
		builder.WriteString(" [")
		builder.WriteString(sanitizeLogField(m.Detour))
		builder.WriteByte(']')
	}

	if reason := sanitizeLogField(serial.ToString(m.Reason)); len(reason) > 0 {
		builder.WriteString(" ")
		builder.WriteString(reason)
	}

	if len(m.Email) > 0 {
		builder.WriteString(" email: ")
		builder.WriteString(sanitizeLogField(m.Email))
	}

	return builder.String()
}

// sanitizeLogField replaces ASCII controls, including CR, LF, and DEL.
// One access event stays one line. Text with no controls is returned unchanged,
// so the spaces between fields of a clean record stay as they are.
func sanitizeLogField(s string) string {
	if !hasASCIIControl(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < ' ' || c == 0x7F {
			b.WriteByte('?')
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

func hasASCIIControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < ' ' || s[i] == 0x7F {
			return true
		}
	}
	return false
}

func ContextWithAccessMessage(ctx context.Context, accessMessage *AccessMessage) context.Context {
	return context.WithValue(ctx, accessMessageKey, accessMessage)
}

func AccessMessageFromContext(ctx context.Context) *AccessMessage {
	if accessMessage, ok := ctx.Value(accessMessageKey).(*AccessMessage); ok {
		return accessMessage
	}
	return nil
}
