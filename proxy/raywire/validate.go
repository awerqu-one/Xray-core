package raywire

import (
	"crypto/subtle"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// MaxPreviousPskOverlap is the longest that a previous PSK may be accepted after the
// load time (owner decision O-4). A planned rotation needs days, and a longer overlap
// keeps an old key usable for longer than the rotation needs.
const MaxPreviousPskOverlap = 14 * 24 * time.Hour

// maxEmailLen is the longest client email in bytes, not runes.
const maxEmailLen = 128

// ParseFallback checks the decoy address and returns its destination. The address
// is host:port, with a port from 1 to 65535 and a host that is named. A wildcard
// address (0.0.0.0, ::) means this machine, so the relay would dial this inbound
// and loop back into it. A host with a zone, or one that only looks like a number
// without being a canonical IP, is refused for the same reason: the system
// resolver reads it as an address, and it may read it as a wildcard. Infra and the
// typed config both call this function.
func ParseFallback(addr string) (net.Destination, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return net.Destination{}, errors.New(`raywire: "fallback" must be host:port`).Base(err)
	}
	if host == "" {
		return net.Destination{}, errors.New(`raywire: "fallback" must name a host`)
	}
	// ParseAddress trims spaces from a host before it reads the host, so " 0.0.0.0"
	// would be dialed as the wildcard while these checks see the padded text. The
	// checks below must see the text that is dialed, so a padded host is refused.
	if strings.TrimSpace(host) != host {
		return net.Destination{}, errors.New(`raywire: "fallback" host must not have spaces`)
	}
	// A zone such as %lo is not part of the IP grammar that ParseIP reads, so
	// the wildcard check below would not see a zoned unspecified address.
	if strings.Contains(host, "%") {
		return net.Destination{}, errors.New(`raywire: "fallback" host must not have a zone`)
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return net.Destination{}, errors.New(`raywire: "fallback" must not be a wildcard address`)
		}
	} else if looksNumeric(host) {
		// Forms such as "0", "0.0" and "0x0" are zero addresses to inet_aton, but
		// ParseIP rejects them, so only a canonical IP or a domain is accepted.
		return net.Destination{}, errors.New(`raywire: "fallback" host must be a canonical IP address or a domain name`)
	}
	p, err := net.PortFromString(port)
	if err != nil || p == 0 {
		return net.Destination{}, errors.New(`raywire: "fallback" port must be between 1 and 65535`)
	}
	return net.TCPDestination(net.ParseAddress(host), p), nil
}

// looksNumeric reports whether host is written in the number forms that inet_aton
// reads: it starts with a digit and holds only digits, dots, x and hex letters.
// A host that starts with a letter is a name, so "dead" is not numeric. The
// check is only used on hosts that net.ParseIP has already rejected.
func looksNumeric(host string) bool {
	if host == "" || host[0] < '0' || host[0] > '9' {
		return false
	}
	for i := range len(host) {
		c := host[i]
		switch {
		case '0' <= c && c <= '9', 'a' <= c && c <= 'f', 'A' <= c && c <= 'F':
		case c == '.', c == 'x', c == 'X':
		default:
			return false
		}
	}
	return true
}

// ValidateAccounts checks the client list of a server. Each key is 32 bytes, is
// not all zero and is unique. Each non-empty email is unique and passes checkEmail.
// Errors name an entry by its index, "clients[i]", so both config paths report
// the same text.
func ValidateAccounts(accounts []*Account) error {
	// Two entries with one key would make the email ambiguous, so keys and emails
	// must each be unique. Emails are compared exactly, without case folding.
	keyIndex := make(map[string]int, len(accounts))
	emailIndex := make(map[string]int, len(accounts))
	for i, account := range accounts {
		field := "clients[" + strconv.Itoa(i) + "]"
		if account == nil {
			return errors.New("raywire: client ", i, " is nil")
		}
		if len(account.PublicKey) != 32 {
			return errors.New("raywire: client ", i, " public key must be 32 bytes")
		}
		if slices.Equal(account.PublicKey, make([]byte, 32)) {
			return errors.New(`raywire: "`, field, `.publicKey" is an invalid all-zero key`)
		}
		if j, ok := keyIndex[string(account.PublicKey)]; ok {
			return errors.New(`raywire: "`, field, `.publicKey" duplicates "clients[`, j, `].publicKey"`)
		}
		keyIndex[string(account.PublicKey)] = i

		if account.Email == "" {
			continue
		}
		if err := checkEmail(account.Email, field+".email"); err != nil {
			return err
		}
		if j, ok := emailIndex[account.Email]; ok {
			return errors.New(`raywire: "`, field, `.email" duplicates "clients[`, j, `].email"`)
		}
		emailIndex[account.Email] = i
	}
	return nil
}

// checkEmail accepts an email of 1 to 128 bytes that is valid UTF-8, has no
// control or invisible characters, and has no leading or trailing spaces. The
// stats key is built from the email, so a stray byte would split one user into
// two. The key is also split at ">>>", so the email may not contain it, or end
// in ">" (which would join the separator into ">>>>" and split one character early).
func checkEmail(email, field string) error {
	if len(email) > maxEmailLen {
		return errors.New(`raywire: "`, field, `" must be at most `, maxEmailLen, ` bytes, got `, len(email))
	}
	if !utf8.ValidString(email) {
		return errors.New(`raywire: "`, field, `" must be valid UTF-8`)
	}
	for _, r := range email {
		if unicode.IsControl(r) {
			return errors.New(`raywire: "`, field, `" must not contain control characters`)
		}
		// Format characters such as U+200B and U+202E are invisible, and separators
		// and spaces other than ASCII space look like one. Two emails that differ
		// only in such a rune look the same in the stats and logs.
		if r != ' ' && unicode.In(r, unicode.Cf, unicode.Zl, unicode.Zp, unicode.Zs) {
			return errors.New(`raywire: "`, field, `" must not contain invisible or non-ASCII space characters`)
		}
	}
	if strings.TrimSpace(email) != email {
		return errors.New(`raywire: "`, field, `" must not have leading or trailing spaces`)
	}
	if strings.Contains(email, ">>>") {
		return errors.New(`raywire: "`, field, `" must not contain ">>>"`)
	}
	if strings.HasSuffix(email, ">") {
		return errors.New(`raywire: "`, field, `" must not end with ">"`)
	}
	return nil
}

// PreviousPskNames spell the config fields in the messages of ValidatePreviousPsk. Each
// caller passes the names as its messages show them: the server config uses bare names,
// and the typed config uses quoted names.
type PreviousPskNames struct {
	PSK         string // the psk field
	PreviousPSK string // the previousPsk field
	Until       string // the previousPskUntil field
}

// ValidatePreviousPsk is the one check of the optional previous PSK and its expiry. It
// serves the server (newHeadKeys) and the typed config (infra/conf). The feature is off
// when previousPsk is empty and until is the zero time, and then nothing is checked.
// Otherwise until must be set, previousPsk must be a 32-byte key that is not all zero and
// differs from psk, and until must be at most MaxPreviousPskOverlap after now. A psk that
// is not a valid key is refused when previousPsk is set. An expiry in the past is valid:
// the server then ignores previousPsk. The messages name no key.
func ValidatePreviousPsk(psk, previousPsk []byte, until, now time.Time, names PreviousPskNames) error {
	if len(previousPsk) == 0 {
		if !until.IsZero() {
			return errors.New("raywire: " + names.Until + " is set without " + names.PreviousPSK)
		}
		return nil
	}
	if len(previousPsk) != 32 {
		return errors.New("raywire: " + names.PreviousPSK + " must be 32 bytes")
	}
	if subtle.ConstantTimeCompare(previousPsk, make([]byte, 32)) == 1 {
		return errors.New("raywire: " + names.PreviousPSK + " must not be all zero")
	}
	// The comparison with psk needs a valid psk, so a previousPsk is never checked
	// against a psk that the server would refuse.
	if len(psk) != 32 || subtle.ConstantTimeCompare(psk, make([]byte, 32)) == 1 {
		return errors.New("raywire: " + names.PreviousPSK + " requires a valid " + names.PSK)
	}
	if subtle.ConstantTimeCompare(previousPsk, psk) == 1 {
		return errors.New("raywire: " + names.PreviousPSK + " must differ from " + names.PSK)
	}
	if until.IsZero() {
		return errors.New("raywire: " + names.Until + " must be set with " + names.PreviousPSK)
	}
	if until.After(now.Add(MaxPreviousPskOverlap)) {
		return errors.New("raywire: " + names.Until + " is more than 14 days ahead")
	}
	return nil
}
