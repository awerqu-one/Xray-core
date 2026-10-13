package conf

import (
	"crypto/subtle"
	"encoding/base64"
	"strconv"
	"time"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/proxy/raywire"
	"google.golang.org/protobuf/proto"
)

// RaywirePadding holds the padding settings. An absent field takes its default.
type RaywirePadding struct {
	Handshake *uint32 `json:"handshake"`
	Frame     *uint32 `json:"frame"`
	Bucket    *uint32 `json:"bucket"`
}

// buildRaywirePadding fills the defaults for absent fields and checks the
// ranges. A nil section means the defaults.
func buildRaywirePadding(p *RaywirePadding) (*raywire.Padding, error) {
	out := &raywire.Padding{Handshake: 255, Frame: 32, Bucket: 0}
	if p == nil {
		return out, nil
	}
	if p.Handshake != nil {
		out.Handshake = *p.Handshake
	}
	if p.Frame != nil {
		out.Frame = *p.Frame
	}
	if p.Bucket != nil {
		out.Bucket = *p.Bucket
	}
	if out.Handshake > 512 {
		return nil, errors.New(`raywire: "padding.handshake" must be at most 512, got `, out.Handshake)
	}
	if out.Frame > 1024 {
		return nil, errors.New(`raywire: "padding.frame" must be at most 1024, got `, out.Frame)
	}
	if out.Bucket != 0 && (out.Bucket < 16 || out.Bucket > 4096) {
		return nil, errors.New(`raywire: "padding.bucket" must be 0 or between 16 and 4096, got `, out.Bucket)
	}
	return out, nil
}

// RaywireClientConfig is the outbound settings of the raywire protocol.
type RaywireClientConfig struct {
	Address         *Address        `json:"address"`
	Port            uint16          `json:"port"`
	PrivateKey      string          `json:"privateKey"`
	ServerPublicKey string          `json:"serverPublicKey"`
	Psk             string          `json:"psk"`
	Padding         *RaywirePadding `json:"padding"`
}

// Build implements Buildable.
func (c *RaywireClientConfig) Build() (proto.Message, error) {
	if c.Address == nil || c.Address.Address == nil {
		return nil, errors.New(`raywire: "address" is not set`)
	}
	if c.Port == 0 {
		return nil, errors.New(`raywire: "port" is not set`)
	}
	privateKey, err := decodeRaywireKey(c.PrivateKey, "privateKey")
	if err != nil {
		return nil, err
	}
	serverPublicKey, err := decodeRaywireKey(c.ServerPublicKey, "serverPublicKey")
	if err != nil {
		return nil, err
	}
	psk, err := decodeRaywirePSK(c.Psk, "psk")
	if err != nil {
		return nil, err
	}
	padding, err := buildRaywirePadding(c.Padding)
	if err != nil {
		return nil, err
	}
	return &raywire.ClientConfig{
		Address:         c.Address.Address.String(),
		Port:            uint32(c.Port),
		PrivateKey:      privateKey,
		ServerPublicKey: serverPublicKey,
		Psk:             psk,
		Padding:         padding,
	}, nil
}

// RaywireAccount is one client public key accepted by the server. The optional
// email names the client in the stats. An empty email means no user, so the
// client has no per-user counter. Per-user stats need "stats": {} and
// policy.levels.0.statsUserUplink and statsUserDownlink set to true.
type RaywireAccount struct {
	PublicKey string `json:"publicKey"`
	Email     string `json:"email"`
}

// RaywireServerConfig is the inbound settings of the raywire protocol. PreviousPsk
// and PreviousPskUntil are optional. They let heads under the old psk pass until the
// expiry, so that clients can move to the new psk. They are server-only.
type RaywireServerConfig struct {
	PrivateKey       string           `json:"privateKey"`
	Psk              string           `json:"psk"`
	PreviousPsk      string           `json:"previousPsk"`
	PreviousPskUntil string           `json:"previousPskUntil"`
	Clients          []RaywireAccount `json:"clients"`
	Padding          *RaywirePadding  `json:"padding"`
	Fallback         string           `json:"fallback"`
	AllowSilentClose bool             `json:"allowSilentClose"`
}

// Build implements Buildable.
func (c *RaywireServerConfig) Build() (proto.Message, error) {
	// A server without clients would start and silently reject every peer.
	if len(c.Clients) == 0 {
		return nil, errors.New(`raywire: "clients" must contain at least one client`)
	}
	privateKey, err := decodeRaywireKey(c.PrivateKey, "privateKey")
	if err != nil {
		return nil, err
	}
	psk, err := decodeRaywirePSK(c.Psk, "psk")
	if err != nil {
		return nil, err
	}
	// The previous PSK is checked after psk, so an invalid psk is reported first and
	// no previous PSK is built from it.
	previousPsk, previousPskUntil, err := buildRaywirePreviousPsk(c.PreviousPsk, c.PreviousPskUntil, psk, time.Now())
	if err != nil {
		return nil, err
	}
	config := &raywire.ServerConfig{
		PrivateKey:       privateKey,
		Psk:              psk,
		PreviousPsk:      previousPsk,
		PreviousPskUntil: previousPskUntil,
		Clients:          make([]*raywire.Account, 0, len(c.Clients)),
	}
	for i, client := range c.Clients {
		publicKey, err := decodeRaywireKey(client.PublicKey, "clients["+strconv.Itoa(i)+"].publicKey")
		if err != nil {
			return nil, err
		}
		config.Clients = append(config.Clients, &raywire.Account{PublicKey: publicKey, Email: client.Email})
	}
	// The shared check covers duplicates and emails, and reports them by index.
	if err := raywire.ValidateAccounts(config.Clients); err != nil {
		return nil, err
	}
	config.Padding, err = buildRaywirePadding(c.Padding)
	if err != nil {
		return nil, err
	}
	if err := checkRaywireFallback(c.Fallback, c.AllowSilentClose); err != nil {
		return nil, err
	}
	config.Fallback = c.Fallback
	config.AllowSilentClose = c.AllowSilentClose
	return config, nil
}

// checkRaywireFallback accepts an empty fallback only with allowSilentClose.
// Otherwise the address must pass raywire.ParseFallback, which the server uses
// too, so both paths refuse the same hosts.
func checkRaywireFallback(fallback string, allowSilentClose bool) error {
	if fallback == "" {
		if !allowSilentClose {
			return errors.New(`raywire: "fallback" is required unless "allowSilentClose" is set`)
		}
		return nil
	}
	_, err := raywire.ParseFallback(fallback)
	return err
}

// decodeRaywireKey decodes an unpadded base64url X25519 key (32 bytes), the
// same encoding that `xray x25519` prints.
func decodeRaywireKey(value, field string) ([]byte, error) {
	if value == "" {
		return nil, errors.New(`raywire: "`, field, `" is not set`)
	}
	key, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New(`raywire: "`, field, `" is not valid unpadded base64url`).Base(err)
	}
	if len(key) != 32 {
		return nil, errors.New(`raywire: "`, field, `" must decode to 32 bytes, got `, len(key))
	}
	// An all-zero public key is a low-order X25519 point; no handshake can complete with it.
	if subtle.ConstantTimeCompare(key, make([]byte, 32)) == 1 {
		return nil, errors.New(`raywire: "`, field, `" is an invalid all-zero key`)
	}
	return key, nil
}

// decodeRaywirePSK checks a raywire/3 pre-shared key and returns its 32 bytes. The
// field is the JSON name ("psk" or "previousPsk") and each message names it. An empty
// previousPsk is unset, and it returns nil with no error. Any other empty value is
// missing. The checks run in this order and the first failure is reported. The
// character check runs first because the lenient decoder skips newlines. The
// canonical check runs after the length check, so it only sees a 32-byte value.
func decodeRaywirePSK(value, field string) ([]byte, error) {
	if value == "" {
		if field == "previousPsk" {
			return nil, nil
		}
		return nil, errors.New(`raywire: "`, field, `" is not set; raywire/3 requires a pre-shared key`)
	}
	for i := 0; i < len(value); i++ {
		if !isRawURLChar(value[i]) {
			return nil, errors.New(`raywire: "`, field, `" is not valid unpadded base64url`)
		}
	}
	psk, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, errors.New(`raywire: "`, field, `" is not valid unpadded base64url`).Base(err)
	}
	if len(psk) != 32 {
		return nil, errors.New(`raywire: "`, field, `" must decode to 32 bytes, got `, len(psk))
	}
	// A 43-character value has two unused bits in its last character. The lenient
	// decoder ignores them, so a non-canonical value would pass for the same key.
	if _, err := base64.RawURLEncoding.Strict().DecodeString(value); err != nil {
		return nil, errors.New(`raywire: "`, field, `" is not in canonical base64url form`).Base(err)
	}
	if subtle.ConstantTimeCompare(psk, make([]byte, 32)) == 1 {
		return nil, errors.New(`raywire: "`, field, `" is an invalid all-zero key`)
	}
	return psk, nil
}

// jsonPreviousPskNames spell the JSON fields in the messages of raywire.ValidatePreviousPsk.
var jsonPreviousPskNames = raywire.PreviousPskNames{PSK: `"psk"`, PreviousPSK: `"previousPsk"`, Until: `"previousPskUntil"`}

// buildRaywirePreviousPsk checks the optional previous PSK and its expiry, and returns
// the values of the two proto fields. When both are empty the feature is off, and the
// result is nil and 0. psk is the already checked psk. now is the load time. The
// expiry is an RFC 3339 time with a zone, and it is stored as Unix seconds.
//
// The rules that relate the key, the expiry and the load time are in
// raywire.ValidatePreviousPsk, the one check that the server runs too. This function
// decodes the two values, and it spells only the messages of the JSON text: the
// decoding messages, the RFC 3339 form and the Unix epoch.
func buildRaywirePreviousPsk(value, until string, psk []byte, now time.Time) ([]byte, int64, error) {
	previousPsk, err := decodeRaywirePSK(value, "previousPsk")
	if err != nil {
		return nil, 0, err
	}
	if previousPsk == nil && until == "" {
		return nil, 0, nil
	}
	// The validator takes the expiry as a time. A previousPsk with no parsed expiry gets
	// now in its place, which passes the validator's expiry rules. The messages for a
	// missing or malformed expiry come below, after the key checks, which the spec
	// orders first. Without a previousPsk, now is not zero, so the validator refuses
	// the set expiry with its own message.
	expiry := now
	parsed, parseErr := time.Parse(time.RFC3339, until)
	if previousPsk != nil && parseErr == nil {
		expiry = parsed
	}
	if err := raywire.ValidatePreviousPsk(psk, previousPsk, expiry, now, jsonPreviousPskNames); err != nil {
		return nil, 0, err
	}
	if parseErr != nil {
		return nil, 0, errors.New(`raywire: "previousPskUntil" must be an RFC 3339 time with a zone when "previousPsk" is set`)
	}
	// Zero is the proto value for unset, so the epoch itself cannot be stored.
	if parsed.Unix() == 0 {
		return nil, 0, errors.New(`raywire: "previousPskUntil" must not be the Unix epoch`)
	}
	return previousPsk, parsed.Unix(), nil
}

// isRawURLChar reports whether c is in the unpadded base64url alphabet.
func isRawURLChar(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-' || c == '_'
}
