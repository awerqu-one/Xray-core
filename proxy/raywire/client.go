package raywire

import (
	"context"

	"github.com/flynn/noise"
	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/retry"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	core "github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/transport"
	"github.com/xtls/xray-core/transport/internet"
	"github.com/xtls/xray-core/transport/internet/stat"
)

// Client is the outbound handler for the raywire protocol.
type Client struct {
	server        net.Destination
	key           noise.DHKey
	serverPublic  []byte
	keys          pskKeys
	pad           padPolicy
	policyManager policy.Manager
}

// padFromProto converts the configured padding. A nil message means the
// defaults. On a 32-bit int, a value of 2^31 or more becomes negative, and
// validate rejects it.
func padFromProto(p *Padding) padPolicy {
	if p == nil {
		return defaultPadPolicy()
	}
	return padPolicy{Handshake: int(p.Handshake), Frame: int(p.Frame), Bucket: int(p.Bucket)}
}

// NewClient creates a raywire outbound from its configuration.
func NewClient(ctx context.Context, config *ClientConfig) (*Client, error) {
	if config.Address == "" {
		return nil, errors.New("raywire: server address is not set")
	}
	if config.Port == 0 || config.Port > 65535 {
		return nil, errors.New("raywire: invalid server port")
	}
	key, err := keyFromPrivate(config.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(config.ServerPublicKey) != 32 {
		return nil, errors.New("raywire: server public key must be 32 bytes")
	}
	psk, err := pskFromConfig(config.Psk)
	if err != nil {
		return nil, err
	}
	pad := padFromProto(config.Padding)
	if err := pad.validate(); err != nil {
		return nil, err
	}

	v := core.MustFromContext(ctx)
	return &Client{
		server:        net.TCPDestination(net.ParseAddress(config.Address), net.Port(config.Port)),
		key:           key,
		serverPublic:  append([]byte(nil), config.ServerPublicKey...),
		keys:          derivePSKKeys(psk),
		pad:           pad,
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}, nil
}

// Process implements proxy.Outbound.Process().
func (c *Client) Process(ctx context.Context, link *transport.Link, dialer internet.Dialer) error {
	outbounds := session.OutboundsFromContext(ctx)
	if len(outbounds) == 0 {
		return errors.New("raywire: no outbound session")
	}
	ob := outbounds[len(outbounds)-1]
	if !ob.Target.IsValid() {
		return errors.New("target not specified")
	}
	ob.Name = "raywire"
	destination := ob.Target
	if destination.Network != net.Network_TCP && destination.Network != net.Network_UDP {
		return errors.New("raywire: unsupported network ", destination.Network)
	}

	var conn stat.Connection
	err := retry.ExponentialBackoff(5, 100).On(func() error {
		rawConn, err := dialer.Dial(ctx, c.server)
		if err != nil {
			return err
		}
		conn = rawConn
		return nil
	})
	if err != nil {
		return errors.New("failed to find an available destination").Base(err)
	}
	defer conn.Close()

	errors.LogInfo(ctx, "tunneling request to ", destination, " via ", c.server.NetAddr())

	rc, err := ClientHandshake(conn, c.key, c.serverPublic, c.keys, c.pad)
	if err != nil {
		return errors.New("raywire: handshake with server failed").Base(err)
	}

	header, err := encodeHeader(destination)
	if err != nil {
		return err
	}
	if _, err := rc.Write(header); err != nil {
		return errors.New("raywire: failed to send request header").Base(err)
	}

	// A UDP session sends each datagram with its own destination, so both
	// directions use the datagram framing. The session's destination is the
	// default for uploads that carry none.
	toServer, fromServer := buf.NewWriter(rc), buf.NewReader(rc)
	if destination.Network == net.Network_UDP {
		toServer, fromServer = newPacketWriter(rc, destination), newPacketReader(rc)
	}

	sessionPolicy := c.policyManager.ForLevel(0)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessionPolicy.Timeouts.ConnectionIdle)

	// Once the upload is done, the download may take DownlinkOnly. Once the
	// download is done, the upload may take UplinkOnly.
	postRequest := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.DownlinkOnly)
		return buf.Copy(link.Reader, toServer, buf.UpdateActivity(timer))
	}
	getResponse := func() error {
		defer timer.SetTimeout(sessionPolicy.Timeouts.UplinkOnly)
		return buf.Copy(fromServer, link.Writer, buf.UpdateActivity(timer))
	}

	// The end-of-stream frame tells the server that the upload is done. The
	// download keeps running until the server ends its side.
	postRequestAndCloseConn := task.OnSuccess(postRequest, rc.CloseWrite)
	responseDoneAndCloseWriter := task.OnSuccess(getResponse, task.Close(link.Writer))
	if err := task.Run(ctx, postRequestAndCloseConn, responseDoneAndCloseWriter); err != nil {
		common.Must(common.Interrupt(link.Reader))
		common.Must(common.Interrupt(link.Writer))
		return errors.New("connection ends").Base(err)
	}
	return nil
}

func init() {
	common.Must(common.RegisterConfig((*ClientConfig)(nil), func(ctx context.Context, config interface{}) (interface{}, error) {
		return NewClient(ctx, config.(*ClientConfig))
	}))
}
