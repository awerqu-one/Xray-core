package raywire

import (
	"encoding/binary"
	"io"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
)

// The header is the first message of a stream, sent inside the encrypted
// channel. It names the destination the server should dial:
//
//	[1 byte network: 1=tcp, 2=udp][2 bytes port, big-endian][1 byte address length][address]
const (
	headerFixedLen = 4

	networkTCP byte = 1
	networkUDP byte = 2
)

// encodeHeader serializes dest into the stream header.
func encodeHeader(dest net.Destination) ([]byte, error) {
	var network byte
	switch dest.Network {
	case net.Network_TCP:
		network = networkTCP
	case net.Network_UDP:
		network = networkUDP
	default:
		return nil, errors.New("raywire: unsupported network ", dest.Network)
	}
	if dest.Address == nil {
		return nil, errors.New("raywire: destination address is empty")
	}
	address := dest.Address.String()
	if len(address) == 0 || len(address) > 255 {
		return nil, errors.New("raywire: destination address length must be 1..255 bytes")
	}
	if dest.Port == 0 {
		return nil, errors.New("raywire: destination port is zero")
	}

	header := make([]byte, headerFixedLen+len(address))
	header[0] = network
	binary.BigEndian.PutUint16(header[1:3], uint16(dest.Port))
	header[3] = byte(len(address))
	copy(header[headerFixedLen:], address)
	return header, nil
}

// decodeHeader reads one header from r. It reads exactly the header bytes, so
// payload that follows stays in r.
func decodeHeader(r io.Reader) (net.Destination, error) {
	var fixed [headerFixedLen]byte
	if _, err := io.ReadFull(r, fixed[:]); err != nil {
		return net.Destination{}, errors.New("raywire: failed to read header").Base(err)
	}

	var network net.Network
	switch fixed[0] {
	case networkTCP:
		network = net.Network_TCP
	case networkUDP:
		network = net.Network_UDP
	default:
		return net.Destination{}, errors.New("raywire: unknown network in header ", fixed[0])
	}

	port := net.Port(binary.BigEndian.Uint16(fixed[1:3]))
	if port == 0 {
		return net.Destination{}, errors.New("raywire: header port is zero")
	}

	address := make([]byte, fixed[3])
	if len(address) == 0 {
		return net.Destination{}, errors.New("raywire: header address is empty")
	}
	if _, err := io.ReadFull(r, address); err != nil {
		return net.Destination{}, errors.New("raywire: failed to read header address").Base(err)
	}

	// ParseAddress trims spaces, so an address of only spaces becomes empty. Such a
	// header could not be encoded again, so it is refused here.
	addr := net.ParseAddress(string(address))
	if addr.String() == "" {
		return net.Destination{}, errors.New("raywire: header address is empty")
	}
	dest := net.Destination{
		Network: network,
		Address: addr,
		Port:    port,
	}
	return dest, nil
}
