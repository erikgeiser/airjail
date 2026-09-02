// Package proxysocks implements airjail's policy-aware SOCKS5 CONNECT proxy.
package proxysocks

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
)

const (
	socksHandshakeTimeout = 10 * time.Second
	socksVersion          = 5
	socksNoAuthentication = 0
	socksNoAcceptableAuth = 0xff
	socksConnectCommand   = 1
	socksIPv4Address      = 1
	socksDomainAddress    = 3
	socksIPv6Address      = 4
	socksSucceeded        = 0
	socksGeneralFailure   = 1
	socksDenied           = 2
	socksCommandNotFound  = 7
	socksAddressNotFound  = 8
)

// Connector establishes a policy-checked destination connection.
type Connector interface {
	Dial(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error)
}

// Server is a TCP CONNECT-only SOCKS5 proxy.
type Server struct {
	connector   Connector
	connections *stream.ConnGroup
}

// New creates a SOCKS5 proxy.
func New(connector Connector) (*Server, error) {
	if connector == nil {
		return nil, fmt.Errorf("create SOCKS server: connector is nil")
	}

	return &Server{
		connector:   connector,
		connections: stream.NewConnGroup(),
	}, nil
}

// Serve handles SOCKS connections until ctx is canceled.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	stopShutdown := server.connections.ShutdownOnContext(ctx, listener)
	defer stopShutdown()

	for {
		connection, err := listener.Accept()
		if err != nil {
			server.connections.Close()
			server.connections.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept SOCKS connection: %w", err)
		}

		err = connection.SetDeadline(time.Now().Add(socksHandshakeTimeout))
		if err != nil {
			_ = connection.Close()

			continue
		}

		started := server.connections.Go(func(scope *stream.ConnScope) {
			defer func() { _ = connection.Close() }()

			_ = server.serveConnection(ctx, scope, connection)
		}, connection)
		if !started {
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(ctx context.Context, scope *stream.ConnScope, connection net.Conn) error {
	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, socksHandshakeTimeout)
	defer cancelHandshake()

	reader := bufio.NewReader(connection)

	err := negotiateAuthentication(reader, connection)
	if err != nil {
		return err
	}

	destination, port, responseCode, err := readConnectRequest(reader)
	if err != nil {
		if responseCode != 0 {
			_ = writeReply(connection, responseCode, nil)
		}

		return err
	}

	upstream, err := server.connector.Dial(handshakeCtx, destination, port)
	if err != nil {
		responseCode = socksGeneralFailure
		if errors.Is(err, outbound.ErrDenied) {
			responseCode = socksDenied
		}

		_ = writeReply(connection, responseCode, nil)

		return fmt.Errorf("connect SOCKS destination: %w", err)
	}
	defer func() { _ = upstream.Close() }()

	cancelHandshake()

	if !scope.Add(upstream) {
		return fmt.Errorf("register SOCKS upstream during shutdown")
	}

	err = writeReply(connection, socksSucceeded, upstream.LocalAddr())
	if err != nil {
		return fmt.Errorf("write SOCKS success response: %w", err)
	}

	err = connection.SetDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("clear SOCKS handshake deadline: %w", err)
	}

	return stream.Bidirectional(ctx, connection, reader, upstream)
}

func negotiateAuthentication(reader io.Reader, writer io.Writer) error {
	header := make([]byte, 2)

	_, err := io.ReadFull(reader, header)
	if err != nil {
		return fmt.Errorf("read SOCKS greeting: %w", err)
	}

	if header[0] != socksVersion {
		return fmt.Errorf("unsupported SOCKS version %d", header[0])
	}

	methodCount := int(header[1])
	if methodCount == 0 {
		return fmt.Errorf("SOCKS greeting has no authentication methods")
	}

	methods := make([]byte, methodCount)

	_, err = io.ReadFull(reader, methods)
	if err != nil {
		return fmt.Errorf("read SOCKS authentication methods: %w", err)
	}

	selected := byte(socksNoAcceptableAuth)

	for _, method := range methods {
		if method == socksNoAuthentication {
			selected = socksNoAuthentication

			break
		}
	}

	err = writeAll(writer, []byte{socksVersion, selected})
	if err != nil {
		return fmt.Errorf("write SOCKS authentication selection: %w", err)
	}

	if selected == socksNoAcceptableAuth {
		return fmt.Errorf("SOCKS client does not support unauthenticated connections")
	}

	return nil
}

func readConnectRequest(reader io.Reader) (policy.Destination, uint16, byte, error) {
	header := make([]byte, 4)

	_, err := io.ReadFull(reader, header)
	if err != nil {
		return policy.Destination{}, 0, 0, fmt.Errorf("read SOCKS request header: %w", err)
	}

	if header[0] != socksVersion {
		return policy.Destination{}, 0, 0, fmt.Errorf("unsupported SOCKS request version %d", header[0])
	}

	if header[1] != socksConnectCommand {
		return policy.Destination{}, 0, socksCommandNotFound, fmt.Errorf("unsupported SOCKS command %d", header[1])
	}

	if header[2] != 0 {
		return policy.Destination{}, 0, socksGeneralFailure, fmt.Errorf("SOCKS reserved request byte is not zero")
	}

	host, err := readRequestHost(reader, header[3])
	if err != nil {
		return policy.Destination{}, 0, socksAddressNotFound, err
	}

	portBytes := make([]byte, 2)

	_, err = io.ReadFull(reader, portBytes)
	if err != nil {
		return policy.Destination{}, 0, socksGeneralFailure, fmt.Errorf("read SOCKS destination port: %w", err)
	}

	port := uint16(portBytes[0])<<8 | uint16(portBytes[1])
	if port == 0 {
		return policy.Destination{}, 0, socksGeneralFailure, fmt.Errorf("SOCKS destination port is zero")
	}

	destination, err := policy.ParseDestination(host)
	if err != nil {
		return policy.Destination{}, 0, socksAddressNotFound, fmt.Errorf("parse SOCKS destination: %w", err)
	}

	return destination, port, socksSucceeded, nil
}

func readRequestHost(reader io.Reader, addressType byte) (string, error) {
	switch addressType {
	case socksIPv4Address:
		contents := make([]byte, 4)

		_, err := io.ReadFull(reader, contents)
		if err != nil {
			return "", fmt.Errorf("read SOCKS IPv4 destination: %w", err)
		}

		return netip.AddrFrom4([4]byte(contents)).String(), nil
	case socksIPv6Address:
		contents := make([]byte, 16)

		_, err := io.ReadFull(reader, contents)
		if err != nil {
			return "", fmt.Errorf("read SOCKS IPv6 destination: %w", err)
		}

		return netip.AddrFrom16([16]byte(contents)).String(), nil
	case socksDomainAddress:
		length := []byte{0}

		_, err := io.ReadFull(reader, length)
		if err != nil {
			return "", fmt.Errorf("read SOCKS domain length: %w", err)
		}

		if length[0] == 0 {
			return "", fmt.Errorf("SOCKS domain is empty")
		}

		contents := make([]byte, int(length[0]))

		_, err = io.ReadFull(reader, contents)
		if err != nil {
			return "", fmt.Errorf("read SOCKS domain: %w", err)
		}

		return string(contents), nil
	default:
		return "", fmt.Errorf("unsupported SOCKS address type %d", addressType)
	}
}

func writeReply(writer io.Writer, responseCode byte, address net.Addr) error {
	addressType := byte(socksIPv4Address)
	addressBytes := make([]byte, 4)
	port := uint16(0)

	tcpAddress, ok := address.(*net.TCPAddr)
	if ok {
		parsedAddress, found := netip.AddrFromSlice(tcpAddress.IP)
		if found {
			parsedAddress = parsedAddress.Unmap()
			port = uint16(tcpAddress.Port)

			if parsedAddress.Is4() {
				bytes := parsedAddress.As4()
				addressBytes = bytes[:]
			} else {
				addressType = socksIPv6Address
				bytes := parsedAddress.As16()
				addressBytes = bytes[:]
			}
		}
	}

	response := make([]byte, 0, 6+len(addressBytes))
	response = append(response, socksVersion, responseCode, 0, addressType)
	response = append(response, addressBytes...)
	response = append(response, byte(port>>8), byte(port))

	return writeAll(writer, response)
}

func writeAll(writer io.Writer, contents []byte) error {
	for len(contents) != 0 {
		written, err := writer.Write(contents)
		if err != nil {
			return err
		}

		if written == 0 {
			return io.ErrShortWrite
		}

		contents = contents[written:]
	}

	return nil
}
