package namespace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"
	"unsafe"

	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/stream"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

const (
	maxDNSUDPMessageSize = 4096
	dnsForwardTimeout    = 10 * time.Second
	maxDNSUDPQueries     = 256
)

type dnsUDPResponseWriter interface {
	WriteResponse(response []byte, client, source netip.AddrPort) error
	Close() error
}

type dnsIPv4ResponseWriter struct {
	connection *ipv4.PacketConn
}

func (writer dnsIPv4ResponseWriter) WriteResponse(response []byte, client, source netip.AddrPort) error {
	_, err := writer.connection.WriteTo(
		response,
		&ipv4.ControlMessage{Src: source.Addr().AsSlice()},
		net.UDPAddrFromAddrPort(client),
	)

	return err
}

func (writer dnsIPv4ResponseWriter) Close() error {
	return writer.connection.Close()
}

type dnsIPv6ResponseWriter struct {
	connection *ipv6.PacketConn
}

func (writer dnsIPv6ResponseWriter) WriteResponse(response []byte, client, source netip.AddrPort) error {
	_, err := writer.connection.WriteTo(
		response,
		&ipv6.ControlMessage{Src: source.Addr().AsSlice()},
		net.UDPAddrFromAddrPort(client),
	)

	return err
}

func (writer dnsIPv6ResponseWriter) Close() error {
	return writer.connection.Close()
}

type dnsUDPForwarder struct {
	socketPath string
	logger     *logging.Logger
	queries    chan struct{}

	connections *stream.ConnGroup
}

func newDNSUDPForwarder(socketPath string, logger *logging.Logger) *dnsUDPForwarder {
	return &dnsUDPForwarder{
		socketPath:  socketPath,
		logger:      logger,
		queries:     make(chan struct{}, maxDNSUDPQueries),
		connections: stream.NewConnGroup(),
	}
}

func (forwarder *dnsUDPForwarder) Serve(
	ctx context.Context,
	connection *net.UDPConn,
	responseWriter dnsUDPResponseWriter,
	ipv6Destination bool,
) error {
	stopShutdown := forwarder.connections.ShutdownOnContext(ctx, connection, responseWriter)
	defer stopShutdown()

	defer func() {
		_ = connection.Close()
		_ = responseWriter.Close()

		forwarder.connections.Close()
		forwarder.connections.Wait()
	}()

	buffer := make([]byte, maxDNSUDPMessageSize+1)
	control := make([]byte, 128)

	for {
		read, controlRead, _, client, err := connection.ReadMsgUDPAddrPort(buffer, control)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("read inner DNS UDP query: %w", err)
		}

		if read == 0 || read > maxDNSUDPMessageSize {
			continue
		}

		destination, err := parseOriginalDNSDestination(control[:controlRead], ipv6Destination)
		if err != nil {
			forwarder.logger.Debugf("recover original DNS UDP destination: %v", err)

			continue
		}

		contents := append([]byte(nil), buffer[:read]...)

		select {
		case forwarder.queries <- struct{}{}:
			started := forwarder.connections.Go(func(scope *stream.ConnScope) {
				defer func() { <-forwarder.queries }()

				forwarder.forward(ctx, scope, responseWriter, client, destination, contents)
			})
			if !started {
				<-forwarder.queries
			}
		default:
		}
	}
}

func (forwarder *dnsUDPForwarder) forward(
	ctx context.Context,
	scope *stream.ConnScope,
	responseWriter dnsUDPResponseWriter,
	client netip.AddrPort,
	destination netip.AddrPort,
	request []byte,
) {
	streamConnection, err := (&net.Dialer{}).DialContext(ctx, "unix", forwarder.socketPath)
	if err != nil {
		forwarder.logger.Debugf("connect outer DNS proxy: %v", err)

		return
	}

	defer func() { _ = streamConnection.Close() }()

	if !scope.Add(streamConnection) {
		return
	}

	deadline := time.Now().Add(dnsForwardTimeout)
	if contextDeadline, found := ctx.Deadline(); found && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	err = streamConnection.SetDeadline(deadline)
	if err != nil {
		return
	}

	err = stream.WriteUint16Frame(streamConnection, request)
	if err != nil {
		return
	}

	response, err := stream.ReadUint16Frame(streamConnection, maxDNSUDPMessageSize)
	if err != nil {
		return
	}

	err = responseWriter.WriteResponse(response, client, destination)
	if err != nil {
		forwarder.logger.Debugf("write inner DNS UDP response: %v", err)
	}
}

func createDNSUDPQuerySocket(ctx context.Context, network string, ipv6Destination bool) (*net.UDPConn, error) {
	address := net.JoinHostPort("0.0.0.0", fmt.Sprintf("%d", dnsPort))
	if ipv6Destination {
		address = net.JoinHostPort("::", fmt.Sprintf("%d", dnsPort))
	}

	return listenTransparentUDPSocket(ctx, network, address, ipv6Destination)
}

func createDNSUDPResponseWriter(
	ctx context.Context,
	network string,
	ipv6Destination bool,
) (dnsUDPResponseWriter, error) {
	address := "0.0.0.0:53"
	if ipv6Destination {
		address = "[::]:53"
	}

	udpConnection, err := listenTransparentUDPSocket(ctx, network, address, ipv6Destination)
	if err != nil {
		return nil, fmt.Errorf("listen on transparent DNS UDP response socket %s: %w", address, err)
	}

	if ipv6Destination {
		return dnsIPv6ResponseWriter{connection: ipv6.NewPacketConn(udpConnection)}, nil
	}

	return dnsIPv4ResponseWriter{connection: ipv4.NewPacketConn(udpConnection)}, nil
}

func listenTransparentUDPSocket(
	ctx context.Context,
	network string,
	address string,
	ipv6Destination bool,
) (*net.UDPConn, error) {
	listenConfig := net.ListenConfig{
		Control: func(_, _ string, rawConnection syscall.RawConn) error {
			var controlErr error

			err := rawConnection.Control(func(fileDescriptor uintptr) {
				if ipv6Destination {
					controlErr = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				} else {
					controlErr = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
				}
			})
			if err != nil {
				return fmt.Errorf("control transparent DNS UDP socket: %w", err)
			}

			return controlErr
		},
	}

	packetConnection, err := listenConfig.ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	udpConnection, ok := packetConnection.(*net.UDPConn)
	if !ok {
		_ = packetConnection.Close()

		return nil, fmt.Errorf("listen on transparent DNS UDP socket: unexpected type %T", packetConnection)
	}

	return udpConnection, nil
}

func enableOriginalDNSDestination(connection *net.UDPConn, ipv6Destination bool) error {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return fmt.Errorf("access DNS UDP socket: %w", err)
	}

	var controlErr error

	err = rawConnection.Control(func(fileDescriptor uintptr) {
		if ipv6Destination {
			controlErr = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR, 1)
		} else {
			controlErr = unix.SetsockoptInt(int(fileDescriptor), unix.SOL_IP, unix.IP_RECVORIGDSTADDR, 1)
		}
	})
	if err != nil {
		return fmt.Errorf("control DNS UDP socket: %w", err)
	}

	if controlErr != nil {
		return fmt.Errorf("enable original DNS UDP destination: %w", controlErr)
	}

	return nil
}

func parseOriginalDNSDestination(control []byte, ipv6Destination bool) (netip.AddrPort, error) {
	messages, err := unix.ParseSocketControlMessage(control)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("parse DNS UDP control message: %w", err)
	}

	for _, message := range messages {
		if !ipv6Destination && message.Header.Level == unix.SOL_IP && message.Header.Type == unix.IP_ORIGDSTADDR {
			if len(message.Data) < unix.SizeofSockaddrInet4 {
				return netip.AddrPort{}, fmt.Errorf("original IPv4 DNS destination is truncated")
			}

			raw := (*unix.RawSockaddrInet4)(unsafe.Pointer(&message.Data[0]))

			return netip.AddrPortFrom(netip.AddrFrom4(raw.Addr), networkPort(raw.Port)), nil
		}

		if ipv6Destination && message.Header.Level == unix.SOL_IPV6 && message.Header.Type == unix.IPV6_ORIGDSTADDR {
			if len(message.Data) < unix.SizeofSockaddrInet6 {
				return netip.AddrPort{}, fmt.Errorf("original IPv6 DNS destination is truncated")
			}

			raw := (*unix.RawSockaddrInet6)(unsafe.Pointer(&message.Data[0]))

			return netip.AddrPortFrom(netip.AddrFrom16(raw.Addr), networkPort(raw.Port)), nil
		}
	}

	return netip.AddrPort{}, fmt.Errorf("original DNS destination is unavailable")
}

func networkPort(rawPort uint16) uint16 {
	return binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rawPort))[:])
}
