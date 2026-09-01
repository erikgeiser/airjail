package namespace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"unsafe"

	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/relay"
	xproxy "golang.org/x/net/proxy"
	"golang.org/x/sys/unix"
)

type transparentTCPForwarder struct {
	dialer    xproxy.ContextDialer
	dnsSocket string
	logger    *logging.Logger

	mutex       sync.Mutex
	connections map[net.Conn]struct{}
	waitGroup   sync.WaitGroup
}

func newTransparentTCPForwarder(socketPath, dnsSocketPath string, logger *logging.Logger) (*transparentTCPForwarder, error) {
	proxyDialer, err := xproxy.SOCKS5("unix", socketPath, nil, &net.Dialer{})
	if err != nil {
		return nil, fmt.Errorf("create internal SOCKS dialer: %w", err)
	}

	dialer, ok := proxyDialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("create internal SOCKS dialer: context cancellation is unsupported")
	}

	return &transparentTCPForwarder{
		dialer:      dialer,
		dnsSocket:   dnsSocketPath,
		logger:      logger,
		connections: make(map[net.Conn]struct{}),
	}, nil
}

func (forwarder *transparentTCPForwarder) Serve(ctx context.Context, listener net.Listener) error {
	serveDone := make(chan struct{})
	shutdownComplete := make(chan struct{})

	go func() {
		defer close(shutdownComplete)

		select {
		case <-ctx.Done():
			_ = listener.Close()

			forwarder.closeAll()
		case <-serveDone:
		}
	}()

	defer func() {
		close(serveDone)
		<-shutdownComplete
	}()

	for {
		connection, err := listener.Accept()
		if err != nil {
			forwarder.closeAll()
			forwarder.waitGroup.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept transparent TCP connection: %w", err)
		}

		forwarder.add(connection)
		forwarder.waitGroup.Go(func() {
			forwarder.forward(ctx, connection)
		})
	}
}

func (forwarder *transparentTCPForwarder) forward(ctx context.Context, connection net.Conn) {
	defer forwarder.remove(connection)
	defer func() { _ = connection.Close() }()

	tcpConnection, ok := connection.(*net.TCPConn)
	if !ok {
		forwarder.logger.Debugf("reject transparent connection with type %T", connection)

		return
	}

	destination, err := originalDestination(tcpConnection)
	if err != nil {
		forwarder.logger.Debugf("recover transparent TCP destination: %v", err)

		return
	}

	if isInternalEndpoint(destination) {
		forwarder.logger.Debugf("reject direct connection to internal endpoint %s", destination)

		return
	}

	var upstream net.Conn
	if destination.Port() == 53 {
		upstream, err = (&net.Dialer{}).DialContext(ctx, "unix", forwarder.dnsSocket)
	} else {
		upstream, err = forwarder.dialer.DialContext(ctx, "tcp", destination.String())
	}

	if err != nil {
		forwarder.logger.Debugf("connect transparent TCP destination %s: %v", destination, err)

		return
	}

	defer func() { _ = upstream.Close() }()

	forwarder.add(upstream)
	defer forwarder.remove(upstream)

	err = relay.Bidirectional(ctx, connection, connection, upstream)
	if err != nil {
		forwarder.logger.Debugf("relay transparent TCP destination %s: %v", destination, err)
	}
}

func (forwarder *transparentTCPForwarder) add(connections ...net.Conn) {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for _, connection := range connections {
		forwarder.connections[connection] = struct{}{}
	}
}

func (forwarder *transparentTCPForwarder) remove(connections ...net.Conn) {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for _, connection := range connections {
		delete(forwarder.connections, connection)
	}
}

func (forwarder *transparentTCPForwarder) closeAll() {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for connection := range forwarder.connections {
		_ = connection.Close()
	}
}

func originalDestination(connection *net.TCPConn) (netip.AddrPort, error) {
	rawConnection, err := connection.SyscallConn()
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("access transparent TCP socket: %w", err)
	}

	localAddress, ok := connection.LocalAddr().(*net.TCPAddr)
	if !ok {
		return netip.AddrPort{}, fmt.Errorf("inspect transparent TCP local address: unexpected type %T", connection.LocalAddr())
	}

	var (
		destination netip.AddrPort
		controlErr  error
	)

	err = rawConnection.Control(func(fileDescriptor uintptr) {
		if localAddress.IP.To4() != nil {
			destination, controlErr = originalIPv4Destination(int(fileDescriptor))
		} else {
			destination, controlErr = originalIPv6Destination(int(fileDescriptor))
		}
	})
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("control transparent TCP socket: %w", err)
	}

	if controlErr != nil {
		return netip.AddrPort{}, controlErr
	}

	return destination, nil
}

func originalIPv4Destination(fileDescriptor int) (netip.AddrPort, error) {
	rawAddress := unix.RawSockaddrInet4{}

	addressLength, err := readOriginalDestination(
		fileDescriptor,
		unix.SOL_IP,
		unsafe.Pointer(&rawAddress),
		uint32(unsafe.Sizeof(rawAddress)),
	)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("get original IPv4 destination: %w", err)
	}

	return parseOriginalDestination(
		rawAddress.Family,
		unix.AF_INET,
		addressLength,
		uint32(unsafe.Sizeof(rawAddress)),
		rawAddress.Port,
		netip.AddrFrom4(rawAddress.Addr),
	)
}

func originalIPv6Destination(fileDescriptor int) (netip.AddrPort, error) {
	rawAddress := unix.RawSockaddrInet6{}

	addressLength, err := readOriginalDestination(
		fileDescriptor,
		unix.SOL_IPV6,
		unsafe.Pointer(&rawAddress),
		uint32(unsafe.Sizeof(rawAddress)),
	)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("get original IPv6 destination: %w", err)
	}

	return parseOriginalDestination(
		rawAddress.Family,
		unix.AF_INET6,
		addressLength,
		uint32(unsafe.Sizeof(rawAddress)),
		rawAddress.Port,
		netip.AddrFrom16(rawAddress.Addr),
	)
}

func readOriginalDestination(fileDescriptor, level int, address unsafe.Pointer, addressSize uint32) (uint32, error) {
	addressLength := addressSize

	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		uintptr(fileDescriptor),
		uintptr(level),
		unix.SO_ORIGINAL_DST,
		uintptr(address),
		uintptr(unsafe.Pointer(&addressLength)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}

	return addressLength, nil
}

func parseOriginalDestination(
	family uint16,
	expectedFamily uint16,
	addressLength uint32,
	expectedLength uint32,
	rawPort uint16,
	address netip.Addr,
) (netip.AddrPort, error) {
	if family != expectedFamily || addressLength < expectedLength {
		return netip.AddrPort{}, fmt.Errorf("malformed socket address")
	}

	port := binary.BigEndian.Uint16((*[2]byte)(unsafe.Pointer(&rawPort))[:])
	if port == 0 {
		return netip.AddrPort{}, fmt.Errorf("port is zero")
	}

	return netip.AddrPortFrom(address, port), nil
}

func isInternalEndpoint(destination netip.AddrPort) bool {
	if destination.Addr() == netip.MustParseAddr(internalIPv4Address) {
		switch destination.Port() {
		case 19080, 19081, transparentTCPPort, dnsPort:
			return true
		}
	}

	return destination.Addr() == netip.MustParseAddr(internalIPv6Address) &&
		(destination.Port() == transparentTCPPort || destination.Port() == dnsPort)
}
