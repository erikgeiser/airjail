package namespace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/stream"
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

		request := append([]byte(nil), buffer[:read]...)
		forwarder.startQuery(ctx, responseWriter, client, destination, request)
	}
}

func (forwarder *dnsUDPForwarder) startQuery(
	ctx context.Context,
	responseWriter dnsUDPResponseWriter,
	client netip.AddrPort,
	destination netip.AddrPort,
	request []byte,
) {
	select {
	case forwarder.queries <- struct{}{}:
		started := forwarder.connections.Go(func(scope *stream.ConnScope) {
			defer func() { <-forwarder.queries }()

			forwarder.forward(ctx, scope, responseWriter, client, destination, request)
		})
		if !started {
			<-forwarder.queries
		}
	default:
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
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", forwarder.socketPath)
	if err != nil {
		forwarder.logger.Debugf("connect outer DNS proxy: %v", err)

		return
	}
	defer func() { _ = connection.Close() }()

	if !scope.Add(connection) {
		return
	}

	deadline := time.Now().Add(dnsForwardTimeout)
	if contextDeadline, found := ctx.Deadline(); found && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	err = connection.SetDeadline(deadline)
	if err != nil {
		return
	}

	err = stream.WriteUint16Frame(connection, request)
	if err != nil {
		return
	}

	response, err := stream.ReadUint16Frame(connection, maxDNSUDPMessageSize)
	if err != nil {
		return
	}

	err = responseWriter.WriteResponse(response, client, destination)
	if err != nil {
		forwarder.logger.Debugf("write inner DNS UDP response: %v", err)
	}
}
