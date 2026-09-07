package namespace

import (
	"bytes"
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
)

type dnsUDPForwarder struct {
	socketPath string
	logger     *logging.Logger

	connections *stream.ConnGroup
}

func newDNSUDPForwarder(socketPath string, logger *logging.Logger) *dnsUDPForwarder {
	return &dnsUDPForwarder{
		socketPath:  socketPath,
		logger:      logger,
		connections: stream.NewConnGroup(),
	}
}

func (forwarder *dnsUDPForwarder) Serve(ctx context.Context, connection *net.UDPConn) error {
	stopShutdown := forwarder.connections.ShutdownOnContext(ctx, connection)
	defer stopShutdown()

	defer func() {
		_ = connection.Close()

		forwarder.connections.Close()
		forwarder.connections.Wait()
	}()

	buffer := make([]byte, maxDNSUDPMessageSize+1)

	for {
		read, client, err := connection.ReadFromUDPAddrPort(buffer)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("read inner DNS UDP query: %w", err)
		}

		if read == 0 || read > maxDNSUDPMessageSize {
			forwarder.logger.Debugf(
				"UDP message with %d bytes exceeded maximum message size of %d bytes and will be ignored",
				read,
				maxDNSUDPMessageSize,
			)

			continue
		}

		request := bytes.Clone(buffer[:read])

		forwarder.connections.Go(func(scope *stream.ConnScope) {
			err := forwarder.forward(ctx, scope, connection, client, request)
			if err != nil {
				forwarder.logger.Debugf("could not forward DNS message: %v", err)
			}
		})
	}
}

func (forwarder *dnsUDPForwarder) forward(
	ctx context.Context,
	scope *stream.ConnScope,
	responseWriter *net.UDPConn,
	client netip.AddrPort,
	request []byte,
) error {
	connection, err := (&net.Dialer{}).DialContext(ctx, "unix", forwarder.socketPath)
	if err != nil {
		return fmt.Errorf("connect to outer proxy: %w", err)
	}
	defer func() { _ = connection.Close() }()

	if !scope.Add(connection) {
		return fmt.Errorf("add connection: %w", err)
	}

	deadline := time.Now().Add(dnsForwardTimeout)
	if contextDeadline, found := ctx.Deadline(); found && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}

	err = connection.SetDeadline(deadline)
	if err != nil {
		return fmt.Errorf("set deadline: %w", err)
	}

	err = stream.WriteUint16Frame(connection, request)
	if err != nil {
		return fmt.Errorf("write datagram frame: %w", err)
	}

	response, err := stream.ReadUint16Frame(connection, maxDNSUDPMessageSize)
	if err != nil {
		return fmt.Errorf("read response frame: %w", err)
	}

	_, err = responseWriter.WriteToUDPAddrPort(response, client)
	if err != nil {
		return fmt.Errorf("send DNS reply to client: %w", err)
	}

	return nil
}
