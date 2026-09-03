// Package proxydns implements airjail's policy-aware DNS forwarder.
package proxydns

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
)

const (
	maxDNSMessageSize       = 65535
	maxConcurrentQueries    = 256
	maxQueriesPerConnection = 256
	dnsStreamTimeout        = 10 * time.Second
)

// Server forwards filtered DNS queries and records approved answers in policy.
type Server struct {
	policy   *policy.Policy
	upstream Upstream
	logger   *logging.Logger
	queries  chan struct{}

	connections *stream.ConnGroup
}

// New creates a DNS server.
func New(networkPolicy *policy.Policy, upstream Upstream, logger *logging.Logger) (*Server, error) {
	if networkPolicy == nil {
		return nil, fmt.Errorf("create DNS server: network policy is nil")
	}

	if upstream == nil {
		return nil, fmt.Errorf("create DNS server: upstream resolver is nil")
	}

	return &Server{
		policy:      networkPolicy,
		upstream:    upstream,
		logger:      logger,
		queries:     make(chan struct{}, maxConcurrentQueries),
		connections: stream.NewConnGroup(),
	}, nil
}

// Serve accepts DNS-over-stream connections until ctx is canceled.
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

			return fmt.Errorf("accept DNS proxy connection: %w", err)
		}

		started := server.connections.Go(func(_ *stream.ConnScope) {
			server.serveConnection(ctx, connection)
		}, connection)
		if !started {
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()

	for range maxQueriesPerConnection {
		err := connection.SetReadDeadline(time.Now().Add(dnsStreamTimeout))
		if err != nil {
			server.logger.Debugf("set DNS stream read deadline: %v", err)

			return
		}

		request, err := stream.ReadUint16Frame(connection, maxDNSMessageSize)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				server.logger.Debugf("read DNS proxy request: %v", err)
			}

			return
		}

		response := server.handle(ctx, request)
		if len(response) == 0 {
			return
		}

		err = connection.SetWriteDeadline(time.Now().Add(dnsStreamTimeout))
		if err != nil {
			server.logger.Debugf("set DNS stream write deadline: %v", err)

			return
		}

		err = stream.WriteUint16Frame(connection, response)
		if err != nil {
			server.logger.Debugf("write DNS proxy response: %v", err)

			return
		}
	}
}
