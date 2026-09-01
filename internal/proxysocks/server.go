// Package proxysocks adapts armon/go-socks5 to airjail's policy connector.
package proxysocks

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/armon/go-socks5"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
)

const socksHandshakeTimeout = 10 * time.Second

// Connector establishes a policy-checked destination connection.
type Connector interface {
	Dial(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error)
}

// Server is a TCP CONNECT-only SOCKS5 proxy.
type Server struct {
	backend *socks5.Server

	connections *stream.ConnGroup
}

// New creates a SOCKS5 proxy.
func New(connector Connector) (*Server, error) {
	backend, err := socks5.New(&socks5.Config{
		Resolver: validatingResolver{},
		Rules: &socks5.PermitCommand{
			EnableConnect: true,
		},
		Logger: log.New(io.Discard, "", 0),
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" {
				return nil, fmt.Errorf("unsupported SOCKS network %q", network)
			}

			host, rawPort, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("parse SOCKS address %q: %w", address, err)
			}

			port, err := strconv.Atoi(rawPort)
			if err != nil || port < 1 {
				return nil, fmt.Errorf("invalid SOCKS port: %q", rawPort)
			}

			destination, err := policy.ParseDestination(host)
			if err != nil {
				return nil, fmt.Errorf("parse SOCKS destination: %w", err)
			}

			return connector.Dial(ctx, destination, uint16(port))
		},
	})
	if err != nil {
		return nil, fmt.Errorf("create SOCKS backend: %w", err)
	}

	return &Server{
		backend:     backend,
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

		wrapped := &handshakeConnection{Conn: connection}

		err = wrapped.SetDeadline(time.Now().Add(socksHandshakeTimeout))
		if err != nil {
			_ = wrapped.Close()

			continue
		}

		started := server.connections.Go(func(_ *stream.ConnScope) {
			defer func() { _ = wrapped.Close() }()

			_ = server.backend.ServeConn(wrapped)
		}, wrapped)
		if !started {
			_ = wrapped.Close()
		}
	}
}

type handshakeConnection struct {
	net.Conn
	mutex  sync.Mutex
	writes int
}

func (connection *handshakeConnection) CloseWrite() error {
	closeable, ok := connection.Conn.(interface{ CloseWrite() error })
	if !ok {
		return nil
	}

	return closeable.CloseWrite()
}

func (connection *handshakeConnection) Write(contents []byte) (int, error) {
	connection.mutex.Lock()
	defer connection.mutex.Unlock()

	connection.writes++
	if connection.writes == 2 && len(contents) >= 2 && contents[1] == 0 {
		err := connection.SetDeadline(time.Time{})
		if err != nil {
			return 0, fmt.Errorf("clear SOCKS handshake deadline: %w", err)
		}
	}

	return connection.Conn.Write(contents)
}

type validatingResolver struct{}

func (validatingResolver) Resolve(ctx context.Context, hostname string) (context.Context, net.IP, error) {
	destination, err := policy.ParseDestination(hostname)
	if err != nil {
		return ctx, nil, fmt.Errorf("validate SOCKS hostname %q: %w", hostname, err)
	}

	if !destination.IsHostname() && destination.Zone() == "" {
		return ctx, nil, fmt.Errorf("validate SOCKS hostname %q: value is an IP address", hostname)
	}

	// A scoped IPv6 address must use SOCKS' domain form because its native IPv6
	// address type has no field for a zone. A nil address keeps that original
	// value for the policy-aware dialer and also prevents an extra DNS lookup.
	return ctx, nil, nil
}
