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
)

const socksHandshakeTimeout = 10 * time.Second

// Connector establishes a policy-checked destination connection.
type Connector interface {
	Dial(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error)
}

// Server is a TCP CONNECT-only SOCKS5 proxy.
type Server struct {
	backend *socks5.Server

	mutex       sync.Mutex
	condition   *sync.Cond
	connections map[net.Conn]struct{}
	active      int
	closing     bool
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

	server := &Server{
		backend:     backend,
		connections: make(map[net.Conn]struct{}),
	}
	server.condition = sync.NewCond(&server.mutex)

	return server, nil
}

// Serve handles SOCKS connections until ctx is canceled.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	serveDone := make(chan struct{})

	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)

		select {
		case <-ctx.Done():
			_ = listener.Close()

			server.closeAll()
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
			server.closeAll()
			server.wait()

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

		if !server.add(wrapped) {
			_ = wrapped.Close()

			continue
		}

		go func() {
			defer server.remove(wrapped)

			_ = server.backend.ServeConn(wrapped)
		}()
	}
}

func (server *Server) add(connection net.Conn) bool {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	if server.closing {
		return false
	}

	server.active++
	server.connections[connection] = struct{}{}

	return true
}

func (server *Server) remove(connection net.Conn) {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	delete(server.connections, connection)
	server.active--
	server.condition.Broadcast()
}

func (server *Server) closeAll() {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	server.closing = true
	for connection := range server.connections {
		_ = connection.Close()
	}
}

func (server *Server) wait() {
	server.mutex.Lock()
	defer server.mutex.Unlock()

	for server.active != 0 {
		server.condition.Wait()
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

	if !destination.IsHostname() {
		return ctx, nil, fmt.Errorf("validate SOCKS hostname %q: value is an IP address", hostname)
	}

	// A nil address keeps go-socks5's original FQDN for the policy-aware dialer
	// while preventing an extra, policy-unbound DNS lookup in the backend.
	return ctx, nil, nil
}
