// Package bridge forwards child-netns loopback TCP connections over pathname Unix sockets.
package bridge

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/erikgeiser/airjail/internal/relay"
)

// Forwarder forwards one TCP listener to one outer Unix socket.
type Forwarder struct {
	socketPath string

	mutex       sync.Mutex
	connections map[net.Conn]struct{}
	waitGroup   sync.WaitGroup
}

// New creates a TCP-to-Unix forwarder.
func New(socketPath string) *Forwarder {
	return &Forwarder{
		socketPath:  socketPath,
		connections: make(map[net.Conn]struct{}),
	}
}

// Serve accepts connections until ctx is canceled.
func (forwarder *Forwarder) Serve(ctx context.Context, listener net.Listener) error {
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
		client, err := listener.Accept()
		if err != nil {
			forwarder.closeAll()
			forwarder.waitGroup.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept bridge connection: %w", err)
		}

		forwarder.waitGroup.Add(1)
		go forwarder.forward(ctx, client)
	}
}

func (forwarder *Forwarder) forward(ctx context.Context, client net.Conn) {
	defer forwarder.waitGroup.Done()
	defer func() { _ = client.Close() }()

	outer, err := (&net.Dialer{}).DialContext(ctx, "unix", forwarder.socketPath)
	if err != nil {
		return
	}
	defer func() { _ = outer.Close() }()

	forwarder.add(client, outer)
	defer forwarder.remove(client, outer)

	_ = relay.Bidirectional(ctx, client, client, outer)
}

func (forwarder *Forwarder) add(connections ...net.Conn) {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for _, connection := range connections {
		forwarder.connections[connection] = struct{}{}
	}
}

func (forwarder *Forwarder) remove(connections ...net.Conn) {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for _, connection := range connections {
		delete(forwarder.connections, connection)
	}
}

func (forwarder *Forwarder) closeAll() {
	forwarder.mutex.Lock()
	defer forwarder.mutex.Unlock()

	for connection := range forwarder.connections {
		_ = connection.Close()
	}
}
