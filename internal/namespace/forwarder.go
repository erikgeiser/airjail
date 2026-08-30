package namespace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/erikgeiser/airjail/internal/relay"
)

type forwarder struct {
	socketPath string

	mutex       sync.Mutex
	connections map[net.Conn]struct{}
	waitGroup   sync.WaitGroup
}

// newForwarder creates a TCP-to-Unix forwarder.
func newForwarder(socketPath string) *forwarder {
	return &forwarder{
		socketPath:  socketPath,
		connections: make(map[net.Conn]struct{}),
	}
}

// Serve accepts connections until ctx is canceled.
func (f *forwarder) Serve(ctx context.Context, listener net.Listener) error {
	serveDone := make(chan struct{})

	shutdownComplete := make(chan struct{})
	go func() {
		defer close(shutdownComplete)

		select {
		case <-ctx.Done():
			_ = listener.Close()

			f.closeAll()
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
			f.closeAll()
			f.waitGroup.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept bridge connection: %w", err)
		}

		f.waitGroup.Go(func() {
			f.forward(ctx, client)
		})
	}
}

func (f *forwarder) forward(ctx context.Context, client net.Conn) {
	defer func() { _ = client.Close() }()

	outer, err := (&net.Dialer{}).DialContext(ctx, "unix", f.socketPath)
	if err != nil {
		return
	}
	defer func() { _ = outer.Close() }()

	f.add(client, outer)
	defer f.remove(client, outer)

	_ = relay.Bidirectional(ctx, client, client, outer)
}

func (f *forwarder) add(connections ...net.Conn) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, connection := range connections {
		f.connections[connection] = struct{}{}
	}
}

func (f *forwarder) remove(connections ...net.Conn) {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	for _, connection := range connections {
		delete(f.connections, connection)
	}
}

func (f *forwarder) closeAll() {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	for connection := range f.connections {
		_ = connection.Close()
	}
}
