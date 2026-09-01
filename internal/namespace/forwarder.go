package namespace

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/erikgeiser/airjail/internal/stream"
)

type forwarder struct {
	socketPath string

	connections *stream.ConnGroup
}

// newForwarder creates a TCP-to-Unix forwarder.
func newForwarder(socketPath string) *forwarder {
	return &forwarder{
		socketPath:  socketPath,
		connections: stream.NewConnGroup(),
	}
}

// Serve accepts connections until ctx is canceled.
func (f *forwarder) Serve(ctx context.Context, listener net.Listener) error {
	stopShutdown := f.connections.ShutdownOnContext(ctx, listener)
	defer stopShutdown()

	for {
		client, err := listener.Accept()
		if err != nil {
			f.connections.Close()
			f.connections.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept bridge connection: %w", err)
		}

		started := f.connections.Go(func(scope *stream.ConnScope) {
			f.forward(ctx, scope, client)
		}, client)
		if !started {
			_ = client.Close()
		}
	}
}

func (f *forwarder) forward(ctx context.Context, scope *stream.ConnScope, client net.Conn) {
	defer func() { _ = client.Close() }()

	outer, err := (&net.Dialer{}).DialContext(ctx, "unix", f.socketPath)
	if err != nil {
		return
	}
	defer func() { _ = outer.Close() }()

	if !scope.Add(outer) {
		return
	}

	_ = stream.Bidirectional(ctx, client, client, outer)
}
