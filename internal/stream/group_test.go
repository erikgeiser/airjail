package stream

import (
	"context"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

func TestConnGroupWaitsForHandlerCleanup(t *testing.T) {
	t.Parallel()

	group := NewConnGroup()

	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	release := make(chan struct{})
	readDone := make(chan error, 1)
	handlerDone := make(chan struct{})

	started := group.Go(func(_ *ConnScope) {
		defer close(handlerDone)

		buffer := make([]byte, 1)

		_, err := left.Read(buffer)
		readDone <- err

		<-release
	}, left)
	if !started {
		t.Fatal("handler was rejected before shutdown")
	}

	group.Close()

	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("handler read error = %v, want closed connection", err)
		}
	case <-time.After(time.Second):
		_ = left.Close()

		<-readDone
		t.Error("Close did not unblock the handler")
	}

	waitDone := make(chan struct{})

	go func() {
		group.Wait()
		close(waitDone)
	}()

	// The socket has closed, but the handler deliberately still owns cleanup.
	select {
	case <-waitDone:
		t.Error("Wait returned before handler cleanup finished")
	case <-time.After(50 * time.Millisecond):
	}

	close(release)
	<-handlerDone

	select {
	case <-waitDone:
	case <-time.After(time.Second):
		t.Fatal("Wait did not return after handler cleanup")
	}

	if group.Go(func(*ConnScope) {}, right) {
		t.Fatal("Go accepted an operation after shutdown")
	}
}

func TestConnGroupCancellationClosesConnections(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	group := NewConnGroup()

	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	scope, ok := group.Acquire(left)
	if !ok {
		t.Fatal("Acquire rejected an operation before shutdown")
	}
	defer scope.Done()

	readDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 1)

		_, err := left.Read(buffer)
		readDone <- err
	}()

	stopShutdown := group.ShutdownOnContext(ctx)
	defer stopShutdown()

	cancel()

	select {
	case err := <-readDone:
		if !errors.Is(err, io.ErrClosedPipe) {
			t.Errorf("read after cancellation = %v, want closed connection", err)
		}
	case <-time.After(time.Second):
		_ = left.Close()

		<-readDone
		t.Error("cancellation did not close the connection")
	}

	stopShutdown()

	if scope.Add(right) || group.Go(func(*ConnScope) {}) {
		t.Fatal("accepted new work after cancellation")
	}
}
