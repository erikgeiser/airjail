package stream

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestConnGroupClosesConnectionsAndWaits(t *testing.T) {
	t.Parallel()

	group := NewConnGroup()

	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	handlerDone := make(chan struct{})

	started := group.Go(func(_ *ConnScope) {
		defer close(handlerDone)

		buffer := make([]byte, 1)
		_, _ = left.Read(buffer)
	}, left)
	if !started {
		t.Fatal("Go rejected an operation before shutdown")
	}

	group.Close()
	group.Wait()

	select {
	case <-handlerDone:
	case <-time.After(time.Second):
		t.Fatal("handler did not stop after connection closure")
	}

	if group.Go(func(*ConnScope) {}, right) {
		t.Fatal("Go accepted an operation after shutdown")
	}
}

func TestConnGroupShutdownOnContext(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	group := NewConnGroup()

	left, right := net.Pipe()
	defer func() { _ = right.Close() }()

	scope, ok := group.Acquire(left)
	if !ok {
		t.Fatal("Acquire rejected an operation before shutdown")
	}
	defer scope.Done()

	stopShutdown := group.ShutdownOnContext(ctx)

	cancel()

	err := left.SetReadDeadline(time.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("set read deadline: %v", err)
	}

	buffer := make([]byte, 1)
	_, err = left.Read(buffer)

	stopShutdown()

	if err == nil {
		t.Fatal("tracked connection remained open after cancellation")
	}

	if group.Go(func(*ConnScope) {}) {
		t.Fatal("Go accepted an operation after cancellation")
	}
}

func TestConnScopeRejectsConnectionDuringShutdown(t *testing.T) {
	t.Parallel()

	group := NewConnGroup()

	scope, ok := group.Acquire()
	if !ok {
		t.Fatal("Acquire rejected an operation before shutdown")
	}
	defer scope.Done()

	group.Close()

	left, right := net.Pipe()
	defer func() { _ = left.Close() }()
	defer func() { _ = right.Close() }()

	if scope.Add(left) {
		t.Fatal("Add accepted a connection during shutdown")
	}
}
