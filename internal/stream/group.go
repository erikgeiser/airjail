package stream

import (
	"context"
	"io"
	"net"
	"sync"
)

// ConnGroup owns connections and the goroutines using them during shutdown.
type ConnGroup struct {
	mutex       sync.Mutex
	waitGroup   sync.WaitGroup
	connections map[net.Conn]int
	closing     bool
}

// ConnScope owns the connections used by one ConnGroup operation.
type ConnScope struct {
	group       *ConnGroup
	connections map[net.Conn]struct{}
	done        bool
}

// NewConnGroup creates an empty connection group.
func NewConnGroup() *ConnGroup {
	return &ConnGroup{connections: make(map[net.Conn]int)}
}

// Go starts an owned goroutine unless group is shutting down. Connections are
// tracked for shutdown but remain the handler's responsibility to close.
func (group *ConnGroup) Go(handler func(*ConnScope), connections ...net.Conn) bool {
	scope, ok := group.acquire(connections...)
	if !ok {
		return false
	}

	go func() {
		defer scope.Done()

		handler(scope)
	}()

	return true
}

// Acquire starts an operation in group without starting a goroutine.
func (group *ConnGroup) Acquire(connections ...net.Conn) (*ConnScope, bool) {
	return group.acquire(connections...)
}

func (group *ConnGroup) acquire(connections ...net.Conn) (*ConnScope, bool) {
	group.mutex.Lock()
	defer group.mutex.Unlock()

	if group.closing {
		return nil, false
	}

	scope := &ConnScope{
		group:       group,
		connections: make(map[net.Conn]struct{}, len(connections)),
	}
	for _, connection := range connections {
		if connection == nil {
			continue
		}

		if _, found := scope.connections[connection]; found {
			continue
		}

		group.connections[connection]++
		scope.connections[connection] = struct{}{}
	}

	group.waitGroup.Add(1)

	return scope, true
}

// Add registers an additional connection obtained by an active operation.
func (scope *ConnScope) Add(connection net.Conn) bool {
	if connection == nil {
		return false
	}

	group := scope.group
	group.mutex.Lock()
	defer group.mutex.Unlock()

	if scope.done || group.closing {
		return false
	}

	if _, found := scope.connections[connection]; found {
		return true
	}

	group.connections[connection]++
	scope.connections[connection] = struct{}{}

	return true
}

// Done releases an operation and its tracked connections from group.
func (scope *ConnScope) Done() {
	group := scope.group
	group.mutex.Lock()

	if scope.done {
		group.mutex.Unlock()

		return
	}

	for connection := range scope.connections {
		group.connections[connection]--
		if group.connections[connection] == 0 {
			delete(group.connections, connection)
		}
	}

	scope.done = true
	group.mutex.Unlock()

	group.waitGroup.Done()
}

// ShutdownOnContext closes closers and group when ctx is canceled. The returned
// function stops the watcher and waits for its goroutine.
func (group *ConnGroup) ShutdownOnContext(ctx context.Context, closers ...io.Closer) func() {
	stop := make(chan struct{})
	stopped := make(chan struct{})

	go func() {
		defer close(stopped)

		select {
		case <-ctx.Done():
			for _, closer := range closers {
				if closer != nil {
					_ = closer.Close()
				}
			}

			group.Close()
		case <-stop:
		}
	}()

	var once sync.Once

	return func() {
		once.Do(func() { close(stop) })
		<-stopped
	}
}

// Close closes every tracked connection and prevents new operations.
func (group *ConnGroup) Close() {
	group.mutex.Lock()
	group.closing = true

	connections := make([]net.Conn, 0, len(group.connections))
	for connection := range group.connections {
		connections = append(connections, connection)
	}

	group.mutex.Unlock()

	for _, connection := range connections {
		_ = connection.Close()
	}
}

// Wait waits for all owned operations to finish after Close has prevented new registrations.
func (group *ConnGroup) Wait() {
	group.waitGroup.Wait()
}
