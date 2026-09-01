package stream

import (
	"context"
	"io"
	"net"
	"testing"
	"time"
)

func TestBidirectionalPreservesTCPHalfClose(t *testing.T) {
	t.Parallel()

	leftListener := listenTCP(t)
	rightListener := listenTCP(t)

	client, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", leftListener.Addr().String())
	if err != nil {
		t.Fatalf("dial left: %v", err)
	}
	defer func() { _ = client.Close() }()

	left, err := leftListener.Accept()
	if err != nil {
		t.Fatalf("accept left: %v", err)
	}
	defer func() { _ = left.Close() }()

	right, err := (&net.Dialer{}).DialContext(context.Background(), "tcp", rightListener.Addr().String())
	if err != nil {
		t.Fatalf("dial right: %v", err)
	}
	defer func() { _ = right.Close() }()

	target, err := rightListener.Accept()
	if err != nil {
		t.Fatalf("accept right: %v", err)
	}
	defer func() { _ = target.Close() }()

	relayDone := make(chan error, 1)
	go func() { relayDone <- Bidirectional(context.Background(), left, left, right) }()

	clientTCP, ok := client.(*net.TCPConn)
	if !ok {
		t.Fatalf("client type = %T, want *net.TCPConn", client)
	}

	_, err = client.Write([]byte("request"))
	if err != nil {
		t.Fatalf("write request: %v", err)
	}

	err = clientTCP.CloseWrite()
	if err != nil {
		t.Fatalf("half-close client: %v", err)
	}

	request, err := io.ReadAll(target)
	if err != nil {
		t.Fatalf("read request: %v", err)
	}

	if string(request) != "request" {
		t.Errorf("request = %q, want request", request)
	}

	_, err = target.Write([]byte("response"))
	if err != nil {
		t.Fatalf("write response: %v", err)
	}

	targetTCP, ok := target.(*net.TCPConn)
	if !ok {
		t.Fatalf("target type = %T, want *net.TCPConn", target)
	}

	err = targetTCP.CloseWrite()
	if err != nil {
		t.Fatalf("half-close target: %v", err)
	}

	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if string(response) != "response" {
		t.Errorf("response = %q, want response", response)
	}

	select {
	case err = <-relayDone:
		if err != nil {
			t.Errorf("Bidirectional: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("relay did not stop")
	}
}

func listenTCP(t *testing.T) net.Listener {
	t.Helper()

	listener, err := (&net.ListenConfig{}).Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen TCP: %v", err)
	}

	t.Cleanup(func() { _ = listener.Close() })

	return listener
}
