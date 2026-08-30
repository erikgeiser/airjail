package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
)

func TestEnvironmentRouterHTTPConnectPreservesImmediateTunnelBytes(t *testing.T) {
	t.Parallel()

	listener := listenTCP(t)

	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)

		connection, err := listener.Accept()
		if err != nil {
			t.Errorf("accept proxy connection: %v", err)

			return
		}
		defer func() { _ = connection.Close() }()

		reader := bufio.NewReader(connection)

		line, err := reader.ReadString('\n')
		if err != nil {
			t.Errorf("read CONNECT request: %v", err)

			return
		}

		if line != "CONNECT 192.0.2.10:443 HTTP/1.1\r\n" {
			t.Errorf("CONNECT line = %q", line)
		}

		wantAuthorization := "Basic " + base64.StdEncoding.EncodeToString([]byte("user:secret"))
		foundAuthorization := false

		for {
			header, readErr := reader.ReadString('\n')
			if readErr != nil {
				t.Errorf("read CONNECT header: %v", readErr)

				return
			}

			if strings.EqualFold(header, "Proxy-Authorization: "+wantAuthorization+"\r\n") {
				foundAuthorization = true
			}

			if header == "\r\n" {
				break
			}
		}

		if !foundAuthorization {
			t.Error("Proxy-Authorization header not received")
		}

		_, err = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\nHeader: value\r\n\r\nhello")
		if err != nil {
			t.Errorf("write CONNECT response: %v", err)
		}
	}()

	router, err := NewEnvironmentRouter([]string{"HTTPS_PROXY=http://user:secret@" + listener.Addr().String()})
	if err != nil {
		t.Fatalf("NewEnvironmentRouter: %v", err)
	}

	connection, err := router.Dial(
		context.Background(),
		"service.example",
		netip.MustParseAddr("192.0.2.10"),
		443,
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	defer func() { _ = connection.Close() }()

	payload := make([]byte, 5)

	_, err = io.ReadFull(connection, payload)
	if err != nil {
		t.Fatalf("read immediate tunnel bytes: %v", err)
	}

	if string(payload) != "hello" {
		t.Errorf("immediate tunnel bytes = %q, want hello", payload)
	}

	<-requestDone
}

func TestEnvironmentRouterHonorsNoProxy(t *testing.T) {
	t.Parallel()

	target := listenTCP(t)
	accepted := make(chan net.Conn, 1)

	go func() {
		connection, err := target.Accept()
		if err == nil {
			accepted <- connection
		}
	}()

	tcpAddress, ok := target.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address has type %T, want *net.TCPAddr", target.Addr())
	}

	port := uint16(tcpAddress.Port)

	router, err := NewEnvironmentRouter([]string{
		"HTTPS_PROXY=http://127.0.0.1:1",
		"NO_PROXY=service.example",
	})
	if err != nil {
		t.Fatalf("NewEnvironmentRouter: %v", err)
	}

	connection, err := router.Dial(
		context.Background(),
		"service.example",
		netip.MustParseAddr("127.0.0.1"),
		port,
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	defer func() { _ = connection.Close() }()

	serverConnection := <-accepted
	_ = serverConnection.Close()
}

func TestEnvironmentRouterAlwaysDialsLoopbackDirectly(t *testing.T) {
	t.Parallel()

	target := listenTCP(t)
	accepted := make(chan net.Conn, 1)

	go func() {
		connection, err := target.Accept()
		if err == nil {
			accepted <- connection
		}
	}()

	tcpAddress, ok := target.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address has type %T, want *net.TCPAddr", target.Addr())
	}

	router, err := NewEnvironmentRouter([]string{"HTTPS_PROXY=http://127.0.0.1:1"})
	if err != nil {
		t.Fatalf("NewEnvironmentRouter: %v", err)
	}

	connection, err := router.Dial(
		context.Background(),
		"",
		netip.MustParseAddr("127.0.0.1"),
		uint16(tcpAddress.Port),
	)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer func() { _ = connection.Close() }()

	serverConnection := <-accepted
	_ = serverConnection.Close()
}

func TestEnvironmentRouterRejectsMalformedProxyURL(t *testing.T) {
	t.Parallel()

	_, err := NewEnvironmentRouter([]string{"HTTPS_PROXY=http://proxy.example/path"})
	if err == nil {
		t.Fatal("NewEnvironmentRouter unexpectedly accepted a proxy URL path")
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
