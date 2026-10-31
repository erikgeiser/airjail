//nolint:goconst // Literal addresses make routing expectations explicit.
package outbound

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"testing"
	"time"
)

const deadProxyEnvironment = "HTTPS_PROXY=http://127.0.0.1:1"

func TestProxyAwareRouterConfiguredProxyTakesPrecedence(t *testing.T) {
	t.Parallel()

	listener := listenTCP(t)

	requestDone := make(chan struct{})

	t.Cleanup(func() {
		_ = listener.Close()

		<-requestDone
	})

	go func() {
		defer close(requestDone)

		connection, err := listener.Accept()
		if err != nil {
			t.Errorf("accept proxy connection: %v", err)

			return
		}
		defer func() { _ = connection.Close() }()

		err = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if err != nil {
			t.Errorf("set proxy deadline: %v", err)

			return
		}

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

	router, err := NewProxyAwareRouter(
		[]string{deadProxyEnvironment},
		"http://user:secret@"+listener.Addr().String(),
		defaultConnectTimeout,
	)
	if err != nil {
		t.Fatalf("NewProxyAwareRouter: %v", err)
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

	err = connection.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("set tunnel deadline: %v", err)
	}

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

func TestProxyAwareRouterSelectsRoute(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name    string
		noProxy string
		address string
		want    string
	}{
		{name: "proxy", address: "192.0.2.10", want: "127.0.0.1:1"},
		{name: "hostname exclusion", noProxy: "service.example", address: "192.0.2.10", want: "192.0.2.10:443"},
		{name: "unrelated exclusion", noProxy: "other.example", address: "192.0.2.10", want: "127.0.0.1:1"},
		{name: "outer loopback", address: "127.0.0.1", want: "127.0.0.1:443"},
		{name: "scoped IPv6", address: "fe80::1%lo", want: "[fe80::1%lo]:443"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			router, err := NewProxyAwareRouter([]string{deadProxyEnvironment, "NO_PROXY=" + test.noProxy},
				"", defaultConnectTimeout)
			if err != nil {
				t.Fatalf("create router: %v", err)
			}

			stopDial := errors.New("stop before connecting")
			attempted := ""
			// Observe the actual socket destination without accessing an external network.
			router.dialer.Control = func(_, address string, _ syscall.RawConn) error {
				attempted = address

				return stopDial
			}

			connection, err := router.Dial(t.Context(), "service.example", netip.MustParseAddr(test.address), 443)
			if connection != nil {
				_ = connection.Close()

				t.Fatal("dial unexpectedly connected")
			}

			if !errors.Is(err, stopDial) || attempted != test.want {
				t.Fatalf("dial attempted %q, %v; want %q", attempted, err, test.want)
			}
		})
	}
}

func TestProxyAwareRouterRejectsMalformedProxyURL(t *testing.T) {
	t.Parallel()

	_, err := NewProxyAwareRouter([]string{"HTTPS_PROXY=http://proxy.example/path"}, "", defaultConnectTimeout)
	if err == nil {
		t.Fatal("NewProxyAwareRouter unexpectedly accepted a proxy URL path")
	}
}

func TestProxyAwareRouterRejectsInvalidConnectTimeout(t *testing.T) {
	t.Parallel()

	_, err := NewProxyAwareRouter(nil, "", 0)
	if err == nil {
		t.Fatal("NewProxyAwareRouter unexpectedly accepted a zero connect timeout")
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
