package proxyhttp

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
)

type connectorFunc func(context.Context, policy.Destination, uint16) (net.Conn, error)

func (connector connectorFunc) Dial(
	ctx context.Context,
	destination policy.Destination,
	port uint16,
) (net.Conn, error) {
	return connector(ctx, destination, port)
}

func TestConnectPreservesPipelinedNonTLSBytes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	destinationListener := listenTCP(t)
	destinationDone := make(chan error, 1)

	go func() {
		connection, err := destinationListener.Accept()
		if err != nil {
			destinationDone <- err

			return
		}
		defer func() { _ = connection.Close() }()

		payload := make([]byte, 4)

		_, err = io.ReadFull(connection, payload)
		if err == nil && string(payload) != "ping" {
			err = errors.New("unexpected tunnel payload")
		}

		if err == nil {
			_, err = connection.Write([]byte("pong"))
		}

		destinationDone <- err
	}()

	connector := connectorFunc(func(ctx context.Context, _ policy.Destination, _ uint16) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "tcp", destinationListener.Addr().String())
	})

	proxyAddress, stopProxy := startProxy(t, ctx, New(connector))
	defer stopProxy()

	client, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte("CONNECT example.test:22 HTTP/1.1\r\nHost: example.test:22\r\n\r\nping"))
	if err != nil {
		t.Fatalf("write CONNECT and payload: %v", err)
	}

	reader := bufio.NewReader(client)

	status, err := reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read CONNECT status: %v", err)
	}

	if status != "HTTP/1.1 200 Connection Established\r\n" {
		t.Fatalf("status = %q", status)
	}

	for {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatalf("read CONNECT headers: %v", readErr)
		}

		if line == "\r\n" {
			break
		}
	}

	response := make([]byte, 4)

	_, err = io.ReadFull(reader, response)
	if err != nil {
		t.Fatalf("read tunnel response: %v", err)
	}

	if string(response) != "pong" {
		t.Errorf("tunnel response = %q, want pong", response)
	}

	err = <-destinationDone
	if err != nil {
		t.Fatalf("destination server: %v", err)
	}
}

func TestPlainHTTPForwarding(t *testing.T) {
	t.Parallel()

	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		if request.Host != "service.test:8080" {
			t.Errorf("Host = %q, want service.test:8080", request.Host)
		}

		_, _ = io.WriteString(response, "forwarded")
	}))
	defer target.Close()

	targetURL, err := url.Parse(target.URL)
	if err != nil {
		t.Fatalf("parse target URL: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connector := connectorFunc(func(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error) {
		if destination.Hostname() != "service.test" || port != 8080 {
			t.Fatalf("destination = %q:%d, want service.test:8080", destination.Hostname(), port)
		}

		return (&net.Dialer{}).DialContext(ctx, "tcp", targetURL.Host)
	})

	proxyAddress, stopProxy := startProxy(t, ctx, New(connector))
	defer stopProxy()

	proxyURL := &url.URL{Scheme: "http", Host: proxyAddress}
	client := &http.Client{Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)}}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://service.test:8080/path", nil)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}

	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("send request: %v", err)
	}

	defer func() { _ = response.Body.Close() }()

	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read response: %v", err)
	}

	if string(body) != "forwarded" {
		t.Errorf("response body = %q, want forwarded", body)
	}
}

func TestParseAuthorityPreservesIPv6Zone(t *testing.T) {
	t.Parallel()

	destination, port, err := parseAuthority("[fe80::1%eth0]:443")
	if err != nil {
		t.Fatalf("parseAuthority: %v", err)
	}

	if destination.Address().String() != "fe80::1" || destination.Zone() != "eth0" || port != 443 {
		t.Errorf("destination = %s%%%s:%d, want fe80::1%%eth0:443", destination.Address(), destination.Zone(), port)
	}

	if authority := canonicalAuthority(destination, port, true); authority != "[fe80::1%eth0]:443" {
		t.Errorf("canonical authority = %q, want %q", authority, "[fe80::1%eth0]:443")
	}
}

func TestDeniedConnectReturnsForbidden(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	connector := connectorFunc(func(context.Context, policy.Destination, uint16) (net.Conn, error) {
		return nil, outbound.ErrDenied
	})

	proxyAddress, stopProxy := startProxy(t, ctx, New(connector))
	defer stopProxy()

	connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", proxyAddress)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer func() { _ = connection.Close() }()

	_, err = io.WriteString(connection, "CONNECT blocked.test:443 HTTP/1.1\r\nHost: blocked.test:443\r\n\r\n")
	if err != nil {
		t.Fatalf("write CONNECT: %v", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(connection), &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("read response: %v", err)
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", response.StatusCode, http.StatusForbidden)
	}
}

func startProxy(t *testing.T, ctx context.Context, server *Server) (string, func()) {
	t.Helper()

	listener := listenTCP(t)

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()

	return listener.Addr().String(), func() {
		_ = listener.Close()

		select {
		case err := <-serveDone:
			if err != nil && !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("serve proxy: %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Error("proxy did not stop")
		}
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
