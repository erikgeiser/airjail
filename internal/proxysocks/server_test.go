package proxysocks

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

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

func TestNegotiateAuthenticationRejectsUnsupportedMethods(t *testing.T) {
	t.Parallel()

	var response bytes.Buffer

	err := negotiateAuthentication(bytes.NewReader([]byte{5, 1, 2}), &response)
	if err == nil {
		t.Fatal("negotiateAuthentication unexpectedly accepted username/password authentication")
	}

	if !bytes.Equal(response.Bytes(), []byte{5, socksNoAcceptableAuth}) {
		t.Errorf("response = %v, want no acceptable authentication method", response.Bytes())
	}
}

func TestSOCKSHostnameConnectPreservesPipelinedBytes(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	target := listenTCP(t)
	targetDone := make(chan error, 1)

	go func() {
		connection, err := target.Accept()
		if err != nil {
			targetDone <- err

			return
		}
		defer func() { _ = connection.Close() }()

		payload := make([]byte, 4)

		_, err = io.ReadFull(connection, payload)
		if err == nil {
			_, err = connection.Write([]byte("pong"))
		}

		targetDone <- err
	}()

	connector := connectorFunc(func(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error) {
		if destination.Hostname() != "service.test" {
			t.Fatalf("hostname = %q, want service.test", destination.Hostname())
		}

		if port != 8080 {
			t.Fatalf("port = %d, want 8080", port)
		}

		return (&net.Dialer{}).DialContext(ctx, "tcp", target.Addr().String())
	})

	server, err := New(connector)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	listener := listenTCP(t)

	serveDone := make(chan error, 1)
	go func() { serveDone <- server.Serve(ctx, listener) }()

	client, err := (&net.Dialer{}).DialContext(ctx, "tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dial SOCKS proxy: %v", err)
	}
	defer func() { _ = client.Close() }()

	_, err = client.Write([]byte{5, 1, 0})
	if err != nil {
		t.Fatalf("write greeting: %v", err)
	}

	authentication := make([]byte, 2)

	_, err = io.ReadFull(client, authentication)
	if err != nil {
		t.Fatalf("read authentication: %v", err)
	}

	if authentication[1] != 0 {
		t.Fatalf("authentication method = %d, want no authentication", authentication[1])
	}

	hostname := []byte("service.test")
	request := []byte{5, 1, 0, 3, byte(len(hostname))}
	request = append(request, hostname...)

	request = binary.BigEndian.AppendUint16(request, 8080)
	request = append(request, []byte("ping")...)

	_, err = client.Write(request)
	if err != nil {
		t.Fatalf("write CONNECT request: %v", err)
	}

	reply := make([]byte, 10)

	_, err = io.ReadFull(client, reply)
	if err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}

	if reply[1] != 0 {
		t.Fatalf("SOCKS reply = %d, want success", reply[1])
	}

	payload := make([]byte, 4)

	_, err = io.ReadFull(client, payload)
	if err != nil {
		t.Fatalf("read tunnel payload: %v", err)
	}

	if string(payload) != "pong" {
		t.Errorf("tunnel payload = %q, want pong", payload)
	}

	err = <-targetDone
	if err != nil {
		t.Fatalf("target server: %v", err)
	}

	cancel()

	select {
	case err = <-serveDone:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("SOCKS server did not stop")
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
