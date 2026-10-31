//nolint:goconst // Keep snapshot addresses next to their wire-level expectations.
package proxydns

import (
	"context"
	"errors"
	"io"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
	"github.com/miekg/dns"
)

func TestDNSStreamQueriesAndCancellation(t *testing.T) {
	t.Parallel()

	networkPolicy, err := policy.New(t.Context(), []string{"service.test@192.0.2.10@2001:db8::10"}, nil, policy.Options{})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	server, err := NewWithResolver(networkPolicy, nil, false, nil)
	if err != nil {
		t.Fatalf("create DNS server: %v", err)
	}

	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", filepath.Join(t.TempDir(), "dns.sock"))
	if err != nil {
		t.Fatalf("listen on DNS socket: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan struct{})
	go func() {
		defer close(done)

		serveErr := server.Serve(ctx, listener)
		if serveErr != nil {
			t.Errorf("serve DNS: %v", serveErr)
		}
	}()

	t.Cleanup(func() {
		cancel()

		_ = listener.Close()

		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("DNS server did not finish shutdown")
		}
	})

	client, err := (&net.Dialer{}).DialContext(t.Context(), "unix", listener.Addr().String())
	if err != nil {
		t.Fatalf("connect to DNS socket: %v", err)
	}
	defer func() { _ = client.Close() }()

	err = client.SetDeadline(time.Now().Add(3 * time.Second))
	if err != nil {
		t.Fatalf("set DNS client deadline: %v", err)
	}

	for _, test := range []struct {
		queryType uint16
		address   string
	}{
		{queryType: dns.TypeA, address: "192.0.2.10"},
		{queryType: dns.TypeAAAA, address: "2001:db8::10"},
	} {
		request := new(dns.Msg)
		request.SetQuestion("service.test.", test.queryType)

		wire, packErr := request.Pack()
		if packErr != nil {
			t.Fatalf("pack query: %v", packErr)
		}

		err = stream.WriteUint16Frame(client, wire)
		if err != nil {
			t.Fatalf("send query: %v", err)
		}

		wire, err = stream.ReadUint16Frame(client, 65535)
		if err != nil {
			t.Fatalf("read response: %v", err)
		}

		response := new(dns.Msg)

		err = response.Unpack(wire)
		if err != nil {
			t.Fatalf("unpack response: %v", err)
		}

		mustAddressAnswers(t, response, test.address)

		if response.Id != request.Id {
			t.Errorf("response ID = %d, want %d", response.Id, request.Id)
		}
	}

	cancel()

	buffer := make([]byte, 1)

	_, err = client.Read(buffer)
	if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
		t.Errorf("idle DNS stream after cancellation = %v, want closed", err)
	}
}
