package proxysocks

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
)

func TestSOCKSRequestsReachPolicyBeforeDialing(t *testing.T) {
	t.Parallel()

	ipv6 := append([]byte{5, 1, 0, 4}, netip.MustParseAddr("2001:db8::1").AsSlice()...)
	ipv6 = append(ipv6, 1, 187)
	domain := append([]byte{5, 1, 0, 3, 12}, []byte("service.test")...)
	domain = append(domain, 1, 187)

	for _, test := range []struct {
		name    string
		request []byte
		reply   byte
		dial    string
	}{
		{name: "approved IPv4", request: []byte{5, 1, 0, 1, 192, 0, 2, 1, 1, 187}, reply: 1, dial: "192.0.2.1:443"},
		{name: "approved IPv6", request: ipv6, reply: 1, dial: "[2001:db8::1]:443"},
		{name: "approved hostname snapshot", request: domain, reply: 1, dial: "192.0.2.1:443"},
		{name: "denied address", request: []byte{5, 1, 0, 1, 192, 0, 2, 2, 1, 187}, reply: 2},
		{name: "denied port", request: []byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 80}, reply: 2},
		{name: "BIND rejected", request: []byte{5, 2, 0, 1}, reply: 7},
		{name: "UDP rejected", request: []byte{5, 3, 0, 1}, reply: 7},
		{name: "invalid address type", request: []byte{5, 1, 0, 9}, reply: 8},
		{name: "zero port", request: []byte{5, 1, 0, 1, 192, 0, 2, 1, 0, 0}, reply: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkPolicy, err := policy.New(t.Context(), []string{"service.test:443@192.0.2.1", "[2001:db8::1]:443"},
				nil, policy.Options{})
			if err != nil {
				t.Fatalf("create policy: %v", err)
			}

			dials := make(chan string, 1)
			connector := outbound.NewDirect(networkPolicy, nil, func(_ context.Context, _, address string) (net.Conn, error) {
				dials <- address

				return nil, fmt.Errorf("test dial stopped")
			}, nil)

			server, err := New(connector, time.Second)
			if err != nil {
				t.Fatalf("create SOCKS server: %v", err)
			}

			listener := listenTCP(t)
			ctx, cancel := context.WithCancel(t.Context())

			done := make(chan error, 1)
			go func() { done <- server.Serve(ctx, listener) }()

			t.Cleanup(func() {
				cancel()

				_ = listener.Close()

				select {
				case serveErr := <-done:
					if serveErr != nil {
						t.Errorf("serve SOCKS: %v", serveErr)
					}
				case <-time.After(3 * time.Second):
					t.Error("SOCKS server did not finish shutdown")
				}
			})

			client, err := (&net.Dialer{}).DialContext(t.Context(), "tcp", listener.Addr().String())
			if err != nil {
				t.Fatalf("connect to SOCKS: %v", err)
			}
			defer func() { _ = client.Close() }()

			err = client.SetDeadline(time.Now().Add(3 * time.Second))
			if err != nil {
				t.Fatalf("set client deadline: %v", err)
			}

			wire := append([]byte{5, 1, 0}, test.request...)

			_, err = client.Write(wire)
			if err != nil {
				t.Fatalf("send request: %v", err)
			}

			reply := make([]byte, 12)

			_, err = io.ReadFull(client, reply)
			if err != nil {
				t.Fatalf("read reply: %v", err)
			}

			if reply[0] != 5 || reply[1] != 0 || reply[2] != 5 || reply[3] != test.reply {
				t.Fatalf("greeting and CONNECT reply = %v, want CONNECT code %d", reply, test.reply)
			}

			attempted := ""
			select {
			case attempted = <-dials:
			default:
			}

			if attempted != test.dial {
				t.Errorf("dialed %q, want %q", attempted, test.dial)
			}
		})
	}
}
