package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/erikgeiser/airjail/internal/policy"
)

type fakeResolver struct {
	addresses map[string][]netip.Addr
}

func (resolver fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}

	return resolver.addresses[host], nil
}

func TestDirectDialsOnlyApprovedResolvedAddress(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{addresses: map[string][]netip.Addr{
		"service.example": {
			netip.MustParseAddr("10.0.0.1"),
			netip.MustParseAddr("192.0.2.10"),
		},
	}}

	networkPolicy, err := policy.New(
		context.Background(),
		[]string{"service.example"},
		[]string{"10.0.0.0/8"},
		policy.Options{Resolver: resolver},
	)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	var dialedAddress string

	dial := func(_ context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			t.Fatalf("network = %q, want tcp", network)
		}

		dialedAddress = address
		client, server := net.Pipe()

		t.Cleanup(func() { _ = server.Close() })

		return client, nil
	}

	destination, err := policy.ParseDestination("service.example")
	if err != nil {
		t.Fatalf("policy.ParseDestination: %v", err)
	}

	connection, err := NewDirect(networkPolicy, resolver, dial).Dial(context.Background(), destination, 443)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	if dialedAddress != "192.0.2.10:443" {
		t.Errorf("dialed address = %q, want 192.0.2.10:443", dialedAddress)
	}
}

func TestDirectNeverPassesLegacyNumericHostnameToDialer(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{addresses: map[string][]netip.Addr{
		"127.1": {netip.MustParseAddr("127.0.0.1")},
	}}

	networkPolicy, err := policy.New(
		context.Background(),
		[]string{"127.1"},
		nil,
		policy.Options{Resolver: resolver},
	)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	var dialedAddress string

	dial := func(_ context.Context, _ string, address string) (net.Conn, error) {
		dialedAddress = address
		client, server := net.Pipe()

		t.Cleanup(func() { _ = server.Close() })

		return client, nil
	}

	destination, err := policy.ParseDestination("127.1")
	if err != nil {
		t.Fatalf("policy.ParseDestination: %v", err)
	}

	connection, err := NewDirect(networkPolicy, resolver, dial).Dial(context.Background(), destination, 80)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	if dialedAddress != "127.0.0.1:80" {
		t.Errorf("dialed address = %q, want 127.0.0.1:80", dialedAddress)
	}
}

func TestDirectDoesNotDialDeniedAddress(t *testing.T) {
	t.Parallel()

	resolver := fakeResolver{addresses: map[string][]netip.Addr{
		"blocked.example": {netip.MustParseAddr("192.0.2.1")},
	}}

	networkPolicy, err := policy.New(
		context.Background(),
		nil,
		[]string{"blocked.example"},
		policy.Options{Resolver: resolver},
	)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	dial := func(_ context.Context, _, _ string) (net.Conn, error) {
		t.Fatal("dialer called for denied address")

		return nil, nil
	}

	destination, err := policy.ParseDestination("blocked.example")
	if err != nil {
		t.Fatalf("policy.ParseDestination: %v", err)
	}

	connection, err := NewDirect(networkPolicy, resolver, dial).Dial(context.Background(), destination, 443)
	if connection != nil {
		_ = connection.Close()

		t.Fatal("Dial returned a connection for denied address")
	}

	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Dial error = %v, want ErrDenied", err)
	}
}
