package outbound

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/erikgeiser/airjail/internal/logging"
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

	var logOutput bytes.Buffer

	logger, err := logging.New(&logOutput, "traffic", "")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	connection, err := NewDirect(networkPolicy, resolver, dial, logger).Dial(context.Background(), destination, 443)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	if dialedAddress != "192.0.2.10:443" {
		t.Errorf("dialed address = %q, want 192.0.2.10:443", dialedAddress)
	}

	wantLog := "airjail: blocked: tcp service.example:443 (10.0.0.1)\n" +
		"airjail: allowed: tcp service.example:443 (192.0.2.10)\n"
	if logOutput.String() != wantLog {
		t.Errorf("log output = %q, want %q", logOutput.String(), wantLog)
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

	connection, err := NewDirect(networkPolicy, resolver, dial, nil).Dial(context.Background(), destination, 80)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	if dialedAddress != "127.0.0.1:80" {
		t.Errorf("dialed address = %q, want 127.0.0.1:80", dialedAddress)
	}
}

func TestDirectChecksScopedIPv6WithoutZoneAndRoutesWithZone(t *testing.T) {
	t.Parallel()

	networkPolicy, err := policy.New(context.Background(), []string{"fe80::1"}, nil, policy.Options{})
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	var routedAddress netip.Addr

	route := func(_ context.Context, _ string, address netip.Addr, _ uint16) (net.Conn, error) {
		routedAddress = address

		client, server := net.Pipe()

		t.Cleanup(func() { _ = server.Close() })

		return client, nil
	}

	destination, err := policy.ParseDestination("fe80::1%eth0")
	if err != nil {
		t.Fatalf("policy.ParseDestination: %v", err)
	}

	connection, err := NewRouted(networkPolicy, nil, route, nil).Dial(context.Background(), destination, 443)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	t.Cleanup(func() { _ = connection.Close() })

	if routedAddress != netip.MustParseAddr("fe80::1%eth0") {
		t.Errorf("routed address = %s, want fe80::1%%eth0", routedAddress)
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

	connection, err := NewDirect(networkPolicy, resolver, dial, nil).Dial(context.Background(), destination, 443)
	if connection != nil {
		_ = connection.Close()

		t.Fatal("Dial returned a connection for denied address")
	}

	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Dial error = %v, want ErrDenied", err)
	}
}
