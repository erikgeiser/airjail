//nolint:goconst // Literal targets make policy scenarios self-contained.
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

	connection, err := NewDirect(networkPolicy, resolver, dial, nil).Dial(t.Context(), destination, 443)
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

type resolutionTrackingResolver struct {
	lookups []string
}

func (resolver *resolutionTrackingResolver) LookupNetIP(
	_ context.Context,
	network string,
	host string,
) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}

	resolver.lookups = append(resolver.lookups, host)

	return nil, nil
}

func TestDirectRejectsHostnameBeforeResolution(t *testing.T) {
	t.Parallel()

	resolver := &resolutionTrackingResolver{}

	networkPolicy, err := policy.New(
		context.Background(),
		[]string{"allowed.example"},
		nil,
		policy.Options{Resolver: resolver, AllowUnresolved: true},
	)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	resolver.lookups = nil

	destination, err := policy.ParseDestination("data.c2.example")
	if err != nil {
		t.Fatalf("policy.ParseDestination: %v", err)
	}

	connection, err := NewDirect(networkPolicy, resolver, nil, nil).Dial(t.Context(), destination, 443)
	if connection != nil {
		_ = connection.Close()

		t.Fatal("Dial returned a connection for denied hostname")
	}

	if !errors.Is(err, ErrDenied) {
		t.Fatalf("Dial error = %v, want ErrDenied", err)
	}

	if len(resolver.lookups) != 0 {
		t.Fatalf("denied hostname reached resolver: %v", resolver.lookups)
	}
}

func TestDirectNeverDialsDeniedTargets(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name   string
		block  []string
		target string
	}{
		{name: "empty policy", target: "192.0.2.1"},
		{name: "hostname", block: []string{"blocked.example@192.0.2.1"}, target: "blocked.example"},
		{name: "expanded IP", block: []string{"blocked.example@192.0.2.1"}, target: "192.0.2.1"},
		{name: "IPv4 prefix", block: []string{"192.0.2.0/24"}, target: "192.0.2.1"},
		{name: "IPv6 literal", block: []string{"2001:db8::1"}, target: "2001:db8::1"},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkPolicy, err := policy.New(t.Context(), nil, test.block, policy.Options{})
			if err != nil {
				t.Fatalf("create policy: %v", err)
			}

			dialed := false
			dial := func(context.Context, string, string) (net.Conn, error) {
				dialed = true

				return nil, fmt.Errorf("unexpected dial")
			}

			destination, err := policy.ParseDestination(test.target)
			if err != nil {
				t.Fatalf("parse target: %v", err)
			}

			connection, err := NewDirect(networkPolicy, nil, dial, nil).Dial(t.Context(), destination, 443)
			if connection != nil {
				_ = connection.Close()

				t.Error("denied target returned a connection")
			}

			if dialed || !errors.Is(err, ErrDenied) {
				t.Fatalf("denied target: dialed=%t, error=%v", dialed, err)
			}
		})
	}
}
