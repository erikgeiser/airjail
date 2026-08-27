// Package outbound establishes policy-approved connections from the outer namespace.
package outbound

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"

	"github.com/erikgeiser/airjail/internal/policy"
)

// ErrDenied indicates that policy rejected every usable destination address.
var ErrDenied = errors.New("destination denied by policy")

// DialFunc is compatible with net.Dialer's DialContext method.
type DialFunc func(ctx context.Context, network, address string) (net.Conn, error)

// AddressDialFunc connects to one already-approved concrete address.
type AddressDialFunc func(ctx context.Context, hostname string, address netip.Addr, port uint16) (net.Conn, error)

// Direct resolves policy targets and routes only approved concrete addresses.
type Direct struct {
	policy      *policy.Policy
	resolver    policy.Resolver
	dialAddress AddressDialFunc
	logDecision func(allowed bool, hostname string, address netip.Addr, port uint16)
}

// NewDirect creates a connector using a conventional network dialer. It is primarily useful in tests.
func NewDirect(networkPolicy *policy.Policy, resolver policy.Resolver, dial DialFunc) *Direct {
	if dial == nil {
		netDialer := &net.Dialer{Timeout: connectTimeout}
		dial = netDialer.DialContext
	}

	return NewRouted(networkPolicy, resolver, func(
		ctx context.Context,
		_ string,
		address netip.Addr,
		port uint16,
	) (net.Conn, error) {
		return dial(ctx, "tcp", net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
	})
}

// NewRouted creates a connector using route for approved addresses.
func NewRouted(networkPolicy *policy.Policy, resolver policy.Resolver, route AddressDialFunc) *Direct {
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	return &Direct{policy: networkPolicy, resolver: resolver, dialAddress: route}
}

// LogDecisions installs an optional per-address policy decision callback.
func (direct *Direct) LogDecisions(logger func(bool, string, netip.Addr, uint16)) {
	direct.logDecision = logger
}

// Dial connects to a strictly parsed destination after checking the concrete dialed address.
func (direct *Direct) Dial(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error) {
	if direct.policy == nil {
		return nil, fmt.Errorf("dial destination: network policy is nil")
	}

	if port == 0 {
		return nil, fmt.Errorf("dial destination: port must be from 1 through 65535")
	}

	if !destination.IsHostname() {
		return direct.dialLiteral(ctx, destination.RoutingAddress(), port)
	}

	addresses, err := direct.resolver.LookupNetIP(ctx, "ip", destination.Hostname())
	if err != nil {
		return nil, fmt.Errorf("resolve destination %q: %w", destination.Hostname(), err)
	}

	var lastDialError error

	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			continue
		}

		address = address.Unmap()
		if _, found := seen[address]; found {
			continue
		}

		seen[address] = struct{}{}

		allowed, policyErr := direct.policy.Allows(destination.Hostname(), address, port)
		if policyErr != nil {
			return nil, fmt.Errorf("evaluate destination policy: %w", policyErr)
		}

		if direct.logDecision != nil {
			direct.logDecision(allowed, destination.Hostname(), address, port)
		}

		if !allowed {
			continue
		}

		connection, dialErr := direct.dialAddress(ctx, destination.Hostname(), address, port)
		if dialErr == nil {
			return connection, nil
		}

		lastDialError = dialErr
	}

	if lastDialError != nil {
		return nil, fmt.Errorf("dial approved addresses for %q: %w", destination.Hostname(), lastDialError)
	}

	return nil, fmt.Errorf("%w: %s:%d", ErrDenied, destination.Hostname(), port)
}

func (direct *Direct) dialLiteral(ctx context.Context, address netip.Addr, port uint16) (net.Conn, error) {
	policyAddress := address.WithZone("")

	allowed, err := direct.policy.Allows("", policyAddress, port)
	if err != nil {
		return nil, fmt.Errorf("evaluate destination policy: %w", err)
	}

	if direct.logDecision != nil {
		direct.logDecision(allowed, "", address, port)
	}

	if !allowed {
		return nil, fmt.Errorf("%w: %s", ErrDenied, net.JoinHostPort(address.String(), strconv.Itoa(int(port))))
	}

	connection, err := direct.dialAddress(ctx, "", address, port)
	if err != nil {
		return nil, fmt.Errorf("dial destination %s: %w", address, err)
	}

	return connection, nil
}
