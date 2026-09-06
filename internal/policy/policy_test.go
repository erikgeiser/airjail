//nolint:goconst // Repeated policy literals keep each scenario self-contained.
package policy

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/erikgeiser/airjail/internal/logging"
)

type fakeResolver struct {
	addresses map[string][]netip.Addr
	errors    map[string]error
	lookups   []string
}

func (resolver *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	if network != "ip" {
		return nil, fmt.Errorf("unexpected network %q", network)
	}

	resolver.lookups = append(resolver.lookups, host)

	err := resolver.errors[host]
	if err != nil {
		return nil, err
	}

	return slices.Clone(resolver.addresses[host]), nil
}

func TestPolicySemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowRules []string
		blockRules []string
		hostname   string
		address    string
		port       uint16
		want       bool
	}{
		{name: "empty denies", hostname: "example.com", address: "192.0.2.1", port: 443, want: false},
		{
			name:       "block-only defaults allow",
			blockRules: []string{"blocked.example"},
			hostname:   "other.example",
			port:       443,
			want:       true,
		},
		{
			name:       "block-only denies match",
			blockRules: []string{"blocked.example"},
			hostname:   "blocked.example",
			port:       443,
			want:       false,
		},
		{
			name:       "allow-only defaults deny",
			allowRules: []string{"allowed.example"},
			hostname:   "other.example",
			port:       443,
			want:       false,
		},
		{
			name:       "allow-only permits match",
			allowRules: []string{"allowed.example"},
			hostname:   "ALLOWED.EXAMPLE.",
			port:       443,
			want:       true,
		},
		{
			name:       "block vetoes allow",
			allowRules: []string{"*.example"},
			blockRules: []string{"bad.example"},
			hostname:   "bad.example",
			port:       443,
			want:       false,
		},
		{name: "wildcard arbitrary depth", allowRules: []string{"*.example"}, hostname: "a.b.example", port: 443, want: true},
		{name: "wildcard excludes apex", allowRules: []string{"*.example"}, hostname: "example", port: 443, want: false},
		{
			name:       "exact excludes subdomain",
			allowRules: []string{"example.com"},
			hostname:   "www.example.com",
			port:       443,
			want:       false,
		},
		{name: "matching port", allowRules: []string{"example.com:443"}, hostname: "example.com", port: 443, want: true},
		{name: "different port", allowRules: []string{"example.com:443"}, hostname: "example.com", port: 80, want: false},
		{name: "CIDR match", allowRules: []string{"192.0.2.0/24"}, address: "192.0.2.10", port: 80, want: true},
		{name: "CIDR miss", allowRules: []string{"192.0.2.0/24"}, address: "198.51.100.10", port: 80, want: false},
		{name: "CIDR port veto", blockRules: []string{"192.0.2.0/24:80"}, address: "192.0.2.10", port: 80, want: false},
		{name: "CIDR other port", blockRules: []string{"192.0.2.0/24:80"}, address: "192.0.2.10", port: 443, want: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			resolver := &fakeResolver{addresses: map[string][]netip.Addr{}, errors: map[string]error{}}

			for _, rule := range append(slices.Clone(test.allowRules), test.blockRules...) {
				destination, parseErr := ParseDestination(rule)
				if parseErr == nil && destination.IsHostname() {
					resolver.addresses[destination.Hostname()] = []netip.Addr{netip.MustParseAddr("203.0.113.1")}
				}
			}

			policy, err := New(context.Background(), test.allowRules, test.blockRules, Options{
				Resolver:        resolver,
				AllowUnresolved: true,
			})
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			var address netip.Addr
			if test.address != "" {
				address = netip.MustParseAddr(test.address)
			}

			got, err := policy.Allows(test.hostname, address, test.port)
			if err != nil {
				t.Fatalf("Allows: %v", err)
			}

			if got != test.want {
				t.Errorf("Allows() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestExactHostnameExpansionAppliesToDirectIP(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{
			"service.example": {netip.MustParseAddr("192.0.2.10")},
		},
		errors: map[string]error{},
	}

	policy, err := New(context.Background(), []string{"service.example"}, nil, Options{Resolver: resolver})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allowed, err := policy.Allows("", netip.MustParseAddr("192.0.2.10"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("resolved address was not allowed")
	}
}

func TestResolvedAddressBlockVetoesHostnameAllow(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{
			"service.example": {netip.MustParseAddr("10.0.0.1")},
		},
		errors: map[string]error{},
	}

	policy, err := New(
		context.Background(),
		[]string{"service.example"},
		[]string{"10.0.0.0/8"},
		Options{Resolver: resolver},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allowed, err := policy.Allows("service.example", netip.MustParseAddr("10.0.0.1"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if allowed {
		t.Fatal("blocked resolved address was allowed")
	}
}

func TestLegacyNumericHostnameRetainsTypeWhileExpanding(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{
			"127.1": {netip.MustParseAddr("127.0.0.1")},
		},
		errors: map[string]error{},
	}

	policy, err := New(context.Background(), []string{"127.1"}, nil, Options{Resolver: resolver})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if len(policy.allow.hosts) != 1 || policy.allow.hosts[0].hostname != "127.1" {
		t.Fatalf("parsed hostname rules = %#v, want typed hostname 127.1", policy.allow.hosts)
	}

	if len(policy.allow.addresses) != 0 {
		t.Fatalf("explicit address rules = %#v, want none", policy.allow.addresses)
	}

	allowed, err := policy.Allows("", netip.MustParseAddr("127.0.0.1"), 80)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("resolved expansion did not apply")
	}
}

func TestUnresolvedHostnamePolicy(t *testing.T) {
	t.Parallel()

	lookupError := fmt.Errorf("name not found")

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{},
		errors:    map[string]error{"missing.example": lookupError},
	}

	_, err := New(context.Background(), []string{"missing.example"}, nil, Options{Resolver: resolver})
	if err == nil {
		t.Fatal("New unexpectedly accepted an unresolved rule")
	}

	var warningOutput bytes.Buffer

	logger, err := logging.New(&warningOutput, "warning", "")
	if err != nil {
		t.Fatalf("create logger: %v", err)
	}

	policy, err := New(context.Background(), []string{"missing.example"}, nil, Options{
		Resolver:        resolver,
		AllowUnresolved: true,
		Logger:          logger,
	})
	if err != nil {
		t.Fatalf("New with AllowUnresolved: %v", err)
	}

	wantWarning := "airjail: warning: hostname rule \"missing.example\" did not resolve: name not found\n"
	if warningOutput.String() != wantWarning {
		t.Fatalf("warning output = %q, want %q", warningOutput.String(), wantWarning)
	}

	allowed, err := policy.Allows("missing.example", netip.Addr{}, 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("unresolved hostname-only rule did not match")
	}
}

type chainResolverFunc func(context.Context, string, string) (ResolutionResult, error)

func (resolver chainResolverFunc) Resolve(
	ctx context.Context,
	network string,
	hostname string,
) (ResolutionResult, error) {
	return resolver(ctx, network, hostname)
}

func TestStartupExpansionPreservesCompleteCNAMEChain(t *testing.T) {
	t.Parallel()

	resolver := chainResolverFunc(func(_ context.Context, network, hostname string) (ResolutionResult, error) {
		if network != "ip" || hostname != "example.com" {
			return ResolutionResult{}, fmt.Errorf("unexpected resolution %s %s", network, hostname)
		}

		return ResolutionResult{
			CNAMEChain: []string{"edge.cdn.test", "region.cdn.test"},
			Addresses:  []netip.Addr{netip.MustParseAddr("192.0.2.10")},
		}, nil
	})

	networkPolicy, err := New(context.Background(), []string{"example.com:443"}, nil, Options{
		ChainResolver: resolver,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, hostname := range []string{"example.com", "edge.cdn.test", "region.cdn.test"} {
		allowed, allowErr := networkPolicy.Allows(hostname, netip.MustParseAddr("192.0.2.10"), 443)
		if allowErr != nil {
			t.Fatalf("Allows(%s): %v", hostname, allowErr)
		}

		if !allowed {
			t.Errorf("CNAME chain hostname %s was not allowed", hostname)
		}
	}

	allowed, err := networkPolicy.Allows("region.cdn.test", netip.MustParseAddr("192.0.2.10"), 80)
	if err != nil {
		t.Fatalf("Allows(other port): %v", err)
	}

	if allowed {
		t.Fatal("CNAME expansion lost its source port restriction")
	}
}

func TestStartupCNAMEBlockVetoesOriginalHostnameConnection(t *testing.T) {
	t.Parallel()

	resolver := chainResolverFunc(func(_ context.Context, _ string, hostname string) (ResolutionResult, error) {
		switch hostname {
		case "example.com":
			return ResolutionResult{
				CNAMEChain: []string{"blocked.cdn.test"},
				Addresses:  []netip.Addr{netip.MustParseAddr("192.0.2.10")},
			}, nil
		default:
			return ResolutionResult{}, fmt.Errorf("unexpected resolution for %s", hostname)
		}
	})

	networkPolicy, err := New(
		context.Background(),
		[]string{"example.com"},
		[]string{"*.cdn.test"},
		Options{ChainResolver: resolver},
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	allowed, err := networkPolicy.Allows("example.com", netip.MustParseAddr("192.0.2.10"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if allowed {
		t.Fatal("CNAME hostname block did not veto the original hostname connection")
	}
}

func TestHostnameExpansionIsLoggedAtInfoLevel(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{
			"service.example": {netip.MustParseAddr("192.0.2.10")},
		},
		errors: map[string]error{},
	}

	var output bytes.Buffer

	logger, err := logging.New(&output, "info", "")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	_, err = New(context.Background(), []string{"service.example:443"}, nil, Options{
		Resolver: resolver,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	want := "expanded allow rule service.example:443 to 192.0.2.10:443"
	if !strings.Contains(output.String(), want) {
		t.Errorf("log output = %q, want it to contain %q", output.String(), want)
	}
}

func TestResolverResultsAreCanonicalizedAndDeduplicated(t *testing.T) {
	t.Parallel()

	resolver := &fakeResolver{
		addresses: map[string][]netip.Addr{
			"service.example": {
				netip.MustParseAddr("::ffff:192.0.2.1"),
				netip.MustParseAddr("192.0.2.1"),
				{},
			},
		},
		errors: map[string]error{},
	}

	policy, err := New(context.Background(), []string{"service.example"}, nil, Options{Resolver: resolver})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	got := policy.allow.hosts[0].resolved

	want := []netip.Addr{netip.MustParseAddr("192.0.2.1")}
	if !slices.Equal(got, want) {
		t.Errorf("resolved addresses = %v, want %v", got, want)
	}
}
