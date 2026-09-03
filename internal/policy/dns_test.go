//nolint:goconst // Repeated policy literals keep each DNS scenario self-contained.
package policy

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestResolutionPortSemantics(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		allowRules []string
		blockRules []string
		address    string
		want       bool
	}{
		{
			name:       "allowed port blocked",
			allowRules: []string{"example.com:443"},
			blockRules: []string{"192.0.2.1:443"},
			address:    "192.0.2.1",
		},
		{
			name:       "another port remains",
			allowRules: []string{"example.com"},
			blockRules: []string{"192.0.2.1:443"},
			address:    "192.0.2.1",
			want:       true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkPolicy := newDNSPolicy(t, test.allowRules, test.blockRules)
			now := time.Now()

			authorization, allowed, err := networkPolicy.BeginResolution("example.com", now)
			if err != nil {
				t.Fatalf("BeginResolution: %v", err)
			}

			if !allowed {
				t.Fatal("hostname query was unexpectedly denied before resolution")
			}

			allowed, err = networkPolicy.CommitResolution(
				authorization,
				ResolutionResult{
					Addresses: []netip.Addr{netip.MustParseAddr(test.address)},
					ExpiresAt: now.Add(time.Minute),
				},
				now,
			)
			if err != nil {
				t.Fatalf("CommitResolution: %v", err)
			}

			if allowed != test.want {
				t.Errorf("CommitResolution() = %t, want %t", allowed, test.want)
			}
		})
	}
}

func TestResolutionAliasGrantRetainsOriginalPolicy(t *testing.T) {
	t.Parallel()

	networkPolicy := newDNSPolicy(t, []string{"example.com"}, nil)
	now := time.Now()

	authorization, allowed, err := networkPolicy.BeginResolution("example.com", now)
	if err != nil || !allowed {
		t.Fatalf("BeginResolution(example.com) = %t, %v", allowed, err)
	}

	allowed, err = networkPolicy.CommitResolution(
		authorization,
		ResolutionResult{CNAMEChain: []string{"cdn.test"}, ExpiresAt: now.Add(time.Minute)},
		now,
	)
	if err != nil || !allowed {
		t.Fatalf("CommitResolution(CNAME) = %t, %v", allowed, err)
	}

	aliasAuthorization, allowed, err := networkPolicy.BeginResolution("cdn.test", now)
	if err != nil || !allowed {
		t.Fatalf("BeginResolution(cdn.test) = %t, %v", allowed, err)
	}

	address := netip.MustParseAddr("192.0.2.20")

	allowed, err = networkPolicy.CommitResolution(
		aliasAuthorization,
		ResolutionResult{Addresses: []netip.Addr{address}, ExpiresAt: now.Add(time.Minute)},
		now,
	)
	if err != nil || !allowed {
		t.Fatalf("CommitResolution(address) = %t, %v", allowed, err)
	}

	allowed, err = networkPolicy.Allows("", address, 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("address resolved through CNAME alias was not dynamically allowed")
	}
}

func TestExpiredResolutionGrantIsRemoved(t *testing.T) {
	t.Parallel()

	networkPolicy := newDNSPolicy(t, []string{"*.example.com"}, nil)
	now := time.Now()

	authorization, allowed, err := networkPolicy.BeginResolution("service.example.com", now)
	if err != nil || !allowed {
		t.Fatalf("BeginResolution = %t, %v", allowed, err)
	}

	address := netip.MustParseAddr("192.0.2.30")

	allowed, err = networkPolicy.CommitResolution(
		authorization,
		ResolutionResult{Addresses: []netip.Addr{address}, ExpiresAt: now.Add(-time.Second)},
		now,
	)
	if err != nil || !allowed {
		t.Fatalf("CommitResolution = %t, %v", allowed, err)
	}

	allowed, err = networkPolicy.Allows("", address, 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if allowed {
		t.Fatal("expired DNS grant still allowed a direct address")
	}
}

func newDNSPolicy(t *testing.T, allowRules, blockRules []string) *Policy {
	t.Helper()

	resolver := &fakeResolver{addresses: map[string][]netip.Addr{}, errors: map[string]error{}}

	networkPolicy, err := New(context.Background(), allowRules, blockRules, Options{
		Resolver:        resolver,
		AllowUnresolved: true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return networkPolicy
}
