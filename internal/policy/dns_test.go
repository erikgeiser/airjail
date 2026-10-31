//nolint:goconst // Complete policy scenarios are easier to compare without shared rule constants.
package policy

import (
	"net/netip"
	"testing"
	"time"
)

func TestRuntimeDNSGrantsRetainSourcePortsAndExpire(t *testing.T) {
	t.Parallel()

	networkPolicy := newDNSPolicy(t, []string{"*.example.com:443"}, nil)
	now := time.Now()
	expires := now.Add(time.Hour)
	address := netip.MustParseAddr("192.0.2.30")

	authorization, allowed, err := networkPolicy.BeginResolution("service.example.com", now)
	if err != nil || !allowed {
		t.Fatalf("authorize source name = %t, %v", allowed, err)
	}

	_, allowed, err = networkPolicy.BeginResolution("cdn.test", now)
	if err != nil || allowed {
		t.Fatalf("unlearned alias authorization = %t, %v", allowed, err)
	}

	_, err = networkPolicy.CommitResolution(authorization, ResolutionResult{
		CNAMEChain: []string{"cdn.test"},
		Addresses:  []netip.Addr{address},
		ExpiresAt:  expires,
	}, now)
	if err != nil {
		t.Fatalf("install resolution: %v", err)
	}

	aliasAuthorization, allowed, err := networkPolicy.BeginResolution("cdn.test", now)
	if err != nil || !allowed {
		t.Fatalf("learned alias authorization = %t, %v", allowed, err)
	}

	aliasAddress := netip.MustParseAddr("192.0.2.31")

	_, err = networkPolicy.CommitResolution(aliasAuthorization, ResolutionResult{
		Addresses: []netip.Addr{aliasAddress},
		ExpiresAt: expires,
	}, now)
	if err != nil {
		t.Fatalf("install alias resolution: %v", err)
	}

	for _, target := range []netip.Addr{address, aliasAddress} {
		for _, port := range []uint16{443, 80} {
			allowed, err = networkPolicy.Allows("", target, port)
			if err != nil || allowed != (port == 443) {
				t.Errorf("live grant for %s:%d = %t, %v", target, port, allowed, err)
			}
		}
	}

	// Advance through the existing time-aware resolution API, without sleeps.
	_, allowed, err = networkPolicy.BeginResolution("cdn.test", expires.Add(time.Second))
	if err != nil || allowed {
		t.Fatalf("expired alias authorization = %t, %v", allowed, err)
	}

	for _, target := range []netip.Addr{address, aliasAddress} {
		allowed, err = networkPolicy.Allows("", target, 443)
		if err != nil || allowed {
			t.Errorf("expired grant for %s = %t, %v", target, allowed, err)
		}
	}
}

func TestDNSResolutionPreservesBlockScopeAndLifetime(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		block       string
		port        uint16
		want        bool
		afterExpiry bool
	}{
		{name: "address veto", block: "192.0.2.1:443", port: 443},
		{name: "address veto other port", block: "192.0.2.1:443", port: 80, want: true, afterExpiry: true},
		{name: "CNAME veto", block: "*.cdn.test:443", port: 443, afterExpiry: true},
		{name: "CNAME veto other port", block: "*.cdn.test:443", port: 80, want: true, afterExpiry: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkPolicy := newDNSPolicy(t, []string{"*.example.com", "192.0.2.0/24"}, []string{test.block})
			now := time.Now()
			address := netip.MustParseAddr("192.0.2.1")

			authorization, allowed, err := networkPolicy.BeginResolution("service.example.com", now)
			if err != nil || !allowed {
				t.Fatalf("authorize query = %t, %v", allowed, err)
			}

			_, err = networkPolicy.CommitResolution(authorization, ResolutionResult{
				CNAMEChain: []string{"edge.cdn.test"},
				Addresses:  []netip.Addr{address},
				ExpiresAt:  now.Add(time.Hour),
			}, now)
			if err != nil {
				t.Fatalf("install resolution: %v", err)
			}

			allowed, err = networkPolicy.Allows("", address, test.port)
			if err != nil || allowed != test.want {
				t.Fatalf("connection on port %d = %t, %v; want %t", test.port, allowed, err, test.want)
			}

			_, _, err = networkPolicy.BeginResolution("service.example.com", now.Add(2*time.Hour))
			if err != nil {
				t.Fatalf("expire DNS state: %v", err)
			}

			allowed, err = networkPolicy.Allows("", address, test.port)
			if err != nil || allowed != test.afterExpiry {
				t.Errorf("connection after TTL expiration = %t, %v; want %t", allowed, err, test.afterExpiry)
			}
		})
	}
}

func TestDNSAuthorizationIsSeparateFromConnectionPolicy(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name      string
		allow     []string
		block     []string
		arbitrary bool
		wantDNS   bool
	}{
		{name: "address blocklist", block: []string{"192.0.2.1"}},
		{name: "prefix blocklist", block: []string{"192.0.2.0/24"}},
		{name: "mixed blocklist", block: []string{"blocked.example@192.0.2.1", "192.0.2.2"}},
		{name: "address allowlist", allow: []string{"192.0.2.0/24"}},
		{name: "explicit DNS permission", allow: []string{"192.0.2.0/24"}, arbitrary: true, wantDNS: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			networkPolicy, err := New(t.Context(), test.allow, test.block, Options{AllowArbitraryDNS: test.arbitrary})
			if err != nil {
				t.Fatalf("create policy: %v", err)
			}

			now := time.Now()

			authorization, allowed, err := networkPolicy.BeginResolution("data.c2.example", now)
			if err != nil || allowed != test.wantDNS {
				t.Fatalf("DNS authorization = %t, %v; want %t", allowed, err, test.wantDNS)
			}

			if !allowed {
				return
			}

			outsideAllowlist := netip.MustParseAddr("198.51.100.1")

			_, err = networkPolicy.CommitResolution(authorization, ResolutionResult{
				Addresses: []netip.Addr{outsideAllowlist},
				ExpiresAt: now.Add(time.Hour),
			}, now)
			if err != nil {
				t.Fatalf("install arbitrary resolution: %v", err)
			}

			allowed, err = networkPolicy.Allows("", outsideAllowlist, 443)
			if err != nil || allowed {
				t.Fatalf("arbitrary DNS bypassed address policy: %t, %v", allowed, err)
			}
		})
	}
}

func newDNSPolicy(tb testing.TB, allowRules, blockRules []string) *Policy {
	tb.Helper()

	networkPolicy, err := New(tb.Context(), allowRules, blockRules, Options{AllowUnresolved: true,
		Resolver: &fakeResolver{addresses: map[string][]netip.Addr{}, errors: map[string]error{}},
	})
	if err != nil {
		tb.Fatalf("create policy: %v", err)
	}

	return networkPolicy
}
