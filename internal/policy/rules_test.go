//nolint:goconst // Repeated literals make the parser test cases easier to compare.
package policy

import (
	"net/netip"
	"testing"
)

func TestParseRulesClassifiesStrictly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		raw           string
		hostname      string
		wildcard      bool
		address       string
		prefix        string
		port          uint16
		portSpecified bool
	}{
		{name: "exact hostname", raw: "Example.COM.", hostname: "example.com"},
		{name: "numeric hostname", raw: "127.1", hostname: "127.1"},
		{name: "integer hostname", raw: "2130706433", hostname: "2130706433"},
		{
			name:          "wildcard with port",
			raw:           "*.example.com:443",
			hostname:      "example.com",
			wildcard:      true,
			port:          443,
			portSpecified: true,
		},
		{name: "IPv4", raw: "127.0.0.1", address: "127.0.0.1"},
		{name: "IPv4 with port", raw: "127.0.0.1:80", address: "127.0.0.1", port: 80, portSpecified: true},
		{name: "IPv6", raw: "2001:db8::1", address: "2001:db8::1"},
		{name: "IPv6 with port", raw: "[2001:db8::1]:443", address: "2001:db8::1", port: 443, portSpecified: true},
		{name: "ambiguous raw IPv6 remains address", raw: "2001:db8::1:443", address: "2001:db8::1:443"},
		{name: "IPv4 prefix", raw: "10.0.0.0/8", prefix: "10.0.0.0/8"},
		{name: "IPv4 prefix with port", raw: "10.0.0.0/8:443", prefix: "10.0.0.0/8", port: 443, portSpecified: true},
		{name: "IPv6 prefix with port", raw: "[2001:db8::/32]:443", prefix: "2001:db8::/32", port: 443, portSpecified: true},
		{name: "mapped IPv4", raw: "::ffff:127.0.0.1", address: "127.0.0.1"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			rules, err := parseRules([]string{test.raw})
			if err != nil {
				t.Fatalf("parseRules(%q): %v", test.raw, err)
			}

			switch {
			case test.hostname != "":
				if len(rules.hosts) != 1 {
					t.Fatalf("host rule count = %d, want 1", len(rules.hosts))
				}

				rule := rules.hosts[0]
				if rule.hostname != test.hostname || rule.wildcard != test.wildcard {
					t.Errorf("host rule = %#v, want hostname %q wildcard %t", rule, test.hostname, test.wildcard)
				}

				checkPort(t, rule.port, test.port, test.portSpecified)
			case test.address != "":
				if len(rules.addresses) != 1 {
					t.Fatalf("address rule count = %d, want 1", len(rules.addresses))
				}

				rule := rules.addresses[0]
				if rule.address.String() != test.address {
					t.Errorf("address = %q, want %q", rule.address, test.address)
				}

				checkPort(t, rule.port, test.port, test.portSpecified)
			case test.prefix != "":
				if len(rules.prefixes) != 1 {
					t.Fatalf("prefix rule count = %d, want 1", len(rules.prefixes))
				}

				rule := rules.prefixes[0]
				if rule.prefix.String() != test.prefix {
					t.Errorf("prefix = %q, want %q", rule.prefix, test.prefix)
				}

				checkPort(t, rule.port, test.port, test.portSpecified)
			}
		})
	}
}

func TestParseRulesRejectsInvalidRules(t *testing.T) {
	t.Parallel()

	invalidRules := []string{
		"",
		"foo:",
		"foo:abc",
		"foo:0",
		"foo:65536",
		"*:443",
		"*foo.com",
		"foo.*.com",
		"foo.*",
		".",
		"..",
		"foo..com",
		"foo_bar.example",
		"-foo.example",
		"foo-.example",
		"[2001:db8::1",
		"[2001:db8::1]",
		"[example.com]:443",
		"[2001:db8::1]:abc",
		"10.1.2.3/8",
		"fe80::1%eth0",
	}

	for _, rawRule := range invalidRules {
		t.Run(rawRule, func(t *testing.T) {
			t.Parallel()

			_, err := parseRules([]string{rawRule})
			if err == nil {
				t.Fatalf("parseRules(%q) unexpectedly succeeded", rawRule)
			}
		})
	}
}

func TestNormalizeHostname(t *testing.T) {
	t.Parallel()

	tests := []struct {
		raw  string
		want string
	}{
		{raw: "EXAMPLE.COM.", want: "example.com"},
		{raw: "localhost", want: "localhost"},
		{raw: "127.1", want: "127.1"},
		{raw: "bücher.example", want: "xn--bcher-kva.example"},
	}

	for _, test := range tests {
		t.Run(test.raw, func(t *testing.T) {
			t.Parallel()

			got, err := NormalizeHostname(test.raw)
			if err != nil {
				t.Fatalf("NormalizeHostname(%q): %v", test.raw, err)
			}

			if got != test.want {
				t.Errorf("NormalizeHostname(%q) = %q, want %q", test.raw, got, test.want)
			}
		})
	}
}

func TestParseDestinationKeepsLegacyNumericHostnamesTyped(t *testing.T) {
	t.Parallel()

	destination, err := ParseDestination("127.1")
	if err != nil {
		t.Fatalf("ParseDestination: %v", err)
	}

	if !destination.IsHostname() {
		t.Fatal("127.1 was classified as an IP address")
	}

	if destination.Hostname() != "127.1" {
		t.Errorf("hostname = %q, want 127.1", destination.Hostname())
	}

	if destination.Address().IsValid() {
		t.Errorf("address = %s, want invalid address", destination.Address())
	}

	ipDestination, err := ParseDestination("127.0.0.1")
	if err != nil {
		t.Fatalf("ParseDestination: %v", err)
	}

	if ipDestination.IsHostname() {
		t.Fatal("127.0.0.1 was classified as a hostname")
	}

	if ipDestination.Address() != netip.MustParseAddr("127.0.0.1") {
		t.Errorf("address = %s, want 127.0.0.1", ipDestination.Address())
	}
}

func checkPort(t *testing.T, got portMatcher, want uint16, specified bool) {
	t.Helper()

	if got.port != want || got.set != specified {
		t.Errorf("port = %#v, want port %d specified %t", got, want, specified)
	}
}
