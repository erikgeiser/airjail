package namespace

import (
	"net"
	"net/netip"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestHasIPv6EgressRoute(t *testing.T) {
	t.Parallel()

	for _, test := range []struct {
		name        string
		destination string
		routeType   int
		want        bool
	}{
		{name: "nil default", routeType: unix.RTN_UNICAST, want: true},
		{name: "explicit default", destination: "::/0", routeType: unix.RTN_UNICAST, want: true},
		{name: "global prefix", destination: "2001:db8::/32", routeType: unix.RTN_UNICAST, want: true},
		{name: "private network", destination: "fd00::/64", routeType: unix.RTN_UNICAST, want: true},
		{name: "loopback", destination: "::1/128", routeType: unix.RTN_UNICAST},
		{name: "unspecified", destination: "::/128", routeType: unix.RTN_UNICAST},
		{name: "link-local", destination: "fe80::/64", routeType: unix.RTN_UNICAST},
		{name: "link-local host", destination: "fe80::1/128", routeType: unix.RTN_UNICAST},
		{name: "multicast", destination: "ff00::/8", routeType: unix.RTN_UNICAST},
		{name: "broader than link-local", destination: "fe80::/9", routeType: unix.RTN_UNICAST, want: true},
		{name: "local route", destination: "2001:db8::1/128", routeType: unix.RTN_LOCAL},
		{name: "unreachable default", routeType: unix.RTN_UNREACHABLE},
		{name: "prohibited default", routeType: unix.RTN_PROHIBIT},
		{name: "blackhole default", routeType: unix.RTN_BLACKHOLE},
		{name: "IPv4", destination: "0.0.0.0/0", routeType: unix.RTN_UNICAST},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			route := netlink.Route{Type: test.routeType}
			if test.destination != "" {
				prefix := netip.MustParsePrefix(test.destination)
				route.Dst = &net.IPNet{IP: prefix.Addr().AsSlice(), Mask: net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())}
			}

			// Local routes must not hide a qualifying route later in the dump.
			routes := []netlink.Route{{Type: unix.RTN_LOCAL}, route}
			if got := hasIPv6EgressRoute(routes); got != test.want {
				t.Errorf("IPv6 egress route = %t, want %t", got, test.want)
			}
		})
	}

	if hasIPv6EgressRoute(nil) {
		t.Error("empty routing table enabled IPv6 interception")
	}
}
