package namespace

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"unsafe"

	"golang.org/x/sys/unix"
)

func TestParseOriginalDestination(t *testing.T) {
	t.Parallel()

	rawPort := uint16(0)
	binary.BigEndian.PutUint16((*[2]byte)(unsafe.Pointer(&rawPort))[:], 443)

	destination, err := parseOriginalDestination(
		unix.AF_INET,
		unix.AF_INET,
		uint32(unsafe.Sizeof(unix.RawSockaddrInet4{})),
		uint32(unsafe.Sizeof(unix.RawSockaddrInet4{})),
		rawPort,
		netip.MustParseAddr("192.0.2.1"),
	)
	if err != nil {
		t.Fatalf("parseOriginalDestination: %v", err)
	}

	if destination != netip.MustParseAddrPort("192.0.2.1:443") {
		t.Errorf("destination = %s, want 192.0.2.1:443", destination)
	}
}

func TestParseOriginalDestinationRejectsMalformedAddress(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		family         uint16
		expected       uint16
		addressLength  uint32
		expectedLength uint32
		port           uint16
	}{
		{name: "wrong family", family: unix.AF_INET6, expected: unix.AF_INET, addressLength: 16, expectedLength: 16, port: 1},
		{name: "short address", family: unix.AF_INET, expected: unix.AF_INET, addressLength: 8, expectedLength: 16, port: 1},
		{name: "zero port", family: unix.AF_INET, expected: unix.AF_INET, addressLength: 16, expectedLength: 16},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := parseOriginalDestination(
				test.family,
				test.expected,
				test.addressLength,
				test.expectedLength,
				test.port,
				netip.MustParseAddr("192.0.2.1"),
			)
			if err == nil {
				t.Fatal("parseOriginalDestination unexpectedly accepted malformed input")
			}
		})
	}
}

func TestInternalEndpoints(t *testing.T) {
	t.Parallel()

	tests := []struct {
		destination string
		want        bool
	}{
		{destination: "127.97.105.114:19080", want: true},
		{destination: "127.97.105.114:19081", want: true},
		{destination: "127.97.105.114:19082", want: true},
		{destination: "127.97.105.114:19053", want: true},
		{destination: "[fd61:6972:6a61:696c::1]:19082", want: true},
		{destination: "[fd61:6972:6a61:696c::1]:19053", want: true},
		{destination: "127.0.0.1:19080"},
		{destination: "127.97.105.114:443"},
	}

	for _, test := range tests {
		t.Run(test.destination, func(t *testing.T) {
			t.Parallel()

			got := isInternalEndpoint(netip.MustParseAddrPort(test.destination))
			if got != test.want {
				t.Errorf("isInternalEndpoint() = %t, want %t", got, test.want)
			}
		})
	}
}
