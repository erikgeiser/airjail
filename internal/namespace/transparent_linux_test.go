package namespace

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"testing"
	"unsafe"

	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
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

func TestTransparentDNSUDPDestinationNAT(t *testing.T) {
	t.Parallel()

	gateway := netip.MustParseAddr("127.97.105.114")

	expressions := transparentDNSUDPExpressions(gateway, unix.NFPROTO_IPV4)
	if len(expressions) != 7 {
		t.Fatalf("expression count = %d, want 7", len(expressions))
	}

	destinationPort, ok := expressions[2].(*expr.Payload)
	if !ok || destinationPort.Base != expr.PayloadBaseTransportHeader ||
		destinationPort.Offset != 2 || destinationPort.Len != 2 {
		t.Fatalf("destination-port expression = %#v", expressions[2])
	}

	translatedAddress, ok := expressions[4].(*expr.Immediate)
	if !ok || !slices.Equal(translatedAddress.Data, gateway.AsSlice()) {
		t.Fatalf("translated-address expression = %#v", expressions[4])
	}

	translatedPort, ok := expressions[5].(*expr.Immediate)
	if !ok || !slices.Equal(translatedPort.Data, binaryutil.BigEndian.PutUint16(dnsPort)) {
		t.Fatalf("translated-port expression = %#v", expressions[5])
	}

	translation, ok := expressions[6].(*expr.NAT)
	if !ok || translation.Type != expr.NATTypeDestNAT || translation.Family != unix.NFPROTO_IPV4 ||
		translation.RegAddrMin != 1 || translation.RegProtoMin != 2 {
		t.Fatalf("destination-NAT expression = %#v", expressions[6])
	}

	for _, expression := range expressions {
		payload, isPayload := expression.(*expr.Payload)
		if isPayload && payload.OperationType == expr.PayloadWrite {
			t.Fatalf("DNS destination NAT contains a payload-write expression: %#v", payload)
		}
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
