package policy

import (
	"fmt"
	"net/netip"
)

// Destination is a strictly classified hostname or IP literal.
type Destination struct {
	hostname string
	address  netip.Addr
}

// ParseDestination classifies a complete destination without a port.
func ParseDestination(rawDestination string) (Destination, error) {
	address, addressErr := netip.ParseAddr(rawDestination)
	if addressErr == nil {
		if address.Zone() != "" {
			return Destination{}, fmt.Errorf("destination IP address has a zone identifier")
		}

		return Destination{address: address.Unmap()}, nil
	}

	hostname, err := NormalizeHostname(rawDestination)
	if err != nil {
		return Destination{}, fmt.Errorf("parse destination hostname: %w", err)
	}

	return Destination{hostname: hostname}, nil
}

// IsHostname reports whether the destination is a hostname rather than an IP literal.
func (destination Destination) IsHostname() bool {
	return destination.hostname != ""
}

// Hostname returns the normalized hostname, or an empty string for an IP destination.
func (destination Destination) Hostname() string {
	return destination.hostname
}

// Address returns the canonical IP address, or an invalid address for a hostname destination.
func (destination Destination) Address() netip.Addr {
	return destination.address
}
