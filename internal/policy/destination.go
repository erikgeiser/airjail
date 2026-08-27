package policy

import (
	"fmt"
	"net/netip"
)

// Destination is a strictly classified hostname or IP literal.
type Destination struct {
	hostname string
	address  netip.Addr
	zone     string
}

// ParseDestination classifies a complete destination without a port.
func ParseDestination(rawDestination string) (Destination, error) {
	address, addressErr := netip.ParseAddr(rawDestination)
	if addressErr == nil {
		return parseAddressDestination(address)
	}

	hostname, err := NormalizeHostname(rawDestination)
	if err != nil {
		return Destination{}, fmt.Errorf("parse destination hostname: %w", err)
	}

	return Destination{hostname: hostname}, nil
}

func parseAddressDestination(address netip.Addr) (Destination, error) {
	zone := address.Zone()
	if zone == "" {
		return Destination{address: address.Unmap()}, nil
	}

	if address.Is4In6() {
		return Destination{}, fmt.Errorf("IPv4-mapped destination has a zone identifier")
	}

	err := validateZone(zone)
	if err != nil {
		return Destination{}, fmt.Errorf("validate destination IPv6 zone: %w", err)
	}

	return Destination{address: address.WithZone(""), zone: zone}, nil
}

func validateZone(zone string) error {
	if len(zone) > 15 {
		return fmt.Errorf("zone exceeds Linux interface name limit")
	}

	if zone == "." || zone == ".." {
		return fmt.Errorf("zone is not a valid interface name")
	}

	for _, character := range zone {
		valid := character >= 'a' && character <= 'z' ||
			character >= 'A' && character <= 'Z' ||
			character >= '0' && character <= '9' ||
			character == '_' || character == '-' || character == '.'
		if !valid {
			return fmt.Errorf("zone contains invalid character %q", character)
		}
	}

	return nil
}

// IsHostname reports whether the destination is a hostname rather than an IP literal.
func (destination Destination) IsHostname() bool {
	return destination.hostname != ""
}

// Hostname returns the normalized hostname, or an empty string for an IP destination.
func (destination Destination) Hostname() string {
	return destination.hostname
}

// Address returns the canonical zone-free IP address, or an invalid address for a hostname destination.
func (destination Destination) Address() netip.Addr {
	return destination.address
}

// Zone returns the IPv6 scope zone, or an empty string when the destination is not scoped.
func (destination Destination) Zone() string {
	return destination.zone
}

// RoutingAddress returns the canonical IP address including its IPv6 scope zone.
func (destination Destination) RoutingAddress() netip.Addr {
	if destination.zone == "" {
		return destination.address
	}

	return destination.address.WithZone(destination.zone)
}
