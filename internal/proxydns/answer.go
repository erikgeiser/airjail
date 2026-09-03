package proxydns

import (
	"fmt"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/miekg/dns"
)

const (
	maxCNAMEChain   = 16
	minimumGrantTTL = 5 * time.Second
	maximumGrantTTL = time.Hour
)

type addressAnswer struct {
	cnameChain []string
	addresses  []netip.Addr
	ttl        uint32
}

type cnamePath struct {
	chain    []string
	terminal string
	ttl      uint32
	ttlSet   bool
}

func (answer addressAnswer) empty() bool {
	return len(answer.cnameChain) == 0 && len(answer.addresses) == 0
}

func (answer addressAnswer) policyResult(now time.Time) policy.ResolutionResult {
	return policy.ResolutionResult{
		CNAMEChain: answer.cnameChain,
		Addresses:  answer.addresses,
		ExpiresAt:  now.Add(clampTTL(answer.ttl)),
	}
}

func parseAddressAnswer(response *dns.Msg, queryHostname string, queryType uint16) (addressAnswer, error) {
	cnames := make(map[string]*dns.CNAME)
	addresses := make(map[string][]netip.Addr)

	for _, record := range response.Answer {
		switch typed := record.(type) {
		case *dns.CNAME:
			owner, err := policy.NormalizeHostname(typed.Hdr.Name)
			if err != nil {
				return addressAnswer{}, fmt.Errorf("normalize CNAME owner: %w", err)
			}

			if _, found := cnames[owner]; found {
				return addressAnswer{}, fmt.Errorf("multiple CNAME records for %q", owner)
			}

			cnames[owner] = typed
		case *dns.A:
			if queryType != dns.TypeA {
				continue
			}

			owner, address, err := parseAddressRecord(typed.Hdr.Name, typed.A)
			if err != nil {
				return addressAnswer{}, err
			}

			addresses[owner] = append(addresses[owner], address)
		case *dns.AAAA:
			if queryType != dns.TypeAAAA {
				continue
			}

			owner, address, err := parseAddressRecord(typed.Hdr.Name, typed.AAAA)
			if err != nil {
				return addressAnswer{}, err
			}

			addresses[owner] = append(addresses[owner], address)
		}
	}

	path, err := followCNAMEChain(cnames, queryHostname)
	if err != nil {
		return addressAnswer{}, err
	}

	minimumTTL, _ := terminalAddressTTL(
		response.Answer,
		path.terminal,
		queryType,
		path.ttl,
		path.ttlSet,
	)

	return addressAnswer{
		cnameChain: path.chain,
		addresses:  addresses[path.terminal],
		ttl:        minimumTTL,
	}, nil
}

func followCNAMEChain(cnames map[string]*dns.CNAME, queryHostname string) (cnamePath, error) {
	path := cnamePath{
		chain:    make([]string, 0, min(len(cnames), maxCNAMEChain)),
		terminal: queryHostname,
	}

	for range maxCNAMEChain {
		cname, found := cnames[path.terminal]
		if !found {
			break
		}

		target, err := policy.NormalizeHostname(cname.Target)
		if err != nil {
			return cnamePath{}, fmt.Errorf("normalize CNAME target: %w", err)
		}

		if target == path.terminal || slices.Contains(path.chain, target) {
			return cnamePath{}, fmt.Errorf("CNAME chain contains a cycle")
		}

		path.chain = append(path.chain, target)
		path.ttl = lowerTTL(path.ttl, path.ttlSet, cname.Hdr.Ttl)
		path.ttlSet = true
		path.terminal = target
	}

	if _, found := cnames[path.terminal]; found {
		return cnamePath{}, fmt.Errorf("CNAME chain exceeds %d records", maxCNAMEChain)
	}

	return path, nil
}

func terminalAddressTTL(
	records []dns.RR,
	terminal string,
	queryType uint16,
	minimumTTL uint32,
	ttlSet bool,
) (uint32, bool) {
	for _, record := range records {
		if record.Header().Rrtype != queryType || record.Header().Name == "" {
			continue
		}

		owner, err := policy.NormalizeHostname(record.Header().Name)
		if err != nil || owner != terminal {
			continue
		}

		minimumTTL = lowerTTL(minimumTTL, ttlSet, record.Header().Ttl)
		ttlSet = true
	}

	return minimumTTL, ttlSet
}

func parseAddressRecord(owner string, rawAddress net.IP) (string, netip.Addr, error) {
	hostname, err := policy.NormalizeHostname(owner)
	if err != nil {
		return "", netip.Addr{}, fmt.Errorf("normalize address owner: %w", err)
	}

	address, ok := netip.AddrFromSlice(rawAddress)
	if !ok {
		return "", netip.Addr{}, fmt.Errorf("parse address record for %q", hostname)
	}

	return hostname, address.Unmap(), nil
}

func lowerTTL(current uint32, set bool, candidate uint32) uint32 {
	if !set || candidate < current {
		return candidate
	}

	return current
}

func clampTTL(ttl uint32) time.Duration {
	duration := time.Duration(ttl) * time.Second
	if duration < minimumGrantTTL {
		return minimumGrantTTL
	}

	if duration > maximumGrantTTL {
		return maximumGrantTTL
	}

	return duration
}
