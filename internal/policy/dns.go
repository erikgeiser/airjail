package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"time"
)

// ResolutionAuthorization records the configured policy origins under which a DNS query may proceed.
type ResolutionAuthorization struct {
	query   string
	origins []string
}

// ResolutionResult contains the policy-relevant records from one validated DNS answer.
type ResolutionResult struct {
	CNAMEChain []string
	Addresses  []netip.Addr
	ExpiresAt  time.Time
}

// BeginResolution determines whether a normalized DNS hostname may be resolved.
func (policy *Policy) BeginResolution(rawHostname string, now time.Time) (ResolutionAuthorization, bool, error) {
	hostname, err := NormalizeHostname(rawHostname)
	if err != nil {
		return ResolutionAuthorization{}, false, fmt.Errorf("normalize DNS question hostname: %w", err)
	}

	policy.dynamic.mutex.Lock()
	defer policy.dynamic.mutex.Unlock()

	policy.dynamic.removeExpired(now)

	policyOrigins := policy.resolutionPolicyCandidates(hostname)
	if policy.mayResolve(hostname, policyOrigins) {
		return ResolutionAuthorization{query: hostname, origins: policyOrigins}, true, nil
	}

	return ResolutionAuthorization{}, false, nil
}

func (policy *Policy) resolutionPolicyCandidates(hostname string) []string {
	origins := []string{hostname}
	for origin := range policy.dynamic.aliases[hostname] {
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}

	return origins
}

// CommitResolution records one authorized runtime resolution before its answer is returned.
func (policy *Policy) CommitResolution(
	authorization ResolutionAuthorization,
	result ResolutionResult,
	now time.Time,
) (bool, error) {
	if authorization.query == "" || len(authorization.origins) == 0 {
		return false, fmt.Errorf("DNS resolution authorization is empty")
	}

	chain, err := normalizeResolutionChain(authorization.query, result.CNAMEChain)
	if err != nil {
		return false, err
	}

	addresses := normalizeAddresses(result.Addresses)

	policy.dynamic.mutex.Lock()
	defer policy.dynamic.mutex.Unlock()

	policy.dynamic.removeExpired(now)
	policy.installResolutionGrantsLocked(authorization.origins, chain, addresses, result.ExpiresAt)

	return true, nil
}

func normalizeResolutionChain(query string, rawChain []string) ([]string, error) {
	chain := make([]string, 0, len(rawChain)+1)
	chain = append(chain, query)

	for _, rawHostname := range rawChain {
		hostname, err := NormalizeHostname(rawHostname)
		if err != nil {
			return nil, fmt.Errorf("normalize DNS answer hostname: %w", err)
		}

		if !slices.Contains(chain, hostname) {
			chain = append(chain, hostname)
		}
	}

	return chain, nil
}

func (policy *Policy) installResolutionGrantsLocked(
	origins []string,
	chain []string,
	addresses []netip.Addr,
	expires time.Time,
) {
	for _, address := range addresses {
		for _, origin := range origins {
			policy.addMatchingDynamicAddresses(&policy.allow, policy.dynamic.allow, origin, address, expires)
		}

		for _, hostname := range chain {
			policy.addMatchingDynamicAddresses(&policy.block, policy.dynamic.block, hostname, address, expires)
		}
	}

	for _, alias := range chain[1:] {
		for _, origin := range origins {
			policy.dynamic.addAlias(alias, origin, expires)
		}
	}

	policy.dynamic.enforceLimit()
}

func (policy *Policy) mayResolve(query string, origins []string) bool {
	if policy.block.matchesHostnameOnAllPorts(query) {
		return false
	}

	if policy.allowArbitraryDNS {
		return true
	}

	for _, origin := range origins {
		if policy.allow.matchesHostnameOnAnyPort(origin) && !policy.block.matchesHostnameOnAllPorts(origin) {
			return true
		}
	}

	return false
}

func (policy *Policy) allowsLocked(hostname string, address netip.Addr, port uint16) bool {
	if policy.Empty() {
		return false
	}

	allowed := policy.allow.empty() || policy.allow.matches(hostname, address, port) ||
		policy.dynamicMatches(policy.allow.hosts, policy.dynamic.allow, address, port)
	if !allowed {
		return false
	}

	return !policy.block.matches(hostname, address, port) &&
		!policy.dynamicMatches(policy.block.hosts, policy.dynamic.block, address, port)
}
