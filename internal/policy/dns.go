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

	origins := policy.resolutionOriginsLocked(hostname)
	for _, origin := range origins {
		if policy.hostnameMayResolveLocked(origin) {
			return ResolutionAuthorization{query: hostname, origins: origins}, true, nil
		}
	}

	// Address and prefix allow rules require seeing an answer before the policy
	// can determine whether an otherwise unknown hostname is useful.
	if policy.hasAddressAllowRules() && policy.hostnameNotBlockedOnEveryPortLocked(hostname) {
		return ResolutionAuthorization{query: hostname, origins: origins}, true, nil
	}

	return ResolutionAuthorization{}, false, nil
}

func (policy *Policy) resolutionOriginsLocked(hostname string) []string {
	origins := []string{hostname}
	for origin := range policy.dynamic.aliases[hostname] {
		if !slices.Contains(origins, origin) {
			origins = append(origins, origin)
		}
	}

	return origins
}

func (policy *Policy) hasAddressAllowRules() bool {
	return len(policy.allow.addresses) != 0 || len(policy.allow.prefixes) != 0
}

// CommitResolution validates a DNS result and installs its temporary policy grants.
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

	if len(addresses) == 0 && len(chain) > 1 &&
		!policy.chainMayResolveLocked(authorization.origins, chain) {
		return false, nil
	}

	// Refuse the complete answer if any terminal address is unusable. Filtering
	// individual records would change DNS load-balancing and DNSSEC semantics.
	for _, address := range addresses {
		if !policy.addressMayBeUsedLocked(authorization.origins, chain, address) {
			return false, nil
		}
	}

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

func (policy *Policy) hostnameMayResolveLocked(hostname string) bool {
	for _, port := range policy.representativePorts() {
		if policy.allowsLocked(hostname, netip.Addr{}, port) {
			return true
		}
	}

	return false
}

func (policy *Policy) hostnameNotBlockedOnEveryPortLocked(hostname string) bool {
	for _, port := range policy.representativePorts() {
		if !policy.block.matches(hostname, netip.Addr{}, port) {
			return true
		}
	}

	return false
}

func (policy *Policy) chainMayResolveLocked(origins, chain []string) bool {
	for _, port := range policy.representativePorts() {
		potentiallyAllowed := false

		for _, origin := range origins {
			if policy.allowsLocked(origin, netip.Addr{}, port) {
				potentiallyAllowed = true

				break
			}
		}

		if !potentiallyAllowed && policy.addressRuleMayAllowPort(port) {
			potentiallyAllowed = true
		}

		if potentiallyAllowed && !policy.chainBlockedLocked(chain, netip.Addr{}, port) {
			return true
		}
	}

	return false
}

func (policy *Policy) addressRuleMayAllowPort(port uint16) bool {
	for _, rule := range policy.allow.addresses {
		if rule.port.matches(port) {
			return true
		}
	}

	for _, rule := range policy.allow.prefixes {
		if rule.port.matches(port) {
			return true
		}
	}

	return false
}

func (policy *Policy) addressMayBeUsedLocked(origins, chain []string, address netip.Addr) bool {
	for _, port := range policy.representativePorts() {
		for _, origin := range origins {
			if policy.allowsLocked(origin, address, port) && !policy.chainBlockedLocked(chain, address, port) {
				return true
			}
		}
	}

	return false
}

func (policy *Policy) chainBlockedLocked(chain []string, address netip.Addr, port uint16) bool {
	for _, hostname := range chain {
		if policy.block.matches(hostname, address, port) {
			return true
		}
	}

	return false
}

func (policy *Policy) representativePorts() []uint16 {
	specified := make(map[uint16]struct{})

	for _, rules := range []*ruleSet{&policy.allow, &policy.block} {
		for _, rule := range rules.hosts {
			if rule.port.set {
				specified[rule.port.port] = struct{}{}
			}
		}

		for _, rule := range rules.addresses {
			if rule.port.set {
				specified[rule.port.port] = struct{}{}
			}
		}

		for _, rule := range rules.prefixes {
			if rule.port.set {
				specified[rule.port.port] = struct{}{}
			}
		}
	}

	ports := make([]uint16, 0, len(specified)+1)
	for port := range specified {
		ports = append(ports, port)
	}

	// One unspecified port represents every port not mentioned by a rule.
	for port := 1; port <= 65535; port++ {
		candidate := uint16(port)
		if _, found := specified[candidate]; !found {
			ports = append(ports, candidate)

			break
		}
	}

	return ports
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
