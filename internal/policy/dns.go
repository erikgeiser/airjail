package policy

import (
	"fmt"
	"net/netip"
	"slices"
	"sync"
	"time"
)

const maxDynamicDNSGrants = 8192

type dynamicAddressKey struct {
	ruleIndex int
	address   netip.Addr
}

type dynamicPolicy struct {
	mutex   sync.Mutex
	allow   map[dynamicAddressKey]time.Time
	block   map[dynamicAddressKey]time.Time
	aliases map[string]map[string]time.Time
}

// ResolutionAuthorization records the configured policy origins under which a DNS query may proceed.
type ResolutionAuthorization struct {
	query   string
	origins []string
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

	origins := []string{hostname}
	if aliases := policy.dynamic.aliases[hostname]; len(aliases) != 0 {
		for origin := range aliases {
			if !slices.Contains(origins, origin) {
				origins = append(origins, origin)
			}
		}
	}

	for _, origin := range origins {
		if policy.hostnameMayResolveLocked(origin) {
			return ResolutionAuthorization{query: hostname, origins: origins}, true, nil
		}
	}

	if len(policy.allow.addresses) != 0 || len(policy.allow.prefixes) != 0 {
		if policy.hostnameNotBlockedOnEveryPortLocked(hostname) {
			return ResolutionAuthorization{query: hostname, origins: origins}, true, nil
		}
	}

	return ResolutionAuthorization{}, false, nil
}

// CommitResolution validates a DNS answer and installs its temporary policy grants.
func (policy *Policy) CommitResolution(
	authorization ResolutionAuthorization,
	chain []string,
	addresses []netip.Addr,
	expires time.Time,
	now time.Time,
) (bool, error) {
	if authorization.query == "" || len(authorization.origins) == 0 {
		return false, fmt.Errorf("DNS resolution authorization is empty")
	}

	normalizedChain := make([]string, 0, len(chain)+1)
	normalizedChain = append(normalizedChain, authorization.query)

	for _, rawHostname := range chain {
		hostname, err := NormalizeHostname(rawHostname)
		if err != nil {
			return false, fmt.Errorf("normalize DNS answer hostname: %w", err)
		}

		if !slices.Contains(normalizedChain, hostname) {
			normalizedChain = append(normalizedChain, hostname)
		}
	}

	normalizedAddresses := normalizeAddresses(addresses)

	policy.dynamic.mutex.Lock()
	defer policy.dynamic.mutex.Unlock()

	policy.dynamic.removeExpired(now)

	if len(normalizedAddresses) == 0 && len(normalizedChain) > 1 &&
		!policy.chainMayResolveLocked(authorization.origins, normalizedChain) {
		return false, nil
	}

	for _, address := range normalizedAddresses {
		if !policy.addressMayBeUsedLocked(authorization.origins, normalizedChain, address) {
			return false, nil
		}
	}

	for _, address := range normalizedAddresses {
		for _, origin := range authorization.origins {
			policy.addMatchingDynamicAddresses(&policy.allow, policy.dynamic.allow, origin, address, expires)
		}

		for _, hostname := range normalizedChain {
			policy.addMatchingDynamicAddresses(&policy.block, policy.dynamic.block, hostname, address, expires)
		}
	}

	for _, alias := range normalizedChain[1:] {
		for _, origin := range authorization.origins {
			policy.dynamic.addAlias(alias, origin, expires)
		}
	}

	policy.dynamic.enforceLimit()

	return true, nil
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

		if !potentiallyAllowed {
			continue
		}

		blocked := false

		for _, hostname := range chain {
			if policy.block.matches(hostname, netip.Addr{}, port) {
				blocked = true

				break
			}
		}

		if !blocked {
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
			if !policy.allowsLocked(origin, address, port) {
				continue
			}

			blocked := false

			for _, hostname := range chain {
				if policy.block.matches(hostname, address, port) {
					blocked = true

					break
				}
			}

			if !blocked {
				return true
			}
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

func (policy *Policy) dynamicMatches(
	rules []hostRule,
	expansions map[dynamicAddressKey]time.Time,
	address netip.Addr,
	port uint16,
) bool {
	if !address.IsValid() {
		return false
	}

	for ruleIndex, rule := range rules {
		if !rule.port.matches(port) {
			continue
		}

		if _, found := expansions[dynamicAddressKey{ruleIndex: ruleIndex, address: address}]; found {
			return true
		}
	}

	return false
}

func (policy *Policy) addMatchingDynamicAddresses(
	rules *ruleSet,
	expansions map[dynamicAddressKey]time.Time,
	hostname string,
	address netip.Addr,
	expires time.Time,
) {
	for ruleIndex, rule := range rules.hosts {
		if !rule.matchesHostname(hostname) {
			continue
		}

		key := dynamicAddressKey{ruleIndex: ruleIndex, address: address}
		if current, found := expansions[key]; !found || expires.After(current) {
			expansions[key] = expires
		}
	}
}

func (dynamic *dynamicPolicy) addAlias(alias, origin string, expires time.Time) {
	origins := dynamic.aliases[alias]
	if origins == nil {
		origins = make(map[string]time.Time)
		dynamic.aliases[alias] = origins
	}

	if current, found := origins[origin]; !found || expires.After(current) {
		origins[origin] = expires
	}
}

func (dynamic *dynamicPolicy) removeExpired(now time.Time) {
	for key, expires := range dynamic.allow {
		if !expires.After(now) {
			delete(dynamic.allow, key)
		}
	}

	for key, expires := range dynamic.block {
		if !expires.After(now) {
			delete(dynamic.block, key)
		}
	}

	for alias, origins := range dynamic.aliases {
		for origin, expires := range origins {
			if !expires.After(now) {
				delete(origins, origin)
			}
		}

		if len(origins) == 0 {
			delete(dynamic.aliases, alias)
		}
	}
}

func (dynamic *dynamicPolicy) enforceLimit() {
	for dynamic.count() > maxDynamicDNSGrants {
		var (
			oldestExpiration time.Time
			remove           func()
		)

		consider := func(expires time.Time, candidate func()) {
			if remove == nil || expires.Before(oldestExpiration) {
				oldestExpiration = expires
				remove = candidate
			}
		}

		for key, expires := range dynamic.allow {
			key := key

			consider(expires, func() { delete(dynamic.allow, key) })
		}

		for key, expires := range dynamic.block {
			key := key

			consider(expires, func() { delete(dynamic.block, key) })
		}

		for alias, origins := range dynamic.aliases {
			for origin, expires := range origins {
				alias := alias
				origin := origin

				consider(expires, func() {
					delete(dynamic.aliases[alias], origin)

					if len(dynamic.aliases[alias]) == 0 {
						delete(dynamic.aliases, alias)
					}
				})
			}
		}

		if remove == nil {
			return
		}

		remove()
	}
}

func (dynamic *dynamicPolicy) count() int {
	count := len(dynamic.allow) + len(dynamic.block)
	for _, origins := range dynamic.aliases {
		count += len(origins)
	}

	return count
}
