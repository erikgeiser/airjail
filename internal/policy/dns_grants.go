package policy

import (
	"net/netip"
	"sync"
	"time"
)

type dynamicAddressKey struct {
	ruleIndex int
	address   netip.Addr
}

// dynamicPolicy stores DNS observations separately from immutable configured
// rules. Address keys retain the originating rule so its port restriction is
// still applied when a transparent connection provides no hostname.
type dynamicPolicy struct {
	mutex   sync.Mutex
	allow   map[dynamicAddressKey]time.Time
	block   map[dynamicAddressKey]time.Time
	aliases map[string]map[string]time.Time
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
