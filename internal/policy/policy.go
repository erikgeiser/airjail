package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/erikgeiser/airjail/internal/logging"
)

// Resolver resolves hostnames into canonical IP addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// Options controls policy construction and hostname-rule expansion.
type Options struct {
	Resolver        Resolver
	AllowUnresolved bool
	Logger          *logging.Logger
}

// Policy is an immutable, parsed egress policy.
type Policy struct {
	allow ruleSet
	block ruleSet
}

// New parses rules and resolves exact hostname rules.
func New(ctx context.Context, allowRules, blockRules []string, options Options) (*Policy, error) {
	allow, err := parseRules(allowRules, options.Logger)
	if err != nil {
		return nil, fmt.Errorf("parse allow policy: %w", err)
	}

	block, err := parseRules(blockRules, options.Logger)
	if err != nil {
		return nil, fmt.Errorf("parse block policy: %w", err)
	}

	resolver := options.Resolver
	if resolver == nil {
		resolver = net.DefaultResolver
	}

	cache := make(map[string]lookupResult)

	err = resolveHostRules(ctx, &allow, resolver, cache, options)
	if err != nil {
		return nil, fmt.Errorf("expand allow policy: %w", err)
	}

	err = resolveHostRules(ctx, &block, resolver, cache, options)
	if err != nil {
		return nil, fmt.Errorf("expand block policy: %w", err)
	}

	return &Policy{allow: allow, block: block}, nil
}

type lookupResult struct {
	addresses []netip.Addr
	err       error
}

func resolveHostRules(
	ctx context.Context,
	rules *ruleSet,
	resolver Resolver,
	cache map[string]lookupResult,
	options Options,
) error {
	for index := range rules.hosts {
		rule := &rules.hosts[index]
		if rule.wildcard {
			continue
		}

		result, found := cache[rule.hostname]
		if !found {
			addresses, err := resolver.LookupNetIP(ctx, "ip", rule.hostname)
			result = lookupResult{addresses: normalizeAddresses(addresses), err: err}
			cache[rule.hostname] = result
		}

		if result.err != nil {
			if !options.AllowUnresolved {
				return fmt.Errorf("resolve hostname rule %q: %w", rule.hostname, result.err)
			}

			options.Logger.Warnf("hostname rule %q did not resolve: %v", rule.hostname, result.err)

			continue
		}

		if len(result.addresses) == 0 {
			if !options.AllowUnresolved {
				return fmt.Errorf("resolve hostname rule %q: resolver returned no addresses", rule.hostname)
			}

			options.Logger.Warnf("hostname rule %q resolved to no addresses", rule.hostname)

			continue
		}

		rule.resolved = slices.Clone(result.addresses)
	}

	return nil
}

func normalizeAddresses(addresses []netip.Addr) []netip.Addr {
	normalized := make([]netip.Addr, 0, len(addresses))

	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if !address.IsValid() || address.Zone() != "" {
			continue
		}

		address = address.Unmap()
		if _, found := seen[address]; found {
			continue
		}

		seen[address] = struct{}{}
		normalized = append(normalized, address)
	}

	return normalized
}

// Empty reports whether the policy has no allow or block rules.
func (policy *Policy) Empty() bool {
	return policy.allow.empty() && policy.block.empty()
}

// Allows reports whether a normalized hostname and concrete address may be used on port.
// Hostname may be empty for a direct IP request, and address may be invalid when a remote
// upstream proxy must resolve the hostname.
func (policy *Policy) Allows(hostname string, address netip.Addr, port uint16) (bool, error) {
	if port == 0 {
		return false, fmt.Errorf("destination port must be from 1 through 65535")
	}

	if hostname == "" && !address.IsValid() {
		return false, fmt.Errorf("destination has neither a hostname nor an IP address")
	}

	if hostname != "" {
		normalizedHostname, err := NormalizeHostname(hostname)
		if err != nil {
			return false, fmt.Errorf("normalize destination hostname: %w", err)
		}

		hostname = normalizedHostname
	}

	if address.IsValid() {
		if address.Zone() != "" {
			return false, fmt.Errorf("destination IP address has a zone identifier")
		}

		address = address.Unmap()
	}

	if policy.Empty() {
		return false, nil
	}

	allowed := policy.allow.empty() || policy.allow.matches(hostname, address, port)
	if !allowed {
		return false, nil
	}

	return !policy.block.matches(hostname, address, port), nil
}

func (rules *ruleSet) empty() bool {
	return len(rules.hosts) == 0 && len(rules.addresses) == 0 && len(rules.prefixes) == 0
}

func (rules *ruleSet) matches(hostname string, address netip.Addr, port uint16) bool {
	for _, rule := range rules.hosts {
		if !rule.port.matches(port) {
			continue
		}

		if hostname != "" && rule.matchesHostname(hostname) {
			return true
		}

		if address.IsValid() && slices.Contains(rule.resolved, address) {
			return true
		}
	}

	if address.IsValid() {
		for _, rule := range rules.addresses {
			if rule.port.matches(port) && rule.address == address {
				return true
			}
		}

		for _, rule := range rules.prefixes {
			if rule.port.matches(port) && rule.prefix.Contains(address) {
				return true
			}
		}
	}

	return false
}

func (rule hostRule) matchesHostname(hostname string) bool {
	if !rule.wildcard {
		return hostname == rule.hostname
	}

	return len(hostname) > len(rule.hostname) && strings.HasSuffix(hostname, "."+rule.hostname)
}
