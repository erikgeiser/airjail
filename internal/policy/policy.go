package policy

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/erikgeiser/airjail/internal/logging"
)

// Resolver resolves hostnames into canonical IP addresses.
type Resolver interface {
	LookupNetIP(ctx context.Context, network string, host string) ([]netip.Addr, error)
}

// ChainResolver resolves complete, ordered CNAME chains and their terminal addresses.
type ChainResolver interface {
	Resolve(ctx context.Context, network string, hostname string) (ResolutionResult, error)
}

// Options controls policy construction and hostname-rule expansion.
type Options struct {
	Resolver          Resolver
	ChainResolver     ChainResolver
	AllowUnresolved   bool
	AllowArbitraryDNS bool
	Logger            *logging.Logger
}

// Policy is an immutable, parsed egress policy.
type Policy struct {
	allow             ruleSet
	block             ruleSet
	allowArbitraryDNS bool
	dynamic           dynamicPolicy
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

	err = resolveHostRules(ctx, "allow", &allow, resolver, options.ChainResolver, cache, options)
	if err != nil {
		return nil, fmt.Errorf("expand allow policy: %w", err)
	}

	err = resolveHostRules(ctx, "block", &block, resolver, options.ChainResolver, cache, options)
	if err != nil {
		return nil, fmt.Errorf("expand block policy: %w", err)
	}

	propagateCNAMEBlocks(allow.hosts, &block, options.Logger)

	return &Policy{
		allow:             allow,
		block:             block,
		allowArbitraryDNS: options.AllowArbitraryDNS,
		dynamic: dynamicPolicy{
			allow:   make(map[dynamicAddressKey]time.Time),
			block:   make(map[dynamicAddressKey]time.Time),
			aliases: make(map[string]map[string]time.Time),
		},
	}, nil
}

type lookupResult struct {
	aliases   []string
	addresses []netip.Addr
	err       error
}

func resolveHostRules(
	ctx context.Context,
	kind string,
	rules *ruleSet,
	resolver Resolver,
	chainResolver ChainResolver,
	cache map[string]lookupResult,
	options Options,
) error {
	for index := range rules.hosts {
		rule := &rules.hosts[index]
		if rule.wildcard {
			continue
		}

		if rule.configuredSnapshot {
			for _, address := range rule.resolved {
				options.Logger.Infof(
					"using configured %s snapshot %s to %s",
					kind,
					formatHostRule(*rule),
					formatAddressRule(address, rule.port),
				)
			}

			continue
		}

		result, found := cache[rule.hostname]
		if !found {
			if chainResolver != nil {
				resolution, err := chainResolver.Resolve(ctx, "ip", rule.hostname)
				result = lookupResult{
					aliases:   normalizeAliases(resolution.CNAMEChain),
					addresses: normalizeAddresses(resolution.Addresses),
					err:       err,
				}
			} else {
				addresses, err := resolver.LookupNetIP(ctx, "ip", rule.hostname)
				result = lookupResult{addresses: normalizeAddresses(addresses), err: err}
			}

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

		rule.aliases = slices.Clone(result.aliases)
		rule.resolved = slices.Clone(result.addresses)

		expansion := ""
		if len(rule.aliases) != 0 {
			expansion = " via " + strings.Join(rule.aliases, ", ")
		}

		for _, address := range rule.resolved {
			options.Logger.Infof(
				"expanded %s rule %s%s to %s",
				kind,
				formatHostRule(*rule),
				expansion,
				formatAddressRule(address, rule.port),
			)
		}
	}

	return nil
}

func propagateCNAMEBlocks(allowRules []hostRule, block *ruleSet, logger *logging.Logger) {
	for _, allowRule := range allowRules {
		if allowRule.wildcard || len(allowRule.aliases) == 0 {
			continue
		}

		for _, alias := range allowRule.aliases {
			for blockIndex := range block.hosts {
				blockRule := &block.hosts[blockIndex]
				if !blockRule.matchesHostname(alias) {
					continue
				}

				for _, address := range allowRule.resolved {
					if slices.Contains(blockRule.resolved, address) {
						continue
					}

					blockRule.resolved = append(blockRule.resolved, address)
					logger.Infof(
						"expanded block rule %s through CNAME %s to %s",
						formatHostRule(*blockRule),
						alias,
						formatAddressRule(address, blockRule.port),
					)
				}
			}
		}
	}
}

func normalizeAliases(aliases []string) []string {
	normalized := make([]string, 0, len(aliases))
	for _, alias := range aliases {
		hostname, err := NormalizeHostname(alias)
		if err != nil || slices.Contains(normalized, hostname) {
			continue
		}

		normalized = append(normalized, hostname)
	}

	return normalized
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

// StaticAddresses returns invocation-snapshot addresses for an exact allowed hostname.
func (policy *Policy) StaticAddresses(rawHostname string) ([]netip.Addr, bool, error) {
	hostname, err := NormalizeHostname(rawHostname)
	if err != nil {
		return nil, false, fmt.Errorf("normalize snapshot hostname: %w", err)
	}

	addresses := []netip.Addr{}
	found := false

	for _, rule := range policy.allow.hosts {
		if rule.wildcard || !rule.matchesHostname(hostname) {
			continue
		}

		found = true

		for _, address := range rule.resolved {
			if !slices.Contains(addresses, address) {
				addresses = append(addresses, address)
			}
		}
	}

	return addresses, found, nil
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

	policy.dynamic.mutex.Lock()
	defer policy.dynamic.mutex.Unlock()

	policy.dynamic.removeExpired(time.Now())

	return policy.allowsLocked(hostname, address, port), nil
}

func (rules *ruleSet) empty() bool {
	return len(rules.hosts) == 0 && len(rules.addresses) == 0 && len(rules.prefixes) == 0
}

func (rules *ruleSet) matchesHostnameOnAnyPort(hostname string) bool {
	for _, rule := range rules.hosts {
		if rule.matchesHostname(hostname) {
			return true
		}
	}

	return false
}

func (rules *ruleSet) matchesHostnameOnAllPorts(hostname string) bool {
	for _, rule := range rules.hosts {
		if !rule.port.set && rule.matchesHostname(hostname) {
			return true
		}
	}

	return false
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
		return hostname == rule.hostname || slices.Contains(rule.aliases, hostname)
	}

	return len(hostname) > len(rule.hostname) && strings.HasSuffix(hostname, "."+rule.hostname)
}
