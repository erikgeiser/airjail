package proxydns

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/miekg/dns"
)

// Resolver follows complete CNAME chains through an upstream DNS server.
type Resolver struct {
	upstream Upstream
}

type responseCodeError struct {
	code int
	host string
}

func (err *responseCodeError) Error() string {
	return fmt.Sprintf("resolve %q: upstream returned %s", err.host, dns.RcodeToString[err.code])
}

// NewResolver creates a chain-aware resolver.
func NewResolver(upstream Upstream) (*Resolver, error) {
	if upstream == nil {
		return nil, fmt.Errorf("create DNS resolver: upstream is nil")
	}

	return &Resolver{upstream: upstream}, nil
}

// LookupNetIP implements policy.Resolver.
func (resolver *Resolver) LookupNetIP(ctx context.Context, network, hostname string) ([]netip.Addr, error) {
	result, err := resolver.Resolve(ctx, network, hostname)
	if err != nil {
		return nil, err
	}

	return result.Addresses, nil
}

// Resolve returns a complete CNAME chain and its terminal addresses.
func (resolver *Resolver) Resolve(
	ctx context.Context,
	network string,
	hostname string,
) (policy.ResolutionResult, error) {
	switch network {
	case "ip4":
		return resolver.resolveType(ctx, hostname, dns.TypeA)
	case "ip6":
		return resolver.resolveType(ctx, hostname, dns.TypeAAAA)
	case "ip":
		ipv4, ipv4Err := resolver.resolveType(ctx, hostname, dns.TypeA)
		ipv6, ipv6Err := resolver.resolveType(ctx, hostname, dns.TypeAAAA)

		if ipv4Err != nil && ipv6Err != nil {
			return policy.ResolutionResult{}, fmt.Errorf(
				"resolve A and AAAA records: %w",
				errors.Join(ipv4Err, ipv6Err),
			)
		}

		return combineResolutions(ipv4, ipv6), nil
	default:
		return policy.ResolutionResult{}, fmt.Errorf("unsupported resolution network %q", network)
	}
}

func (resolver *Resolver) resolveType(
	ctx context.Context,
	hostname string,
	queryType uint16,
) (policy.ResolutionResult, error) {
	hostname, err := policy.NormalizeHostname(hostname)
	if err != nil {
		return policy.ResolutionResult{}, fmt.Errorf("normalize resolution hostname: %w", err)
	}

	result := policy.ResolutionResult{}
	current := hostname
	now := time.Now()

	for range maxCNAMEChain + 1 {
		query := clientQuery{request: new(dns.Msg), hostname: current, queryType: queryType}
		request := newUpstreamRequest(query)

		response, err := resolver.upstream.Exchange(ctx, request)
		if err != nil {
			return policy.ResolutionResult{}, fmt.Errorf(
				"exchange %s query for %q: %w",
				dns.TypeToString[queryType],
				current,
				err,
			)
		}

		err = validateUpstreamResponse(request, response)
		if err != nil {
			return policy.ResolutionResult{}, fmt.Errorf(
				"validate %s response for %q: %w",
				dns.TypeToString[queryType],
				current,
				err,
			)
		}

		if response.Rcode != dns.RcodeSuccess {
			return policy.ResolutionResult{}, &responseCodeError{code: response.Rcode, host: current}
		}

		answer, err := parseAddressAnswer(response, current, queryType)
		if err != nil {
			return policy.ResolutionResult{}, fmt.Errorf(
				"parse %s response for %q: %w",
				dns.TypeToString[queryType],
				current,
				err,
			)
		}

		expiresAt := now.Add(clampTTL(answer.ttl))
		if result.ExpiresAt.IsZero() || expiresAt.Before(result.ExpiresAt) {
			result.ExpiresAt = expiresAt
		}

		for _, alias := range answer.cnameChain {
			if alias == hostname || slices.Contains(result.CNAMEChain, alias) {
				return policy.ResolutionResult{}, fmt.Errorf("CNAME chain for %q contains a cycle", hostname)
			}

			if len(result.CNAMEChain) >= maxCNAMEChain {
				return policy.ResolutionResult{}, fmt.Errorf("CNAME chain for %q exceeds %d records", hostname, maxCNAMEChain)
			}

			result.CNAMEChain = append(result.CNAMEChain, alias)
		}

		if len(answer.addresses) != 0 {
			result.Addresses = append(result.Addresses, answer.addresses...)

			return result, nil
		}

		if len(answer.cnameChain) == 0 {
			return result, nil
		}

		current = answer.cnameChain[len(answer.cnameChain)-1]
	}

	return policy.ResolutionResult{}, fmt.Errorf("CNAME chain for %q exceeds %d records", hostname, maxCNAMEChain)
}

func combineResolutions(first, second policy.ResolutionResult) policy.ResolutionResult {
	combined := policy.ResolutionResult{ExpiresAt: first.ExpiresAt}
	for _, result := range []policy.ResolutionResult{first, second} {
		for _, alias := range result.CNAMEChain {
			if !slices.Contains(combined.CNAMEChain, alias) {
				combined.CNAMEChain = append(combined.CNAMEChain, alias)
			}
		}

		for _, address := range result.Addresses {
			if !slices.Contains(combined.Addresses, address) {
				combined.Addresses = append(combined.Addresses, address)
			}
		}

		if combined.ExpiresAt.IsZero() || !result.ExpiresAt.IsZero() && result.ExpiresAt.Before(combined.ExpiresAt) {
			combined.ExpiresAt = result.ExpiresAt
		}
	}

	return combined
}
