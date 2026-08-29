// Package policy parses and evaluates airjail network policy rules.
package policy

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/net/idna"
)

type portMatcher struct {
	port uint16
	set  bool
}

func (m portMatcher) matches(port uint16) bool {
	return !m.set || m.port == port
}

type hostRule struct {
	hostname string
	wildcard bool
	port     portMatcher
	resolved []netip.Addr
}

type addressRule struct {
	address netip.Addr
	port    portMatcher
}

type prefixRule struct {
	prefix netip.Prefix
	port   portMatcher
}

type ruleSet struct {
	hosts     []hostRule
	addresses []addressRule
	prefixes  []prefixRule
}

func parseRules(rawRules []string, logger *logging.Logger) (ruleSet, error) {
	rules := ruleSet{
		hosts:     make([]hostRule, 0, len(rawRules)),
		addresses: make([]addressRule, 0, len(rawRules)),
		prefixes:  make([]prefixRule, 0, len(rawRules)),
	}

	for _, rawRule := range rawRules {
		err := rules.add(rawRule, logger)
		if err != nil {
			return ruleSet{}, fmt.Errorf("parse rule %q: %w", rawRule, err)
		}
	}

	return rules, nil
}

func (rules *ruleSet) add(rawRule string, logger *logging.Logger) error {
	host, port, bracketed, err := splitRulePort(rawRule)
	if err != nil {
		return err
	}

	prefix, prefixErr := netip.ParsePrefix(host)
	if prefixErr == nil {
		maskedPrefix := prefix.Masked()
		if prefix != maskedPrefix {
			logger.Debugf("normalized CIDR %q to %q", prefix, maskedPrefix)
		}

		rules.prefixes = append(rules.prefixes, prefixRule{
			prefix: normalizePrefix(maskedPrefix),
			port:   port,
		})

		return nil
	}

	address, addressErr := netip.ParseAddr(host)
	if addressErr == nil {
		if address.Zone() != "" {
			return fmt.Errorf("IP address has a zone identifier")
		}

		rules.addresses = append(rules.addresses, addressRule{
			address: address.Unmap(),
			port:    port,
		})

		return nil
	}

	if bracketed {
		return fmt.Errorf("brackets require an IPv6 address or CIDR")
	}

	wildcard := strings.HasPrefix(host, "*.")
	if wildcard {
		host = strings.TrimPrefix(host, "*.")
	}

	if strings.ContainsRune(host, '*') {
		return fmt.Errorf("hostname contains an invalid wildcard")
	}

	hostname, err := NormalizeHostname(host)
	if err != nil {
		return err
	}

	rules.hosts = append(rules.hosts, hostRule{
		hostname: hostname,
		wildcard: wildcard,
		port:     port,
		resolved: []netip.Addr{},
	})

	return nil
}

func splitRulePort(rawRule string) (host string, port portMatcher, bracketed bool, err error) {
	if rawRule == "" {
		return "", portMatcher{}, false, fmt.Errorf("rule is empty")
	}

	if strings.HasPrefix(rawRule, "[") {
		closingBracket := strings.IndexByte(rawRule, ']')
		if closingBracket == -1 {
			return "", portMatcher{}, false, fmt.Errorf("missing closing bracket")
		}

		if closingBracket == 1 {
			return "", portMatcher{}, false, fmt.Errorf("bracketed target is empty")
		}

		if closingBracket+1 >= len(rawRule) || rawRule[closingBracket+1] != ':' {
			return "", portMatcher{}, false, fmt.Errorf("bracketed target requires a port")
		}

		parsedPort, parseErr := parsePort(rawRule[closingBracket+2:])
		if parseErr != nil {
			return "", portMatcher{}, false, parseErr
		}

		return rawRule[1:closingBracket], parsedPort, true, nil
	}

	// A complete IP or prefix wins before looking for a port, preserving raw IPv6 literals.
	_, addressErr := netip.ParseAddr(rawRule)
	if addressErr == nil {
		return rawRule, portMatcher{}, false, nil
	}

	_, prefixErr := netip.ParsePrefix(rawRule)
	if prefixErr == nil {
		return rawRule, portMatcher{}, false, nil
	}

	switch strings.Count(rawRule, ":") {
	case 0:
		return rawRule, portMatcher{}, false, nil
	case 1:
		separator := strings.LastIndexByte(rawRule, ':')
		if separator == 0 {
			return "", portMatcher{}, false, fmt.Errorf("target before port is empty")
		}

		parsedPort, parseErr := parsePort(rawRule[separator+1:])
		if parseErr != nil {
			return "", portMatcher{}, false, parseErr
		}

		return rawRule[:separator], parsedPort, false, nil
	default:
		return "", portMatcher{}, false, fmt.Errorf("invalid unbracketed target")
	}
}

func parsePort(rawPort string) (portMatcher, error) {
	if rawPort == "" {
		return portMatcher{}, fmt.Errorf("port is empty")
	}

	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 {
		return portMatcher{}, fmt.Errorf("port must be a number from 1 through 65535")
	}

	return portMatcher{port: uint16(port), set: true}, nil
}

// NormalizeHostname validates a hostname and returns its canonical ASCII form.
func NormalizeHostname(rawHostname string) (string, error) {
	if !utf8.ValidString(rawHostname) {
		return "", fmt.Errorf("hostname is not valid UTF-8")
	}

	rawHostname = strings.TrimSuffix(rawHostname, ".")
	if rawHostname == "" {
		return "", fmt.Errorf("hostname is empty")
	}

	asciiHostname, err := idna.Lookup.ToASCII(rawHostname)
	if err != nil {
		return "", fmt.Errorf("normalize hostname with IDNA: %w", err)
	}

	asciiHostname = strings.ToLower(asciiHostname)
	if len(asciiHostname) > 253 {
		return "", fmt.Errorf("hostname exceeds 253 bytes")
	}

	for _, label := range strings.Split(asciiHostname, ".") {
		err := validateHostnameLabel(label)
		if err != nil {
			return "", err
		}
	}

	return asciiHostname, nil
}

func validateHostnameLabel(label string) error {
	if label == "" {
		return fmt.Errorf("hostname contains an empty label")
	}

	if len(label) > 63 {
		return fmt.Errorf("hostname label exceeds 63 bytes")
	}

	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("hostname label begins or ends with a hyphen")
	}

	for _, character := range label {
		valid := character >= 'a' && character <= 'z' ||
			character >= '0' && character <= '9' || character == '-'
		if !valid {
			return fmt.Errorf("hostname label contains invalid character %q", character)
		}
	}

	return nil
}

func normalizePrefix(prefix netip.Prefix) netip.Prefix {
	address := prefix.Addr()
	if !address.Is4In6() {
		return prefix
	}

	return netip.PrefixFrom(address.Unmap(), prefix.Bits()-96)
}
