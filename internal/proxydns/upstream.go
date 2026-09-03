package proxydns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Upstream exchanges one validated DNS query with a recursive resolver.
type Upstream interface {
	Exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error)
}

// SystemUpstream forwards queries according to a resolv.conf snapshot.
type SystemUpstream struct {
	servers  []string
	port     string
	timeout  time.Duration
	attempts int
}

// NewSystemUpstream snapshots a resolv.conf file.
func NewSystemUpstream(path string) (*SystemUpstream, error) {
	configuration, err := dns.ClientConfigFromFile(path)
	if err != nil {
		return nil, fmt.Errorf("read DNS resolver configuration %q: %w", path, err)
	}

	if len(configuration.Servers) == 0 {
		return nil, fmt.Errorf("read DNS resolver configuration %q: no nameservers", path)
	}

	timeout := time.Duration(configuration.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	if timeout > 10*time.Second {
		timeout = 10 * time.Second
	}

	attempts := configuration.Attempts
	if attempts < 1 {
		attempts = 1
	}

	if attempts > 3 {
		attempts = 3
	}

	return &SystemUpstream{
		servers:  append([]string(nil), configuration.Servers...),
		port:     configuration.Port,
		timeout:  timeout,
		attempts: attempts,
	}, nil
}

// Exchange sends a query to the configured recursive resolvers.
func (upstream *SystemUpstream) Exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	var lastError error

	for range upstream.attempts {
		for _, server := range upstream.servers {
			address := net.JoinHostPort(server, upstream.port)
			client := &dns.Client{Net: "udp", Timeout: upstream.timeout}

			response, _, err := client.ExchangeContext(ctx, request.Copy(), address)
			if err != nil {
				lastError = err

				continue
			}

			if response.Truncated {
				client.Net = "tcp"

				response, _, err = client.ExchangeContext(ctx, request.Copy(), address)
				if err != nil {
					lastError = err

					continue
				}
			}

			return response, nil
		}
	}

	if lastError == nil {
		lastError = fmt.Errorf("no DNS resolver attempted")
	}

	return nil, fmt.Errorf("exchange DNS query with configured resolvers: %w", lastError)
}
