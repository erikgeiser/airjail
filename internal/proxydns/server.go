// Package proxydns implements airjail's policy-aware DNS forwarder.
package proxydns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"time"

	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
	"github.com/miekg/dns"
)

const (
	maxDNSMessageSize       = 65535
	maxConcurrentQuery      = 256
	maxQueriesPerConnection = 256
	maxCNAMEChain           = 16
	dnsStreamTimeout        = 10 * time.Second
	minimumGrantTTL         = 5 * time.Second
	maximumGrantTTL         = time.Hour
)

// Upstream exchanges one validated DNS query with a recursive resolver.
type Upstream interface {
	Exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error)
}

// Server forwards filtered DNS queries and records approved answers in policy.
type Server struct {
	policy   *policy.Policy
	upstream Upstream
	logger   *logging.Logger
	queries  chan struct{}

	connections *stream.ConnGroup
}

// New creates a DNS server.
func New(networkPolicy *policy.Policy, upstream Upstream, logger *logging.Logger) (*Server, error) {
	if networkPolicy == nil {
		return nil, fmt.Errorf("create DNS server: network policy is nil")
	}

	if upstream == nil {
		return nil, fmt.Errorf("create DNS server: upstream resolver is nil")
	}

	return &Server{
		policy:      networkPolicy,
		upstream:    upstream,
		logger:      logger,
		queries:     make(chan struct{}, maxConcurrentQuery),
		connections: stream.NewConnGroup(),
	}, nil
}

// Serve accepts DNS-over-stream connections until ctx is canceled.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	stopShutdown := server.connections.ShutdownOnContext(ctx, listener)
	defer stopShutdown()

	for {
		connection, err := listener.Accept()
		if err != nil {
			server.connections.Close()
			server.connections.Wait()

			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return nil
			}

			return fmt.Errorf("accept DNS proxy connection: %w", err)
		}

		started := server.connections.Go(func(_ *stream.ConnScope) {
			server.serveConnection(ctx, connection)
		}, connection)
		if !started {
			_ = connection.Close()
		}
	}
}

func (server *Server) serveConnection(ctx context.Context, connection net.Conn) {
	defer func() { _ = connection.Close() }()

	for range maxQueriesPerConnection {
		request, err := readStreamMessage(connection)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
				server.logger.Debugf("read DNS proxy request: %v", err)
			}

			return
		}

		response := server.handle(ctx, request)
		if len(response) == 0 {
			return
		}

		err = writeStreamMessage(connection, response)
		if err != nil {
			server.logger.Debugf("write DNS proxy response: %v", err)

			return
		}
	}
}

func (server *Server) handle(ctx context.Context, wireRequest []byte) []byte {
	request := &dns.Msg{}

	err := request.Unpack(wireRequest)
	if err != nil {
		return packMalformedResponse(wireRequest, dns.RcodeFormatError)
	}

	if request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return packResponse(request, dns.RcodeFormatError)
	}

	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return packResponse(request, dns.RcodeNotImplemented)
	}

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return packResponse(request, dns.RcodeNotImplemented)
	}

	hostname, err := policy.NormalizeHostname(question.Name)
	if err != nil {
		return packResponse(request, dns.RcodeFormatError)
	}

	now := time.Now()

	authorization, allowed, err := server.policy.BeginResolution(hostname, now)
	if err != nil {
		server.logger.Debugf("evaluate DNS question %s: %v", hostname, err)

		return packResponse(request, dns.RcodeServerFailure)
	}

	if !allowed {
		server.logger.Blockf("dns %s %s", dns.TypeToString[question.Qtype], hostname)

		return packResponse(request, dns.RcodeRefused)
	}

	select {
	case server.queries <- struct{}{}:
		defer func() { <-server.queries }()
	case <-ctx.Done():
		return packResponse(request, dns.RcodeServerFailure)
	default:
		return packResponse(request, dns.RcodeServerFailure)
	}

	upstreamRequest := newUpstreamRequest(request, hostname, question.Qtype)

	upstreamResponse, err := server.upstream.Exchange(ctx, upstreamRequest)
	if err != nil {
		server.logger.Debugf("resolve DNS question %s: %v", hostname, err)

		return packResponse(request, dns.RcodeServerFailure)
	}

	err = validateUpstreamResponse(upstreamRequest, upstreamResponse)
	if err != nil {
		server.logger.Debugf("validate DNS response for %s: %v", hostname, err)

		return packResponse(request, dns.RcodeServerFailure)
	}

	upstreamResponse.Id = request.Id
	upstreamResponse.Question = request.Question

	if upstreamResponse.Rcode != dns.RcodeSuccess {
		server.logger.Allowf("dns %s %s", dns.TypeToString[question.Qtype], hostname)

		return packMessage(upstreamResponse)
	}

	chain, addresses, ttl, err := parseAddressAnswer(upstreamResponse, hostname, question.Qtype)
	if err != nil {
		server.logger.Debugf("parse DNS response for %s: %v", hostname, err)

		return packResponse(request, dns.RcodeServerFailure)
	}

	if len(chain) != 0 || len(addresses) != 0 {
		expires := now.Add(clampTTL(ttl))

		allowed, err = server.policy.CommitResolution(authorization, chain, addresses, expires, now)
		if err != nil {
			server.logger.Debugf("record DNS response for %s: %v", hostname, err)

			return packResponse(request, dns.RcodeServerFailure)
		}

		if !allowed {
			server.logger.Blockf("dns %s %s", dns.TypeToString[question.Qtype], hostname)

			return packResponse(request, dns.RcodeRefused)
		}
	}

	server.logger.Allowf("dns %s %s", dns.TypeToString[question.Qtype], hostname)

	return packMessage(upstreamResponse)
}

func newUpstreamRequest(clientRequest *dns.Msg, hostname string, queryType uint16) *dns.Msg {
	request := &dns.Msg{}
	request.SetQuestion(dns.Fqdn(hostname), queryType)
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.CheckingDisabled = clientRequest.CheckingDisabled

	if clientEDNS := clientRequest.IsEdns0(); clientEDNS != nil {
		request.SetEdns0(1232, clientEDNS.Do())
	}

	return request
}

func validateUpstreamResponse(request, response *dns.Msg) error {
	if response == nil {
		return fmt.Errorf("resolver returned a nil response")
	}

	if !response.Response || response.Id != request.Id || response.Opcode != dns.OpcodeQuery {
		return fmt.Errorf("response header does not match query")
	}

	if len(response.Question) != 1 || response.Question[0].Qtype != request.Question[0].Qtype ||
		response.Question[0].Qclass != dns.ClassINET {
		return fmt.Errorf("response question does not match query")
	}

	_, validName := dns.IsDomainName(response.Question[0].Name)
	if !validName {
		return fmt.Errorf("response question hostname is invalid")
	}

	responseHostname, err := policy.NormalizeHostname(response.Question[0].Name)
	if err != nil || responseHostname != request.Question[0].Name[:len(request.Question[0].Name)-1] {
		return fmt.Errorf("response question hostname does not match query")
	}

	return nil
}

func parseAddressAnswer(response *dns.Msg, queryHostname string, queryType uint16) ([]string, []netip.Addr, uint32, error) {
	cnames := make(map[string]*dns.CNAME)
	addresses := make(map[string][]netip.Addr)

	for _, record := range response.Answer {
		switch typed := record.(type) {
		case *dns.CNAME:
			owner, err := policy.NormalizeHostname(typed.Hdr.Name)
			if err != nil {
				return nil, nil, 0, fmt.Errorf("normalize CNAME owner: %w", err)
			}

			if _, found := cnames[owner]; found {
				return nil, nil, 0, fmt.Errorf("multiple CNAME records for %q", owner)
			}

			cnames[owner] = typed
		case *dns.A:
			if queryType != dns.TypeA {
				continue
			}

			owner, address, err := parseAddressRecord(typed.Hdr.Name, typed.A)
			if err != nil {
				return nil, nil, 0, err
			}

			addresses[owner] = append(addresses[owner], address)
		case *dns.AAAA:
			if queryType != dns.TypeAAAA {
				continue
			}

			owner, address, err := parseAddressRecord(typed.Hdr.Name, typed.AAAA)
			if err != nil {
				return nil, nil, 0, err
			}

			addresses[owner] = append(addresses[owner], address)
		}
	}

	current := queryHostname
	chain := []string{}
	minimumTTL := uint32(0)
	ttlSet := false

	for range maxCNAMEChain {
		cname, found := cnames[current]
		if !found {
			break
		}

		target, err := policy.NormalizeHostname(cname.Target)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("normalize CNAME target: %w", err)
		}

		if target == current || slicesContains(chain, target) {
			return nil, nil, 0, fmt.Errorf("CNAME chain contains a cycle")
		}

		chain = append(chain, target)
		minimumTTL = lowerTTL(minimumTTL, ttlSet, cname.Hdr.Ttl)
		ttlSet = true
		current = target
	}

	if _, found := cnames[current]; found {
		return nil, nil, 0, fmt.Errorf("CNAME chain exceeds %d records", maxCNAMEChain)
	}

	terminalAddresses := addresses[current]

	for _, record := range response.Answer {
		if record.Header().Name == "" {
			continue
		}

		owner, err := policy.NormalizeHostname(record.Header().Name)
		if err == nil && owner == current {
			switch record.(type) {
			case *dns.A, *dns.AAAA:
				minimumTTL = lowerTTL(minimumTTL, ttlSet, record.Header().Ttl)
				ttlSet = true
			}
		}
	}

	return chain, terminalAddresses, minimumTTL, nil
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

func packMalformedResponse(request []byte, rcode int) []byte {
	message := &dns.Msg{}
	message.Response = true

	message.Rcode = rcode
	if len(request) >= 2 {
		message.Id = binary.BigEndian.Uint16(request[:2])
	}

	return packMessage(message)
}

func packResponse(request *dns.Msg, rcode int) []byte {
	response := &dns.Msg{}
	response.SetRcode(request, rcode)

	return packMessage(response)
}

func packMessage(message *dns.Msg) []byte {
	contents, err := message.Pack()
	if err != nil {
		return nil
	}

	return contents
}

func readStreamMessage(connection net.Conn) ([]byte, error) {
	err := connection.SetReadDeadline(time.Now().Add(dnsStreamTimeout))
	if err != nil {
		return nil, fmt.Errorf("set DNS stream read deadline: %w", err)
	}

	contents, err := stream.ReadUint16Frame(connection, maxDNSMessageSize)
	if err != nil {
		return nil, fmt.Errorf("read DNS stream message: %w", err)
	}

	return contents, nil
}

func writeStreamMessage(connection net.Conn, contents []byte) error {
	err := connection.SetWriteDeadline(time.Now().Add(dnsStreamTimeout))
	if err != nil {
		return fmt.Errorf("set DNS stream write deadline: %w", err)
	}

	err = stream.WriteUint16Frame(connection, contents)
	if err != nil {
		return fmt.Errorf("write DNS stream message: %w", err)
	}

	return nil
}

func slicesContains(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}

	return false
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
