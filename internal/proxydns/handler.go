package proxydns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/miekg/dns"
)

type clientQuery struct {
	request   *dns.Msg
	hostname  string
	queryType uint16
}

func (server *Server) handle(ctx context.Context, wireRequest []byte) []byte {
	query, errorResponse := validateClientRequest(wireRequest)
	if errorResponse != nil {
		return errorResponse
	}

	now := time.Now()

	authorization, allowed, err := server.policy.BeginResolution(query.hostname, now)
	if err != nil {
		server.logger.Debugf("evaluate DNS question %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	if !allowed {
		server.logger.Blockf(dns.TypeToString[query.queryType] + " " + query.hostname)

		return packResponse(query.request, dns.RcodeRefused)
	}

	addresses, snapshotted, err := server.policy.StaticAddresses(query.hostname)
	if err != nil {
		server.logger.Debugf("read DNS snapshot for %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	if snapshotted {
		server.logger.Allowf(dns.TypeToString[query.queryType] + " " + query.hostname)

		return packAddressResponse(query, addresses, uint32(minimumGrantTTL/time.Second))
	}

	if server.resolver == nil {
		server.logger.Debugf("no upstream resolver is configured for %s", query.hostname)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	if !server.acquireQuery(ctx) {
		return packResponse(query.request, dns.RcodeServerFailure)
	}
	defer server.releaseQuery()

	network := "ip4"
	if query.queryType == dns.TypeAAAA {
		network = "ip6"
	}

	result, err := server.resolver.Resolve(ctx, network, query.hostname)
	if err != nil {
		server.logger.Debugf("resolve DNS question %s: %v", query.hostname, err)

		responseCodeErr := &responseCodeError{}
		if errors.As(err, &responseCodeErr) {
			return packResponse(query.request, responseCodeErr.code)
		}

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	_, err = server.policy.CommitResolution(authorization, result, now)
	if err != nil {
		server.logger.Debugf("record DNS response for %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	server.logger.Allowf(dns.TypeToString[query.queryType] + " " + query.hostname)

	ttlDuration := time.Until(result.ExpiresAt)
	if ttlDuration < minimumGrantTTL {
		ttlDuration = minimumGrantTTL
	}

	if ttlDuration > maximumGrantTTL {
		ttlDuration = maximumGrantTTL
	}

	return packAddressResponse(query, result.Addresses, uint32(ttlDuration/time.Second))
}

func validateClientRequest(wireRequest []byte) (clientQuery, []byte) {
	request := &dns.Msg{}

	err := request.Unpack(wireRequest)
	if err != nil {
		return clientQuery{}, packMalformedResponse(wireRequest, dns.RcodeFormatError)
	}

	if request.Response || request.Opcode != dns.OpcodeQuery || len(request.Question) != 1 {
		return clientQuery{}, packResponse(request, dns.RcodeFormatError)
	}

	question := request.Question[0]
	if question.Qclass != dns.ClassINET {
		return clientQuery{}, packResponse(request, dns.RcodeNotImplemented)
	}

	if question.Qtype != dns.TypeA && question.Qtype != dns.TypeAAAA {
		return clientQuery{}, packResponse(request, dns.RcodeNotImplemented)
	}

	hostname, err := policy.NormalizeHostname(question.Name)
	if err != nil {
		return clientQuery{}, packResponse(request, dns.RcodeFormatError)
	}

	return clientQuery{request: request, hostname: hostname, queryType: question.Qtype}, nil
}

func (server *Server) acquireQuery(ctx context.Context) bool {
	select {
	case server.queries <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	default:
		return false
	}
}

func (server *Server) releaseQuery() {
	<-server.queries
}

func newUpstreamRequest(query clientQuery) *dns.Msg {
	request := &dns.Msg{}
	request.SetQuestion(dns.Fqdn(query.hostname), query.queryType)
	request.Id = dns.Id()
	request.RecursionDesired = true
	request.CheckingDisabled = query.request.CheckingDisabled

	if clientEDNS := query.request.IsEdns0(); clientEDNS != nil {
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

func packAddressResponse(query clientQuery, addresses []netip.Addr, ttl uint32) []byte {
	response := new(dns.Msg)
	response.SetReply(query.request)

	for _, address := range addresses {
		header := dns.RR_Header{
			Name:  dns.Fqdn(query.hostname),
			Class: dns.ClassINET,
			Ttl:   ttl,
		}

		switch {
		case query.queryType == dns.TypeA && address.Is4():
			header.Rrtype = dns.TypeA
			response.Answer = append(response.Answer, &dns.A{Hdr: header, A: address.AsSlice()})
		case query.queryType == dns.TypeAAAA && address.Is6():
			header.Rrtype = dns.TypeAAAA
			response.Answer = append(response.Answer, &dns.AAAA{Hdr: header, AAAA: address.AsSlice()})
		}
	}

	return packMessage(response)
}

func packMalformedResponse(request []byte, responseCode int) []byte {
	message := &dns.Msg{}
	message.Response = true
	message.Rcode = responseCode

	if len(request) >= 2 {
		message.Id = binary.BigEndian.Uint16(request[:2])
	}

	return packMessage(message)
}

func packResponse(request *dns.Msg, responseCode int) []byte {
	response := &dns.Msg{}
	response.SetRcode(request, responseCode)

	return packMessage(response)
}

func packMessage(message *dns.Msg) []byte {
	contents, err := message.Pack()
	if err != nil {
		return nil
	}

	return contents
}
