package proxydns

import (
	"context"
	"encoding/binary"
	"fmt"
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
		server.logDecision(false, query)

		return packResponse(query.request, dns.RcodeRefused)
	}

	if !server.acquireQuery(ctx) {
		return packResponse(query.request, dns.RcodeServerFailure)
	}
	defer server.releaseQuery()

	upstreamRequest := newUpstreamRequest(query)

	upstreamResponse, err := server.upstream.Exchange(ctx, upstreamRequest)
	if err != nil {
		server.logger.Debugf("resolve DNS question %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	err = validateUpstreamResponse(upstreamRequest, upstreamResponse)
	if err != nil {
		server.logger.Debugf("validate DNS response for %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	upstreamResponse.Id = query.request.Id
	upstreamResponse.Question = query.request.Question

	if upstreamResponse.Rcode != dns.RcodeSuccess {
		server.logDecision(true, query)

		return packMessage(upstreamResponse)
	}

	answer, err := parseAddressAnswer(upstreamResponse, query.hostname, query.queryType)
	if err != nil {
		server.logger.Debugf("parse DNS response for %s: %v", query.hostname, err)

		return packResponse(query.request, dns.RcodeServerFailure)
	}

	if !answer.empty() {
		allowed, err = server.policy.CommitResolution(authorization, answer.policyResult(now), now)
		if err != nil {
			server.logger.Debugf("record DNS response for %s: %v", query.hostname, err)

			return packResponse(query.request, dns.RcodeServerFailure)
		}

		if !allowed {
			server.logDecision(false, query)

			return packResponse(query.request, dns.RcodeRefused)
		}
	}

	server.logDecision(true, query)

	return packMessage(upstreamResponse)
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

func (server *Server) logDecision(allowed bool, query clientQuery) {
	if allowed {
		server.logger.Allowf("dns %s %s", dns.TypeToString[query.queryType], query.hostname)
	} else {
		server.logger.Blockf("dns %s %s", dns.TypeToString[query.queryType], query.hostname)
	}
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
