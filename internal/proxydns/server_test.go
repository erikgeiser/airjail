//nolint:goconst // Repeated DNS names keep complete proxy scenarios visible.
package proxydns

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/miekg/dns"
)

type resolverFunc func(context.Context, string, string) ([]netip.Addr, error)

func (resolver resolverFunc) LookupNetIP(ctx context.Context, network, hostname string) ([]netip.Addr, error) {
	return resolver(ctx, network, hostname)
}

type upstreamFunc func(context.Context, *dns.Msg) (*dns.Msg, error)

func (upstream upstreamFunc) Exchange(ctx context.Context, request *dns.Msg) (*dns.Msg, error) {
	return upstream(ctx, request)
}

func TestDNSPrivateLoopbackReturnsSyntheticLocalhostAnswers(t *testing.T) {
	t.Parallel()

	called := false
	server, _ := newTestServer(t, []string{"192.0.2.0/24"}, nil, func(request *dns.Msg) *dns.Msg {
		called = true

		response := new(dns.Msg)
		response.SetReply(request)

		return response
	})
	server.privateLoopback = true

	tests := []struct {
		hostname  string
		queryType uint16
		want      string
	}{
		{hostname: "localhost.", queryType: dns.TypeA, want: "127.0.0.1"},
		{hostname: "service.localhost.", queryType: dns.TypeAAAA, want: "::1"},
	}

	for _, test := range tests {
		response := exchangeTestQuery(t, server, test.hostname, test.queryType)
		if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
			t.Fatalf(
				"response for %s = %s with %d answers",
				test.hostname,
				dns.RcodeToString[response.Rcode],
				len(response.Answer),
			)
		}

		address := response.Answer[0].String()
		if test.queryType == dns.TypeA {
			if record, ok := response.Answer[0].(*dns.A); !ok || record.A.String() != test.want {
				t.Errorf("answer for %s = %s, want %s", test.hostname, address, test.want)
			}
		} else if record, ok := response.Answer[0].(*dns.AAAA); !ok || record.AAAA.String() != test.want {
			t.Errorf("answer for %s = %s, want %s", test.hostname, address, test.want)
		}
	}

	if called {
		t.Fatal("private localhost query reached upstream resolver")
	}
}

func TestDNSConfiguredSnapshotDoesNotReachUpstream(t *testing.T) {
	t.Parallel()

	called := false
	server, _ := newTestServer(t, []string{"foo.bar@10.0.0.1@2001:db8::1"}, nil, func(request *dns.Msg) *dns.Msg {
		called = true

		response := new(dns.Msg)
		response.SetReply(request)

		return response
	})

	response := exchangeTestQuery(t, server, "foo.bar.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("A response = %s with %d answers", dns.RcodeToString[response.Rcode], len(response.Answer))
	}

	response = exchangeTestQuery(t, server, "foo.bar.", dns.TypeAAAA)
	if response.Rcode != dns.RcodeSuccess || len(response.Answer) != 1 {
		t.Fatalf("AAAA response = %s with %d answers", dns.RcodeToString[response.Rcode], len(response.Answer))
	}

	if called {
		t.Fatal("configured snapshot reached upstream resolver")
	}
}

func TestDNSAnswerInstallsTransparentAddressGrant(t *testing.T) {
	t.Parallel()

	server, networkPolicy := newTestServer(t, []string{"*.example.com"}, nil, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 10},
		}}

		return response
	})

	response := exchangeTestQuery(t, server, "service.example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}

	allowed, err := networkPolicy.Allows("", netip.MustParseAddr("192.0.2.10"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("DNS answer did not authorize a transparent direct-IP connection")
	}
}

func TestDNSAnswerBlockIsEnforcedAtConnectionTime(t *testing.T) {
	t.Parallel()

	server, networkPolicy := newTestServer(
		t,
		[]string{"*.example.com"},
		[]string{"192.0.2.10"},
		func(request *dns.Msg) *dns.Msg {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{192, 0, 2, 10},
			}}

			return response
		},
	)

	response := exchangeTestQuery(t, server, "service.example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}

	allowed, err := networkPolicy.Allows("", netip.MustParseAddr("192.0.2.10"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if allowed {
		t.Fatal("blocked DNS address was allowed for connection")
	}
}

func TestDNSMixedAddressAnswerIsReturnedWithoutBypassingBlocks(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"*.example.com"}, []string{"192.0.2.10"}, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{
			&dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{192, 0, 2, 10},
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
				A:   []byte{192, 0, 2, 11},
			},
		}

		return response
	})

	response := exchangeTestQuery(t, server, "service.example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}

	if len(response.Answer) != 2 {
		t.Errorf("answer count = %d, want 2", len(response.Answer))
	}
}

func TestDNSCIDRPolicyResolvesUnknownHostnameWhenArbitraryDNSIsEnabled(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"10.0.0.0/8"}, nil, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{10, 2, 3, 4},
		}}

		return response
	}, policy.Options{AllowArbitraryDNS: true})

	response := exchangeTestQuery(t, server, "unknown.internal.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
}

func TestDNSCNAMEBlockVetoesConnection(t *testing.T) {
	t.Parallel()

	server, networkPolicy := newTestServer(
		t,
		[]string{"*.example.com"},
		[]string{"blocked.cdn.test"},
		func(request *dns.Msg) *dns.Msg {
			response := new(dns.Msg)
			response.SetReply(request)
			response.Answer = []dns.RR{
				&dns.CNAME{
					Hdr:    dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
					Target: "blocked.cdn.test.",
				},
				&dns.A{
					Hdr: dns.RR_Header{Name: "blocked.cdn.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
					A:   []byte{192, 0, 2, 10},
				},
			}

			return response
		},
	)

	response := exchangeTestQuery(t, server, "service.example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}

	allowed, err := networkPolicy.Allows("", netip.MustParseAddr("192.0.2.10"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if allowed {
		t.Fatal("address learned through blocked CNAME was allowed")
	}
}

func TestDNSChainedCNAMEsAuthorizeTerminalAddress(t *testing.T) {
	t.Parallel()

	server, networkPolicy := newTestServer(t, []string{"*.example.com"}, nil, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "edge.cdn.test.",
			},
			&dns.CNAME{
				Hdr:    dns.RR_Header{Name: "edge.cdn.test.", Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
				Target: "region.cdn.test.",
			},
			&dns.A{
				Hdr: dns.RR_Header{Name: "region.cdn.test.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20},
				A:   []byte{192, 0, 2, 40},
			},
		}

		return response
	})

	response := exchangeTestQuery(t, server, "service.example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}

	allowed, err := networkPolicy.Allows("", netip.MustParseAddr("192.0.2.40"), 443)
	if err != nil {
		t.Fatalf("Allows: %v", err)
	}

	if !allowed {
		t.Fatal("terminal address from chained CNAMEs was not authorized")
	}
}

func TestDNSBlockOnlyPolicyRejectsQueryBeforeUpstream(t *testing.T) {
	t.Parallel()

	called := false
	server, _ := newTestServer(t, nil, []string{"blocked.example"}, func(request *dns.Msg) *dns.Msg {
		called = true

		response := new(dns.Msg)
		response.SetReply(request)

		return response
	})

	response := exchangeTestQuery(t, server, "data.c2.example.", dns.TypeA)
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("response code = %s, want REFUSED", dns.RcodeToString[response.Rcode])
	}

	if called {
		t.Fatal("block-only query reached upstream resolver")
	}
}

func TestDNSUnsupportedQueryDoesNotReachUpstream(t *testing.T) {
	t.Parallel()

	called := false
	server, _ := newTestServer(t, []string{"example.com"}, nil, func(request *dns.Msg) *dns.Msg {
		called = true

		response := new(dns.Msg)
		response.SetReply(request)

		return response
	})

	response := exchangeTestQuery(t, server, "example.com.", dns.TypeHTTPS)
	if response.Rcode != dns.RcodeNotImplemented {
		t.Fatalf("response code = %s, want NOTIMP", dns.RcodeToString[response.Rcode])
	}

	if called {
		t.Fatal("unsupported query reached upstream resolver")
	}
}

func newTestServer(
	t *testing.T,
	allowRules []string,
	blockRules []string,
	respond func(*dns.Msg) *dns.Msg,
	additionalOptions ...policy.Options,
) (*Server, *policy.Policy) {
	t.Helper()

	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, nil
	})

	options := policy.Options{Resolver: resolver, AllowUnresolved: true}
	if len(additionalOptions) > 0 {
		options.AllowArbitraryDNS = additionalOptions[0].AllowArbitraryDNS
	}

	networkPolicy, err := policy.New(t.Context(), allowRules, blockRules, options)
	if err != nil {
		t.Fatalf("policy.New: %v", err)
	}

	upstream := upstreamFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		return respond(request), nil
	})

	server, err := New(networkPolicy, upstream, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	return server, networkPolicy
}

func exchangeTestQuery(t *testing.T, server *Server, hostname string, queryType uint16) *dns.Msg {
	t.Helper()

	request := new(dns.Msg)
	request.SetQuestion(hostname, queryType)
	request.Id = 1234

	wireRequest, err := request.Pack()
	if err != nil {
		t.Fatalf("pack request: %v", err)
	}

	wireResponse := server.handle(context.Background(), wireRequest)
	if len(wireResponse) == 0 {
		t.Fatal("DNS server returned an empty response")
	}

	response := new(dns.Msg)

	err = response.Unpack(wireResponse)
	if err != nil {
		t.Fatalf("unpack response: %v", err)
	}

	if response.Id != request.Id {
		t.Errorf("response ID = %d, want %d", response.Id, request.Id)
	}

	return response
}

func TestClampTTL(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ttl  uint32
		want time.Duration
	}{
		{name: "zero", want: minimumGrantTTL},
		{name: "ordinary", ttl: 60, want: time.Minute},
		{name: "maximum", ttl: 86400, want: maximumGrantTTL},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if got := clampTTL(test.ttl); got != test.want {
				t.Errorf("clampTTL(%d) = %s, want %s", test.ttl, got, test.want)
			}
		})
	}
}
