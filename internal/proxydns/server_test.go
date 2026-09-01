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

func TestDNSAnswerBlockedByAddressIsRefused(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"example.com"}, []string{"192.0.2.10"}, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{192, 0, 2, 10},
		}}

		return response
	})

	response := exchangeTestQuery(t, server, "example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("response code = %s, want REFUSED", dns.RcodeToString[response.Rcode])
	}
}

func TestDNSMixedAddressAnswerIsRefused(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"example.com"}, []string{"192.0.2.10"}, func(request *dns.Msg) *dns.Msg {
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

	response := exchangeTestQuery(t, server, "example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("response code = %s, want REFUSED", dns.RcodeToString[response.Rcode])
	}
}

func TestDNSCIDRPolicyProvisionallyResolvesUnknownHostname(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"10.0.0.0/8"}, nil, func(request *dns.Msg) *dns.Msg {
		response := new(dns.Msg)
		response.SetReply(request)
		response.Answer = []dns.RR{&dns.A{
			Hdr: dns.RR_Header{Name: request.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 60},
			A:   []byte{10, 2, 3, 4},
		}}

		return response
	})

	response := exchangeTestQuery(t, server, "unknown.internal.", dns.TypeA)
	if response.Rcode != dns.RcodeSuccess {
		t.Fatalf("response code = %s, want NOERROR", dns.RcodeToString[response.Rcode])
	}
}

func TestDNSCNAMEBlockVetoesAllowedOriginalName(t *testing.T) {
	t.Parallel()

	server, _ := newTestServer(t, []string{"example.com"}, []string{"blocked.cdn.test"}, func(request *dns.Msg) *dns.Msg {
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
	})

	response := exchangeTestQuery(t, server, "example.com.", dns.TypeA)
	if response.Rcode != dns.RcodeRefused {
		t.Fatalf("response code = %s, want REFUSED", dns.RcodeToString[response.Rcode])
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
) (*Server, *policy.Policy) {
	t.Helper()

	resolver := resolverFunc(func(context.Context, string, string) ([]netip.Addr, error) {
		return nil, nil
	})

	networkPolicy, err := policy.New(t.Context(), allowRules, blockRules, policy.Options{
		Resolver:        resolver,
		AllowUnresolved: true,
	})
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
