//nolint:goconst // Repeated names keep the CNAME chain scenario readable.
package proxydns

import (
	"context"
	"net/netip"
	"slices"
	"testing"

	"github.com/miekg/dns"
)

func TestResolverFollowsIncompleteCNAMEChain(t *testing.T) {
	t.Parallel()

	queries := []string{}
	upstream := upstreamFunc(func(_ context.Context, request *dns.Msg) (*dns.Msg, error) {
		hostname := request.Question[0].Name
		queries = append(queries, hostname)

		response := new(dns.Msg)
		response.SetReply(request)

		switch hostname {
		case "example.com.":
			response.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: hostname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 60},
				Target: "edge.cdn.test.",
			}}
		case "edge.cdn.test.":
			response.Answer = []dns.RR{&dns.CNAME{
				Hdr:    dns.RR_Header{Name: hostname, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 30},
				Target: "region.cdn.test.",
			}}
		case "region.cdn.test.":
			response.Answer = []dns.RR{&dns.A{
				Hdr: dns.RR_Header{Name: hostname, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 20},
				A:   []byte{192, 0, 2, 10},
			}}
		default:
			t.Fatalf("unexpected query %q", hostname)
		}

		return response, nil
	})

	resolver, err := NewResolver(upstream)
	if err != nil {
		t.Fatalf("NewResolver: %v", err)
	}

	result, err := resolver.Resolve(t.Context(), "ip4", "example.com")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}

	wantQueries := []string{"example.com.", "edge.cdn.test.", "region.cdn.test."}
	if !slices.Equal(queries, wantQueries) {
		t.Errorf("queries = %v, want %v", queries, wantQueries)
	}

	wantChain := []string{"edge.cdn.test", "region.cdn.test"}
	if !slices.Equal(result.CNAMEChain, wantChain) {
		t.Errorf("CNAME chain = %v, want %v", result.CNAMEChain, wantChain)
	}

	wantAddresses := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	if !slices.Equal(result.Addresses, wantAddresses) {
		t.Errorf("addresses = %v, want %v", result.Addresses, wantAddresses)
	}
}
