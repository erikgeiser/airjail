package namespace

import (
	"fmt"
	"net"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/binaryutil"
	"github.com/google/nftables/expr"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const transparentTableName = "airjail-transparent"

func configureTransparentRoutes() error {
	loopback, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("find loopback for transparent routing: %w", err)
	}

	internalIPv6 := netip.MustParseAddr(internalIPv6Address)
	internalIPv6Prefix := &net.IPNet{
		IP:   net.IP(internalIPv6.AsSlice()),
		Mask: net.CIDRMask(128, 128),
	}

	err = netlink.AddrReplace(loopback, &netlink.Addr{IPNet: internalIPv6Prefix})
	if err != nil {
		return fmt.Errorf("assign transparent IPv6 gateway to loopback: %w", err)
	}

	routes := []netlink.Route{
		{
			LinkIndex: loopback.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)},
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
		},
		{
			LinkIndex: loopback.Attrs().Index,
			Dst:       &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)},
			Scope:     netlink.SCOPE_HOST,
			Type:      unix.RTN_LOCAL,
		},
	}

	for _, route := range routes {
		err = netlink.RouteAdd(&route)
		if err != nil {
			return fmt.Errorf("add transparent route %s: %w", route.Dst, err)
		}
	}

	return nil
}

func installTransparentRules() error {
	connection, err := nftables.New()
	if err != nil {
		return fmt.Errorf("open nftables connection: %w", err)
	}

	addTransparentTable(
		connection,
		nftables.TableFamilyIPv4,
		netip.MustParseAddr(internalIPv4Address),
		unix.NFPROTO_IPV4,
		16,
		[]uint16{19080, 19081, transparentTCPPort, dnsPort},
	)
	addTransparentTable(
		connection,
		nftables.TableFamilyIPv6,
		netip.MustParseAddr(internalIPv6Address),
		unix.NFPROTO_IPV6,
		24,
		[]uint16{transparentTCPPort, dnsPort},
	)

	err = connection.Flush()
	if err != nil {
		return fmt.Errorf("install transparent nftables rules: %w", err)
	}

	return nil
}

func addTransparentTable(
	connection *nftables.Conn,
	family nftables.TableFamily,
	gateway netip.Addr,
	natFamily uint32,
	destinationOffset uint32,
	exemptPorts []uint16,
) {
	table := connection.AddTable(&nftables.Table{Family: family, Name: transparentTableName})
	chain := connection.AddChain(&nftables.Chain{
		Name:     "output",
		Table:    table,
		Hooknum:  nftables.ChainHookOutput,
		Priority: nftables.ChainPriorityNATDest,
		Type:     nftables.ChainTypeNAT,
	})
	preroutingChain := connection.AddChain(&nftables.Chain{
		Name:     "prerouting",
		Table:    table,
		Hooknum:  nftables.ChainHookPrerouting,
		Priority: nftables.ChainPriorityMangle,
		Type:     nftables.ChainTypeFilter,
	})

	for _, port := range exemptPorts {
		connection.AddRule(&nftables.Rule{
			Table: table,
			Chain: chain,
			Exprs: append(
				matchTCPDestination(gateway, destinationOffset, port),
				&expr.Verdict{Kind: expr.VerdictReturn},
			),
		})
	}

	connection.AddRule(&nftables.Rule{
		Table: table,
		Chain: preroutingChain,
		Exprs: transparentDNSUDPExpressions(family),
	})

	connection.AddRule(&nftables.Rule{
		Table: table,
		Chain: chain,
		Exprs: []expr.Any{
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
			&expr.Immediate{Register: 1, Data: gateway.AsSlice()},
			&expr.Immediate{Register: 2, Data: binaryutil.BigEndian.PutUint16(transparentTCPPort)},
			&expr.NAT{
				Type:        expr.NATTypeDestNAT,
				Family:      natFamily,
				RegAddrMin:  1,
				RegProtoMin: 2,
			},
		},
	})
}

func transparentDNSUDPExpressions(family nftables.TableFamily) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_UDP}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(53)},
		&expr.Immediate{Register: 1, Data: binaryutil.BigEndian.PutUint16(dnsPort)},
		&expr.TProxy{
			Family:      byte(family),
			TableFamily: byte(family),
			RegPort:     1,
		},
	}
}

func matchTCPDestination(address netip.Addr, destinationOffset uint32, port uint16) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{unix.IPPROTO_TCP}},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseNetworkHeader,
			Offset:       destinationOffset,
			Len:          uint32(len(address.AsSlice())),
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: address.AsSlice()},
		&expr.Payload{
			DestRegister: 1,
			Base:         expr.PayloadBaseTransportHeader,
			Offset:       2,
			Len:          2,
		},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: binaryutil.BigEndian.PutUint16(port)},
	}
}
