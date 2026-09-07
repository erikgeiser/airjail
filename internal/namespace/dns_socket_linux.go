package namespace

import (
	"context"
	"fmt"
	"net"
)

func createDNSUDPSocket(ctx context.Context, network, address string) (*net.UDPConn, error) {
	packetConnection, err := (&net.ListenConfig{}).ListenPacket(ctx, network, address)
	if err != nil {
		return nil, err
	}

	udpConnection, ok := packetConnection.(*net.UDPConn)
	if !ok {
		_ = packetConnection.Close()

		return nil, fmt.Errorf("listen on DNS UDP socket: unexpected type %T", packetConnection)
	}

	return udpConnection, nil
}
