// Package namespace creates and configures airjail's Linux network namespace.
package namespace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const (
	internalIPv4Address       = "127.97.105.114"
	internalIPv6Address       = "fd61:6972:6a61:696c::1"
	HTTPAddress               = internalIPv4Address + ":19080"
	SOCKAddress               = internalIPv4Address + ":19081"
	transparentTCPIPv4Address = internalIPv4Address + ":19082"
	transparentTCPIPv6Address = "[" + internalIPv6Address + "]:19082"
	DNSIPv4Address            = internalIPv4Address + ":19053"
	DNSIPv6Address            = "[" + internalIPv6Address + "]:19053"
	transparentTCPPort        = 19082
	dnsPort                   = 19053
)

// Mode describes how airjail obtains and preserves namespace privileges.
type Mode uint8

const (
	// RootlessMode creates a user namespace and drops its setup capabilities.
	RootlessMode Mode = iota
	// PermissionPreservingMode uses existing capabilities without changing the caller's user namespace.
	PermissionPreservingMode
)

// DetectMode chooses the permission-preserving path when the caller can both
// create and configure a network namespace.
func DetectMode() (Mode, error) {
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}

	data := [2]unix.CapUserData{}

	err := unix.Capget(&header, &data[0])
	if err != nil {
		return RootlessMode, fmt.Errorf("read effective capabilities: %w", err)
	}

	if capabilityEffective(data, unix.CAP_SYS_ADMIN) && capabilityEffective(data, unix.CAP_NET_ADMIN) {
		return PermissionPreservingMode, nil
	}

	return RootlessMode, nil
}

func capabilityEffective(data [2]unix.CapUserData, capability int) bool {
	word := capability / 32
	bit := uint(capability % 32)

	return data[word].Effective&(uint32(1)<<bit) != 0
}

// ParentOptions configures the hidden supervisor process.
type ParentOptions struct {
	Executable             string
	Command                []string
	Environment            []string
	Directory              string
	HTTPSocket             string
	SOCKSocket             string
	DNSSocket              string
	Mode                   Mode
	RestrictUnixSockets    bool
	KeepUnsafeCapabilities []string
	TransparentTCP         bool
	PrivateLoopback        bool
	Logger                 *logging.Logger
}

// Run starts the hidden supervisor in fresh user and network namespaces.
func Run(ctx context.Context, options ParentOptions) (int, error) {
	keptCapabilities, err := resolveUnsafeCapabilities(options.KeepUnsafeCapabilities, options.Mode, options.Logger)
	if err != nil {
		return 0, err
	}

	// Decide this in the outer process because the hidden supervisor is never
	// its process-group leader. Detached sessions have no controlling terminal,
	// while foreground wrappers such as `go run` legitimately share a job group.
	terminal, foregroundProcessGroup := terminalForeground()

	transparentIPv6 := false
	if options.TransparentTCP {
		transparentIPv6, err = detectTransparentIPv6()
		if err != nil {
			return 0, err
		}

		if !transparentIPv6 {
			options.Logger.Infof("IPv6 transparent networking disabled because no IPv6 egress route was detected")
		}
	}

	invocation := cli.SupervisorInvocation{
		Command:                options.Command,
		HTTPSocket:             options.HTTPSocket,
		SOCKSocket:             options.SOCKSocket,
		DNSSocket:              options.DNSSocket,
		LogLevel:               options.Logger.LevelName(),
		PreservePermissions:    options.Mode == PermissionPreservingMode,
		RestrictUnixSockets:    options.RestrictUnixSockets,
		ManageForeground:       ownsTerminalForeground(terminal, foregroundProcessGroup, unix.Getpgrp()),
		KeepUnsafeCapabilities: keptCapabilities,
		TransparentTCP:         options.TransparentTCP,
		TransparentIPv6:        transparentIPv6,
		PrivateLoopback:        options.PrivateLoopback,
	}

	args, err := invocation.Args()
	if err != nil {
		return 0, err
	}

	arguments := append([]string{options.Executable, cli.SupervisorCommand}, args...)

	sys := namespaceProcessAttributes(options.Mode)

	exitCode, err := runSandboxedProcess(ctx, arguments, runOptions{
		Environment: options.Environment,
		Directory:   options.Directory,
		Sys:         sys,
		// Keep the hidden supervisor in airjail's shell job, only the actual
		// command gets a foreground process group.
		JoinParentProcessGroup: true,
		Logger:                 options.Logger,
	})
	if err != nil {
		if options.Mode == PermissionPreservingMode {
			return 0, fmt.Errorf("run permission-preserving network namespace supervisor: %w", err)
		}

		return 0, fmt.Errorf(
			"run rootless network namespace supervisor "+
				"(unprivileged user namespaces may be disabled by kernel or distro policy): %w",
			err,
		)
	}

	return exitCode, nil
}

type innerServer interface {
	Serve(ctx context.Context, listener net.Listener) error
}

type bridgeServer struct {
	listener net.Listener
	server   innerServer
}

type dnsPacketServer struct {
	connection *net.UDPConn
	forwarder  *dnsUDPForwarder
}

func namespaceProcessAttributes(mode Mode) *syscall.SysProcAttr {
	if mode == PermissionPreservingMode {
		return &syscall.SysProcAttr{
			Cloneflags: unix.CLONE_NEWNET,
			Pdeathsig:  syscall.SIGKILL,
		}
	}

	uid := os.Getuid()
	gid := os.Getgid()

	return &syscall.SysProcAttr{
		Cloneflags:                 unix.CLONE_NEWUSER | unix.CLONE_NEWNET,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: uid, HostID: uid, Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: gid, HostID: gid, Size: 1}},
		GidMappingsEnableSetgroups: false,
		AmbientCaps:                []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SETPCAP},
		Pdeathsig:                  syscall.SIGKILL,
	}
}

// SupervisorOptions configures the process already running inside the namespaces.
type SupervisorOptions struct {
	Command                []string
	Environment            []string
	Directory              string
	HTTPSocket             string
	SOCKSocket             string
	DNSSocket              string
	PreservePermissions    bool
	RestrictUnixSockets    bool
	ManageForeground       bool
	KeepUnsafeCapabilities []string
	TransparentTCP         bool
	TransparentIPv6        bool
	PrivateLoopback        bool
	Logger                 *logging.Logger
}

// RunSupervisor sets up the namespace and supervises the isolated command.
func RunSupervisor(ctx context.Context, options SupervisorOptions) (int, error) {
	options.Logger = options.Logger.WithPrefix("supervisor")

	for _, socketPath := range []string{options.HTTPSocket, options.SOCKSocket, options.DNSSocket} {
		if socketPath == "" {
			continue
		}

		err := validateProxySocket(socketPath)
		if err != nil {
			return 0, err
		}
	}

	err := bringLoopbackUp()
	if err != nil {
		return 0, err
	}

	if options.TransparentTCP {
		if options.SOCKSocket == "" {
			return 0, fmt.Errorf("transparent TCP requires an outer SOCKS socket")
		}

		if options.DNSSocket == "" {
			return 0, fmt.Errorf("transparent TCP requires an outer DNS socket")
		}

		err = configureTransparentRoutes(options.TransparentIPv6)
		if err != nil {
			return 0, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverCapacity := 2
	if options.TransparentTCP {
		serverCapacity += 4
	}

	servers := make([]bridgeServer, 0, serverCapacity)
	packetServers := make([]dnsPacketServer, 0, 2)

	listenConfig := net.ListenConfig{}
	gatewayListenConfig := newTransparentListenConfig()

	if options.HTTPSocket != "" {
		listener, err := listenConfig.Listen(ctx, "tcp4", HTTPAddress)
		if err != nil {
			return 0, fmt.Errorf("listen on inner HTTP proxy %s: %w", HTTPAddress, err)
		}

		options.Logger.WithPrefix("HTTP proxy bridge").Debugf("listening on %s in namespace", HTTPAddress)

		servers = append(servers, bridgeServer{listener: listener, server: newForwarder(options.HTTPSocket)})
	}

	if options.SOCKSocket != "" {
		listener, err := listenConfig.Listen(ctx, "tcp4", SOCKAddress)
		if err != nil {
			closeBridgeListeners(servers)

			return 0, fmt.Errorf("listen on inner SOCKS proxy %s: %w", SOCKAddress, err)
		}

		options.Logger.WithPrefix("SOCKS proxy bridge").Debugf("listening on %s in namespace", HTTPAddress)

		servers = append(servers, bridgeServer{listener: listener, server: newForwarder(options.SOCKSocket)})
	}

	if options.TransparentTCP {
		dnsServers, dnsPacketServers, setupErr := createDNSBridgeServers(
			ctx,
			&gatewayListenConfig,
			options.DNSSocket,
			options.TransparentIPv6,
			options.Logger.WithPrefix("DNS bridge"),
		)
		if setupErr != nil {
			closeBridgeListeners(servers)

			return 0, setupErr
		}

		servers = append(servers, dnsServers...)
		packetServers = append(packetServers, dnsPacketServers...)

		transparentServers, setupErr := createTransparentTCPServers(
			ctx,
			&gatewayListenConfig,
			options.SOCKSocket,
			options.DNSSocket,
			options.TransparentIPv6,
			options.Logger.WithPrefix("transparent TCP to SOCKS bridge"),
		)
		if setupErr != nil {
			closeBridgeListeners(servers)
			closeDNSPacketServers(packetServers)

			return 0, setupErr
		}

		servers = append(servers, transparentServers...)

		err = installTransparentRules(options.PrivateLoopback, options.TransparentIPv6)
		if err != nil {
			closeBridgeListeners(servers)
			closeDNSPacketServers(packetServers)

			return 0, err
		}
	}

	// Adopt orphaned command descendants so airjail can reap them instead of
	// leaving them to the host PID 1.
	err = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	if err != nil {
		closeBridgeListeners(servers)
		closeDNSPacketServers(packetServers)

		return 0, fmt.Errorf("set child subreaper: %w", err)
	}

	group, groupCtx := errgroup.WithContext(ctx)
	for _, server := range servers {
		group.Go(func() error {
			err := server.server.Serve(groupCtx, server.listener)
			if err != nil {
				return err
			}

			if groupCtx.Err() == nil {
				return fmt.Errorf("inner proxy bridge stopped unexpectedly")
			}

			return nil
		})
	}

	for _, server := range packetServers {
		group.Go(func() error {
			err := server.forwarder.Serve(groupCtx, server.connection)
			if err != nil {
				return err
			}

			if groupCtx.Err() == nil {
				return fmt.Errorf("inner DNS UDP bridge stopped unexpectedly")
			}

			return nil
		})
	}

	var (
		childExitCode int
		childErr      error
	)

	group.Go(func() error {
		defer cancel()

		command := options.Command
		if options.RestrictUnixSockets {
			executable, executableErr := os.Executable()
			if executableErr != nil {
				childErr = fmt.Errorf("locate airjail executable for restricted child: %w", executableErr)

				return nil
			}

			invocation := cli.RestrictedExecInvocation{Command: command, LogLevel: options.Logger.LevelName()}

			args, encodeErr := invocation.Args()
			if encodeErr != nil {
				childErr = encodeErr

				return nil
			}

			command = append([]string{executable, cli.RestrictedExecCommand}, args...)
		}

		childExitCode, childErr = runSupervisorChild(groupCtx, command, options)

		return nil
	})

	infrastructureErr := group.Wait()
	if childErr == nil {
		childErr = infrastructureErr
	}

	if childErr != nil {
		return 0, fmt.Errorf("run isolated command: %w", childErr)
	}

	return childExitCode, nil
}

func runSupervisorChild(ctx context.Context, command []string, options SupervisorOptions) (int, error) {
	// Capabilities and no_new_privs are thread-local. Fork the child from the
	// thread that drops them, and let Go retire it rather than reuse it.
	runtime.LockOSThread()

	childProcessAttributes, err := prepareChildCapabilities(options)
	if err != nil {
		return 0, err
	}

	return runSandboxedProcess(ctx, command, runOptions{
		Environment:      options.Environment,
		Directory:        options.Directory,
		Sys:              childProcessAttributes,
		ManageForeground: options.ManageForeground,
		ReapDescendants:  true,
		Logger:           options.Logger,
	})
}

func validateProxySocket(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("inspect outer proxy socket %q: %w", path, err)
	}

	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("outer proxy path %q is not a Unix socket", path)
	}

	return nil
}

func bringLoopbackUp() error {
	fileDescriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("open loopback control socket: %w", err)
	}
	defer func() { _ = unix.Close(fileDescriptor) }()

	request, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("create loopback interface request: %w", err)
	}

	err = unix.IoctlIfreq(fileDescriptor, unix.SIOCGIFFLAGS, request)
	if err != nil {
		return fmt.Errorf("read loopback flags: %w", err)
	}

	request.SetUint16(request.Uint16() | unix.IFF_UP)

	err = unix.IoctlIfreq(fileDescriptor, unix.SIOCSIFFLAGS, request)
	if err != nil {
		return fmt.Errorf("bring loopback up: %w", err)
	}

	return nil
}

func dropSetupCapabilities() error {
	for capability := range 64 {
		err := unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability), 0, 0, 0)
		if errors.Is(err, unix.EINVAL) {
			break
		}

		if err != nil {
			return fmt.Errorf("drop capability %d from bounding set: %w", capability, err)
		}
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}

	data := [2]unix.CapUserData{}

	err := unix.Capset(&header, &data[0])
	if err != nil {
		return fmt.Errorf("drop namespace capabilities: %w", err)
	}

	err = unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("set no_new_privs: %w", err)
	}

	return nil
}

func prepareChildCapabilities(options SupervisorOptions) (*syscall.SysProcAttr, error) {
	if !options.PreservePermissions {
		err := dropSetupCapabilities()
		if err != nil {
			return nil, err
		}

		options.Logger.Debugf("dropped all capabilities from effective, permitted, inheritable, ambient, and bounding sets")

		return nil, nil
	}

	err := dropDangerousCapabilities(options.KeepUnsafeCapabilities)
	if err != nil {
		return nil, err
	}

	ambientCapabilities, err := unsafeCapabilityValues(options.KeepUnsafeCapabilities)
	if err != nil {
		return nil, err
	}

	dropped := make([]string, 0, len(dangerousCapabilities))
	for _, capability := range dangerousCapabilities {
		if !slices.Contains(ambientCapabilities, uintptr(capability.value)) {
			dropped = append(dropped, capability.name)
		}
	}

	options.Logger.Debugf("dropped capabilities: %s", strings.Join(dropped, ", "))

	return &syscall.SysProcAttr{AmbientCaps: ambientCapabilities}, nil
}

func createDNSBridgeServers(
	ctx context.Context,
	listenConfig *net.ListenConfig,
	socketPath string,
	ipv6 bool,
	logger *logging.Logger,
) ([]bridgeServer, []dnsPacketServer, error) {
	servers := make([]bridgeServer, 0, 2)
	packetServers := make([]dnsPacketServer, 0, 2)

	for _, endpoint := range []struct {
		tcpNetwork string
		udpNetwork string
		address    string
	}{
		{tcpNetwork: "tcp4", udpNetwork: "udp4", address: DNSIPv4Address},
		{tcpNetwork: tcp6Network, udpNetwork: udp6Network, address: DNSIPv6Address},
	} {
		if endpoint.tcpNetwork == tcp6Network && !ipv6 {
			continue
		}

		listener, err := listenConfig.Listen(ctx, endpoint.tcpNetwork, endpoint.address)
		if err != nil {
			closeBridgeListeners(servers)
			closeDNSPacketServers(packetServers)

			return nil, nil, fmt.Errorf("listen on inner DNS TCP gateway %s: %w", endpoint.address, err)
		}

		logger.Debugf("listening on %s in namepspace", endpoint.address)

		servers = append(servers, bridgeServer{listener: listener, server: newForwarder(socketPath)})

		udpConnection, err := createDNSUDPSocket(ctx, listenConfig, endpoint.udpNetwork, endpoint.address)
		if err != nil {
			closeBridgeListeners(servers)
			closeDNSPacketServers(packetServers)

			return nil, nil, fmt.Errorf("listen on inner DNS UDP gateway %s: %w", endpoint.address, err)
		}

		packetServers = append(packetServers, dnsPacketServer{
			connection: udpConnection,
			forwarder:  newDNSUDPForwarder(socketPath, logger),
		})
	}

	return servers, packetServers, nil
}

func createTransparentTCPServers(
	ctx context.Context,
	listenConfig *net.ListenConfig,
	socketPath string,
	dnsSocketPath string,
	ipv6 bool,
	logger *logging.Logger,
) ([]bridgeServer, error) {
	servers := make([]bridgeServer, 0, 2)

	for _, endpoint := range []struct {
		network string
		address string
	}{
		{network: "tcp4", address: transparentTCPIPv4Address},
		{network: tcp6Network, address: transparentTCPIPv6Address},
	} {
		if endpoint.network == tcp6Network && !ipv6 {
			continue
		}

		listener, err := listenConfig.Listen(ctx, endpoint.network, endpoint.address)
		if err != nil {
			closeBridgeListeners(servers)

			return nil, fmt.Errorf("listen on inner transparent TCP gateway %s: %w", endpoint.address, err)
		}

		logger.Debugf("listening on %s in namepspace", endpoint.address)

		transparentServer, err := newTransparentTCPForwarder(socketPath, dnsSocketPath, logger)
		if err != nil {
			_ = listener.Close()

			closeBridgeListeners(servers)

			return nil, err
		}

		servers = append(servers, bridgeServer{listener: listener, server: transparentServer})
	}

	return servers, nil
}

func closeBridgeListeners(servers []bridgeServer) {
	for _, server := range servers {
		_ = server.listener.Close()
	}
}

func closeDNSPacketServers(servers []dnsPacketServer) {
	for _, server := range servers {
		_ = server.connection.Close()
	}
}
