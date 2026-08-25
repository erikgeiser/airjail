// Package namespace creates and configures airjail's Linux network namespace.
package namespace

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"

	"github.com/erikgeiser/airjail/internal/bridge"
	"github.com/erikgeiser/airjail/internal/cli"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const (
	HTTPAddress = "127.0.0.1:19080"
	SOCKAddress = "127.0.0.1:19081"
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
	Executable          string
	Command             []string
	Environment         []string
	Directory           string
	HTTPSocket          string
	SOCKSocket          string
	Mode                Mode
	RestrictUnixSockets bool
}

// Run starts the hidden supervisor in fresh user and network namespaces.
func Run(ctx context.Context, options ParentOptions) (int, error) {
	arguments := []string{options.Executable, cli.SupervisorCommand}
	if options.HTTPSocket != "" {
		arguments = append(arguments, "--"+cli.SupervisorHTTPSocketOption, options.HTTPSocket)
	}

	if options.SOCKSocket != "" {
		arguments = append(arguments, "--"+cli.SupervisorSOCKSSocketOption, options.SOCKSocket)
	}

	if options.Mode == PermissionPreservingMode {
		arguments = append(arguments, "--"+cli.SupervisorPreservePermissionsOption)
	}

	if options.RestrictUnixSockets {
		arguments = append(arguments, "--"+cli.SupervisorRestrictSocketsOption)
	}

	arguments = append(arguments, "--")
	arguments = append(arguments, options.Command...)

	sys := namespaceProcessAttributes(options.Mode)

	exitCode, err := runSupervisor(ctx, arguments, runOptions{
		Environment: options.Environment,
		Directory:   options.Directory,
		Sys:         sys,
		// Keep the hidden supervisor in airjail's shell job, only the actual
		// command gets a foreground process group.
		JoinParentProcessGroup: true,
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

type bridgeServer struct {
	listener  net.Listener
	forwarder *bridge.Forwarder
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
	Command             []string
	Environment         []string
	Directory           string
	HTTPSocket          string
	SOCKSocket          string
	PreservePermissions bool
	RestrictUnixSockets bool
}

// RunSupervisor configures loopback, starts bridges, and supervises the command.
func RunSupervisor(ctx context.Context, options SupervisorOptions) (int, error) {
	for _, socketPath := range []string{options.HTTPSocket, options.SOCKSocket} {
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	servers := make([]bridgeServer, 0, 2)

	listenConfig := net.ListenConfig{}
	if options.HTTPSocket != "" {
		listener, err := listenConfig.Listen(ctx, "tcp4", HTTPAddress)
		if err != nil {
			return 0, fmt.Errorf("listen on inner HTTP proxy %s: %w", HTTPAddress, err)
		}

		servers = append(servers, bridgeServer{listener: listener, forwarder: bridge.New(options.HTTPSocket)})
	}

	if options.SOCKSocket != "" {
		listener, err := listenConfig.Listen(ctx, "tcp4", SOCKAddress)
		if err != nil {
			closeBridgeListeners(servers)

			return 0, fmt.Errorf("listen on inner SOCKS proxy %s: %w", SOCKAddress, err)
		}

		servers = append(servers, bridgeServer{listener: listener, forwarder: bridge.New(options.SOCKSocket)})
	}

	// Adopt orphaned command descendants so airjail can reap them instead of
	// leaving them to the host PID 1.
	err = unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
	if err != nil {
		closeBridgeListeners(servers)

		return 0, fmt.Errorf("set child subreaper: %w", err)
	}

	if !options.PreservePermissions {
		err = dropSetupCapabilities()
		if err != nil {
			closeBridgeListeners(servers)

			return 0, err
		}
	}

	group, groupCtx := errgroup.WithContext(ctx)
	for _, server := range servers {
		group.Go(func() error {
			err := server.forwarder.Serve(groupCtx, server.listener)
			if err != nil {
				return err
			}

			if groupCtx.Err() == nil {
				return fmt.Errorf("inner proxy bridge stopped unexpectedly")
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

			command = append([]string{executable, cli.RestrictedExecCommand, "--"}, command...)
		}

		childExitCode, childErr = runSupervisor(groupCtx, command, runOptions{
			Environment:      options.Environment,
			Directory:        options.Directory,
			ReapProcessGroup: true,
		})

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

func closeBridgeListeners(servers []bridgeServer) {
	for _, server := range servers {
		_ = server.listener.Close()
	}
}
