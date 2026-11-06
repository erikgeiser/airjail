package namespace

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sys/unix"
)

// SocketOptions controls exceptions to the child's local socket restrictions.
type SocketOptions struct {
	AllowSockets    []string
	AllowAllSockets bool
	AllowVSocks     bool
}

func requiresSocketRestrictions(allowAllSockets, allowVSocks bool) bool {
	return !allowAllSockets || !allowVSocks
}

// ExecRestricted installs child socket restrictions and replaces the current process with command.
func ExecRestricted(command []string, options SocketOptions, logger *logging.Logger) error {
	if len(command) == 0 {
		return fmt.Errorf("restricted child command is required")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("look up restricted command %q: %w", command[0], err)
	}

	landlockEnabled := false

	if !options.AllowAllSockets {
		abi, abiErr := landlockABIVersion()
		if abiErr != nil && !landlockUnavailable(abiErr) {
			return fmt.Errorf("restrict local sockets: %w", abiErr)
		}

		landlockEnabled = abiErr == nil && landlockUnixSocketsAvailable(abi, runtime.GOARCH)
		if !landlockEnabled {
			logger.Warnf("landlock unix socket isolation is unavailable, restricting all unix sockets")

			if len(options.AllowSockets) != 0 {
				logger.Warnf("--allow-socket requires Landlock ABI 9")
			}
		}
	}

	// no_new_privs is per-thread until Landlock and seccomp synchronize the
	// restriction, so the goroutine must not move between kernel threads.
	runtime.LockOSThread()

	defer runtime.UnlockOSThread()

	err = seccomp.SetNoNewPrivs()
	if err != nil {
		return fmt.Errorf("restrict local sockets: set no_new_privs: %w", err)
	}

	if landlockEnabled {
		err = restrictExternalUnixSockets(options.AllowSockets)
		if err != nil {
			return fmt.Errorf("restrict local sockets: %w", err)
		}
	}

	denyUnixSockets := !options.AllowAllSockets && !landlockEnabled

	denyVSocks := !options.AllowVSocks
	if denyUnixSockets || denyVSocks {
		err = loadNativeArchitectureGuard()
		if err != nil {
			return fmt.Errorf("restrict local sockets: %w", err)
		}

		err = seccomp.LoadFilter(restrictedSocketFilter(denyUnixSockets, denyVSocks))
		if err != nil {
			return fmt.Errorf("restrict local sockets: %w", err)
		}
	}

	logger.Debugf("starting process in sandbox: %s", strings.Join(command, ", "))

	err = unix.Exec(path, command, os.Environ())
	if err != nil {
		return fmt.Errorf("execute restricted command %q: %w", command[0], err)
	}

	return nil
}

func restrictedSocketFilter(denyUnixSockets, denyVSocks bool) seccomp.Filter {
	blockedSyscalls := []string{
		// io_uring can create sockets without invoking the socket syscall.
		"io_uring_setup",
	}
	if runtime.GOARCH == "386" {
		// Seccomp cannot inspect the argument array used by the legacy socket
		// multiplexer, so block it and rely on modern direct socket syscalls.
		blockedSyscalls = append(blockedSyscalls, "socketcall")
	}

	restrictedFamilies := []uint64{}
	if denyVSocks {
		restrictedFamilies = append(restrictedFamilies, unix.AF_VSOCK)
	}

	if denyUnixSockets {
		restrictedFamilies = append(restrictedFamilies, unix.AF_UNIX)
	}

	restrictedSocketConditions := make([]seccomp.NameWithConditions, 0, len(restrictedFamilies)*2)

	for _, syscallName := range []string{"socket", "socketpair"} {
		for _, family := range restrictedFamilies {
			restrictedSocketConditions = append(restrictedSocketConditions, seccomp.NameWithConditions{
				Name: syscallName,
				Conditions: seccomp.ArgumentConditions{
					{Argument: 0, Operation: seccomp.Equal, Value: family},
				},
			})
		}
	}

	return seccomp.Filter{
		NoNewPrivs: false,
		Flag:       seccomp.FilterFlagTSync,
		Policy: seccomp.Policy{
			DefaultAction: seccomp.ActionAllow,
			Syscalls: []seccomp.SyscallGroup{
				{
					Action:             seccomp.ActionErrno,
					Names:              blockedSyscalls,
					NamesWithCondtions: restrictedSocketConditions,
				},
			},
		},
	}
}
