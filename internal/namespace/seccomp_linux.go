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

// ExecRestricted installs the optional child seccomp filter and replaces the
// current process with command.
func ExecRestricted(command []string, logger *logging.Logger) error {
	if len(command) == 0 {
		return fmt.Errorf("restricted child command is required")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("look up restricted command %q: %w", command[0], err)
	}

	abi, err := landlockABIVersion()
	landlockEnabled := err == nil && landlockUnixSocketsAvailable(abi, runtime.GOARCH)

	switch {
	case err != nil && !landlockUnavailable(err):
		return fmt.Errorf("restrict local sockets: %w", err)
	case err != nil:
		logger.Debugf("landlock is unavailable: %v", err)
	case abi < landlockUnixSocketABI:
		logger.Debugf("landlock ABI %d does not support pathname Unix socket isolation", abi)
	case !landlockEnabled:
		logger.Debugf("landlock unix socket isolation is unavailable on %s", runtime.GOARCH)
	}

	if !landlockEnabled {
		logger.Warnf("landlock unix socket isolation is unavailable, denying all unix and vsock socket creation")
	} else {
		logger.Debugf("installing landlock unix socket isolation")
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
		err = restrictExternalUnixSockets()
		if err != nil {
			return fmt.Errorf("restrict local sockets: %w", err)
		}
	}

	err = loadNativeArchitectureGuard()
	if err != nil {
		return fmt.Errorf("restrict local sockets: %w", err)
	}

	err = seccomp.LoadFilter(restrictedSocketFilter(!landlockEnabled))
	if err != nil {
		return fmt.Errorf("restrict local sockets: %w", err)
	}

	logger.Debugf("starting process in sandbox: %s", strings.Join(command, ", "))

	err = unix.Exec(path, command, os.Environ())
	if err != nil {
		return fmt.Errorf("execute restricted command %q: %w", command[0], err)
	}

	return nil
}

func restrictedSocketFilter(denyUnixSockets bool) seccomp.Filter {
	blockedSyscalls := []string{
		// io_uring can create sockets without invoking the socket syscall.
		"io_uring_setup",
	}
	if runtime.GOARCH == "386" {
		// Seccomp cannot inspect the argument array used by the legacy socket
		// multiplexer, so block it and rely on modern direct socket syscalls.
		blockedSyscalls = append(blockedSyscalls, "socketcall")
	}

	restrictedFamilies := []uint64{unix.AF_VSOCK}
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
