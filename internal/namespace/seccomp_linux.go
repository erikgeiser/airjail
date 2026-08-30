package namespace

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"golang.org/x/sys/unix"
)

// ExecRestricted installs the optional child seccomp filter and replaces the
// current process with command.
func ExecRestricted(command []string) error {
	if len(command) > 0 && command[0] == "--" {
		command = command[1:]
	}

	if len(command) == 0 {
		return fmt.Errorf("restricted child command is required")
	}

	path, err := exec.LookPath(command[0])
	if err != nil {
		return fmt.Errorf("look up restricted command %q: %w", command[0], err)
	}

	err = seccomp.SetNoNewPrivs()
	if err != nil {
		return fmt.Errorf("restrict local sockets: set no_new_privs: %w", err)
	}

	err = loadNativeArchitectureGuard()
	if err != nil {
		return fmt.Errorf("restrict local sockets: %w", err)
	}

	err = seccomp.LoadFilter(restrictedSocketFilter())
	if err != nil {
		return fmt.Errorf("restrict local sockets: %w", err)
	}

	err = unix.Exec(path, command, os.Environ())
	if err != nil {
		return fmt.Errorf("execute restricted command %q: %w", command[0], err)
	}

	return nil
}

func restrictedSocketFilter() seccomp.Filter {
	blockedSyscalls := []string{
		// io_uring can create sockets without invoking the socket syscall.
		"io_uring_setup",
	}
	if runtime.GOARCH == "386" {
		// Seccomp cannot inspect the argument array used by the legacy socket
		// multiplexer, so block it and rely on modern direct socket syscalls.
		blockedSyscalls = append(blockedSyscalls, "socketcall")
	}

	restrictedSocketConditions := make([]seccomp.NameWithConditions, 0, 4)

	for _, syscallName := range []string{"socket", "socketpair"} {
		for _, family := range []uint64{unix.AF_UNIX, unix.AF_VSOCK} {
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
