package namespace

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const seccompTestStage = "AIRJAIL_SECCOMP_TEST_STAGE"

func TestNativeArchitectureGuard(t *testing.T) {
	t.Parallel()

	const nativeArchitecture = uint32(unix.AUDIT_ARCH_X86_64)

	virtualMachine, err := bpf.NewVM(nativeArchitectureGuard(nativeArchitecture))
	if err != nil {
		t.Fatalf("create BPF virtual machine: %v", err)
	}

	tests := []struct {
		name         string
		architecture uint32
		want         uint32
	}{
		{name: "native architecture allowed", architecture: nativeArchitecture, want: unix.SECCOMP_RET_ALLOW},
		{name: "other architecture killed", architecture: unix.AUDIT_ARCH_I386, want: unix.SECCOMP_RET_KILL_PROCESS},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			seccompData := make([]byte, 8)
			binary.BigEndian.PutUint32(seccompData[seccompArchitectureOffset:], test.architecture)

			result, runErr := virtualMachine.Run(seccompData)
			if runErr != nil {
				t.Fatalf("evaluate guard: %v", runErr)
			}

			if uint32(result) != test.want {
				t.Errorf("guard action = %#x, want %#x", uint32(result), test.want)
			}
		})
	}
}

func TestExecRestrictedBlocksUnixSockets(t *testing.T) {
	t.Parallel()

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExecRestrictedProcess$")

	command.Env = append(os.Environ(), seccompTestStage+"=launch")

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("restricted subprocess: %v\n%s", err, output)
	}
}

func TestExecRestrictedProcess(t *testing.T) {
	switch os.Getenv(seccompTestStage) {
	case "":
		return
	case "launch":
		t.Setenv(seccompTestStage, "check")

		err := ExecRestricted([]string{os.Args[0], fmt.Sprintf("-test.run=^%s$", t.Name())})
		fmt.Fprintf(os.Stderr, "ExecRestricted: %v\n", err)
		os.Exit(2)
	case "check":
		assertSocketDenied(unix.AF_UNIX, unix.SOCK_STREAM)
		assertSocketPairDenied()
		assertIOUringDenied()
		assertINETSocketAllowed()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "unexpected test stage %q\n", os.Getenv(seccompTestStage))
		os.Exit(2)
	}
}

func assertSocketDenied(domain, socketType int) {
	fileDescriptor, err := unix.Socket(domain, socketType, 0)
	if fileDescriptor >= 0 {
		_ = unix.Close(fileDescriptor)

		fmt.Fprintln(os.Stderr, "Unix socket creation unexpectedly succeeded")
		os.Exit(2)
	}

	if !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "Unix socket error = %v, want EPERM\n", err)
		os.Exit(2)
	}
}

func assertSocketPairDenied() {
	fileDescriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err == nil {
		_ = unix.Close(fileDescriptors[0])
		_ = unix.Close(fileDescriptors[1])

		fmt.Fprintln(os.Stderr, "Unix socketpair creation unexpectedly succeeded")
		os.Exit(2)
	}

	if !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "Unix socketpair error = %v, want EPERM\n", err)
		os.Exit(2)
	}
}

func assertIOUringDenied() {
	_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 1, 0, 0)
	if !errors.Is(errno, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "io_uring_setup error = %v, want EPERM\n", errno)
		os.Exit(2)
	}
}

func assertINETSocketAllowed() {
	fileDescriptor, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "INET socket creation: %v\n", err)
		os.Exit(2)
	}

	_ = unix.Close(fileDescriptor)
}
