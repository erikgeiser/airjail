package namespace

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	seccompTestStage        = "AIRJAIL_SECCOMP_TEST_STAGE"
	seccompTestLandlock     = "AIRJAIL_SECCOMP_TEST_LANDLOCK"
	seccompTestPathSocket   = "AIRJAIL_SECCOMP_TEST_PATH_SOCKET"
	seccompTestAbstractSock = "AIRJAIL_SECCOMP_TEST_ABSTRACT_SOCKET"
)

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

func TestLandlockUnixSocketsAvailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		abi          int
		architecture string
		want         bool
	}{
		{name: "ABI 8", abi: 8, architecture: "amd64"},
		{name: "ABI 9", abi: 9, architecture: "amd64", want: true},
		{name: "386", abi: 9, architecture: "386"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := landlockUnixSocketsAvailable(test.abi, test.architecture)
			if got != test.want {
				t.Errorf("landlockUnixSocketsAvailable() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestExecRestrictedBlocksExternalLocalSockets(t *testing.T) {
	t.Parallel()

	listenConfig := net.ListenConfig{}
	pathSocket := filepath.Join(t.TempDir(), "external.sock")

	pathListener, err := listenConfig.Listen(t.Context(), "unix", pathSocket)
	if err != nil {
		t.Fatalf("listen on pathname Unix socket: %v", err)
	}

	defer func() { _ = pathListener.Close() }()

	abstractSocket := fmt.Sprintf("@airjail-seccomp-%d-%s", os.Getpid(), filepath.Base(t.TempDir()))

	abstractListener, err := listenConfig.Listen(t.Context(), "unix", abstractSocket)
	if err != nil {
		t.Fatalf("listen on abstract Unix socket: %v", err)
	}

	defer func() { _ = abstractListener.Close() }()

	abi, abiErr := landlockABIVersion()
	if abiErr != nil && !landlockUnavailable(abiErr) {
		t.Fatalf("landlockABIVersion: %v", abiErr)
	}

	landlockEnabled := abiErr == nil && landlockUnixSocketsAvailable(abi, runtime.GOARCH)

	landlockValue := "0"
	if landlockEnabled {
		landlockValue = "1"
	}

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestExecRestrictedProcess$")

	command.Env = append(
		os.Environ(),
		seccompTestStage+"=launch",
		seccompTestLandlock+"="+landlockValue,
		seccompTestPathSocket+"="+pathSocket,
		seccompTestAbstractSock+"="+abstractSocket,
	)

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

		logger, err := logging.New(os.Stderr, "warning", "restricted exec")
		if err != nil {
			fmt.Fprintf(os.Stderr, "create restricted-exec logger: %v\n", err)
			os.Exit(2)
		}

		err = ExecRestricted([]string{os.Args[0], fmt.Sprintf("-test.run=^%s$", t.Name())}, logger)
		fmt.Fprintf(os.Stderr, "ExecRestricted: %v\n", err)
		os.Exit(2)
	case "check":
		if os.Getenv(seccompTestLandlock) == "1" {
			assertUnixSocketAllowedWithinDomain()
			assertSocketPairAllowed()
			assertUnixConnectionDenied(os.Getenv(seccompTestPathSocket))
			assertUnixConnectionDenied(os.Getenv(seccompTestAbstractSock))
		} else {
			assertSocketDenied(unix.AF_UNIX, unix.SOCK_STREAM)
			assertSocketPairDenied()
		}

		assertSocketDenied(unix.AF_VSOCK, unix.SOCK_STREAM)
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

		fmt.Fprintf(os.Stderr, "socket creation for family %d unexpectedly succeeded\n", domain)
		os.Exit(2)
	}

	if !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "socket error for family %d = %v, want EPERM\n", domain, err)
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

func assertSocketPairAllowed() {
	fileDescriptors, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "create internal Unix socket pair: %v\n", err)
		os.Exit(2)
	}

	_ = unix.Close(fileDescriptors[0])
	_ = unix.Close(fileDescriptors[1])
}

func assertUnixSocketAllowedWithinDomain() {
	directory, err := os.MkdirTemp("", "airjail-landlock-test-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create internal Unix socket directory: %v\n", err)
		os.Exit(2)
	}

	listener, err := (&net.ListenConfig{}).Listen(
		context.Background(),
		"unix",
		filepath.Join(directory, "internal.sock"),
	)
	if err != nil {
		_ = os.RemoveAll(directory)

		fmt.Fprintf(os.Stderr, "listen on internal Unix socket: %v\n", err)
		os.Exit(2)
	}

	connection, err := (&net.Dialer{}).DialContext(context.Background(), "unix", listener.Addr().String())
	if err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(directory)

		fmt.Fprintf(os.Stderr, "connect to internal Unix socket: %v\n", err)
		os.Exit(2)
	}

	_ = connection.Close()
	_ = listener.Close()
	_ = os.RemoveAll(directory)
}

func assertUnixConnectionDenied(address string) {
	connection, err := (&net.Dialer{}).DialContext(context.Background(), "unix", address)
	if err == nil {
		_ = connection.Close()

		fmt.Fprintf(os.Stderr, "connection to external Unix socket %q unexpectedly succeeded\n", address)
		os.Exit(2)
	}

	if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
		fmt.Fprintf(os.Stderr, "external Unix socket error = %v, want EACCES or EPERM\n", err)
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
