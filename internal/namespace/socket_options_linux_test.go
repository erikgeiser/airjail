//nolint:goconst
package namespace

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	seccomp "github.com/elastic/go-seccomp-bpf"
	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sys/unix"
)

const socketOptionsStage = "AIRJAIL_SOCKET_OPTIONS_STAGE"

func TestSocketPermissionCombinations(t *testing.T) {
	t.Parallel()

	abi, err := landlockABIVersion()
	if err != nil && !landlockUnavailable(err) {
		t.Fatal(err)
	}

	t.Logf("Landlock ABI: %d", abi)

	for _, mode := range []string{
		"default", "unix", "vsock", "all", "grant", "grant-vsock",
		"default-fallback", "unix-fallback", "vsock-fallback", "all-fallback", "grant-fallback", "grant-vsock-fallback",
	} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			testABI := abi
			if strings.HasSuffix(mode, "-fallback") {
				testABI = 0
			}

			directory := t.TempDir()
			path := filepath.Join(directory, "allowed.sock")

			listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = listener.Close() }()

			datagramPath := filepath.Join(directory, "datagram.sock")

			packet, err := (&net.ListenConfig{}).ListenPacket(t.Context(), "unixgram", datagramPath)
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = packet.Close() }()

			neighbor := filepath.Join(directory, "neighbor.sock")

			neighborListener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", neighbor)
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = neighborListener.Close() }()

			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSocketOptionsProcess$")

			command.Dir = directory

			command.Env = append(os.Environ(), socketOptionsStage+"=launch", "AIRJAIL_SOCKET_MODE="+mode,
				"AIRJAIL_SOCKET_PATH="+path, "AIRJAIL_SOCKET_DATAGRAM="+datagramPath,
				"AIRJAIL_SOCKET_NEIGHBOR="+neighbor, "AIRJAIL_SOCKET_ABI="+strconv.Itoa(testABI))

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("socket permissions subprocess: %v\n%s", err, output)
			}
		})
	}
}

func TestSocketOptionsProcess(t *testing.T) {
	stage := os.Getenv(socketOptionsStage)
	if stage == "" {
		return
	}

	rawMode := os.Getenv("AIRJAIL_SOCKET_MODE")
	mode := strings.TrimSuffix(rawMode, "-fallback")

	options := SocketOptions{
		AllowAllSockets: mode == "unix" || mode == "all",
		AllowVSocks:     mode == "vsock" || mode == "all" || mode == "grant-vsock",
	}
	if strings.HasPrefix(mode, "grant") {
		options.AllowSockets = []string{filepath.Base(os.Getenv("AIRJAIL_SOCKET_PATH")), os.Getenv("AIRJAIL_SOCKET_DATAGRAM")}
	}

	if stage == "launch" {
		if strings.HasSuffix(rawMode, "-fallback") {
			runtime.LockOSThread()

			err := seccomp.LoadFilter(seccomp.Filter{
				NoNewPrivs: true,
				Flag:       seccomp.FilterFlagTSync,
				Policy: seccomp.Policy{
					DefaultAction: seccomp.ActionAllow,
					Syscalls: []seccomp.SyscallGroup{{
						Names:  []string{"landlock_create_ruleset"},
						Action: seccomp.ActionErrno | seccomp.Action(unix.ENOSYS),
					}},
				},
			})
			if err != nil {
				t.Fatalf("simulate unavailable Landlock: %v", err)
			}
		}

		_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 0, 0, 0)
		t.Setenv("AIRJAIL_SOCKET_URING_ERRNO", strconv.Itoa(int(errno)))
		t.Setenv("AIRJAIL_SOCKET_FILTERS", seccompFilterCount(t))
		t.Setenv("AIRJAIL_SOCKET_VSOCK_ERROR", fmt.Sprint(probeVsock()))
		t.Setenv(socketOptionsStage, "check")

		logger, err := logging.New(os.Stderr, "warning", "")
		if err != nil {
			t.Fatal(err)
		}

		err = ExecRestricted([]string{os.Args[0], "-test.run=^TestSocketOptionsProcess$"}, options, logger)
		t.Fatalf("execute restricted child: %v", err)
	}

	abi, err := strconv.Atoi(os.Getenv("AIRJAIL_SOCKET_ABI"))
	if err != nil {
		t.Fatal(err)
	}

	landlockEnabled := landlockUnixSocketsAvailable(abi, runtime.GOARCH)
	unixAllowed := options.AllowAllSockets || strings.HasPrefix(mode, "grant") && landlockEnabled
	assertUnixSocketAccess(t, os.Getenv("AIRJAIL_SOCKET_PATH"), unixAllowed)
	assertUnixSocketAccess(t, os.Getenv("AIRJAIL_SOCKET_NEIGHBOR"), options.AllowAllSockets)

	fd, socketErr := unix.Socket(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if socketErr == nil {
		defer func() { _ = unix.Close(fd) }()

		socketErr = unix.Sendto(fd, []byte("test"), 0, &unix.SockaddrUnix{Name: os.Getenv("AIRJAIL_SOCKET_DATAGRAM")})
	}

	if (socketErr == nil) != unixAllowed {
		t.Errorf("Unix datagram access: %v, want allowed=%t", socketErr, unixAllowed)
	}

	if !options.AllowVSocks {
		assertSocketDenied(unix.AF_VSOCK, unix.SOCK_STREAM)
	} else {
		// Vsock can be unavailable in the host kernel; preserve its original behavior.
		if got := fmt.Sprint(probeVsock()); got != os.Getenv("AIRJAIL_SOCKET_VSOCK_ERROR") {
			t.Errorf("vsock behavior changed: %s", got)
		}
	}

	needsSeccomp := !options.AllowVSocks || !options.AllowAllSockets && !landlockEnabled
	if needsSeccomp {
		assertIOUringDenied()
	} else {
		if got := seccompFilterCount(t); got != os.Getenv("AIRJAIL_SOCKET_FILTERS") {
			t.Errorf("unnecessary seccomp filters: %s, previously %s", got, os.Getenv("AIRJAIL_SOCKET_FILTERS"))
		}

		_, _, errno := unix.Syscall(unix.SYS_IO_URING_SETUP, 0, 0, 0)
		if strconv.Itoa(int(errno)) != os.Getenv("AIRJAIL_SOCKET_URING_ERRNO") {
			t.Errorf("io_uring behavior changed: %v", errno)
		}
	}
}

func probeVsock() error {
	fd, err := unix.Socket(unix.AF_VSOCK, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
	}

	return err
}

func assertUnixSocketAccess(tb testing.TB, path string, allowed bool) {
	tb.Helper()

	connection, err := (&net.Dialer{}).DialContext(tb.Context(), "unix", path)
	if connection != nil {
		_ = connection.Close()
	}

	if (err == nil) != allowed {
		tb.Errorf("access to %s: %v, want allowed=%t", path, err, allowed)
	}
}

func seccompFilterCount(tb testing.TB) string {
	tb.Helper()

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		tb.Fatal(err)
	}

	for line := range strings.SplitSeq(string(status), "\n") {
		if after, ok := strings.CutPrefix(line, "Seccomp_filters:"); ok {
			return strings.TrimSpace(after)
		}
	}

	tb.Fatal("read seccomp filter count: field is missing")

	return ""
}
