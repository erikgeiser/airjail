//nolint:goconst // Subprocess mode names remain visible at each boundary.
package namespace

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const childCapabilitiesMode = "AIRJAIL_CHILD_CAPABILITIES_MODE"

// Keep the expected security boundary independent of the production drop list.
const dangerousCapabilityMask = uint64(1)<<unix.CAP_SYS_ADMIN | uint64(1)<<unix.CAP_NET_ADMIN |
	uint64(1)<<unix.CAP_SYS_PTRACE | uint64(1)<<unix.CAP_SYS_MODULE | uint64(1)<<unix.CAP_SYS_RAWIO |
	uint64(1)<<unix.CAP_BPF | uint64(1)<<unix.CAP_PERFMON | uint64(1)<<unix.CAP_CHECKPOINT_RESTORE

func TestSupervisorChildCapabilities(t *testing.T) {
	t.Parallel()

	if mode := os.Getenv(childCapabilitiesMode); mode != "" {
		options := SupervisorOptions{Environment: os.Environ(), PreservePermissions: mode != "rootless"}
		if mode == "keep" {
			options.KeepUnsafeCapabilities = []string{os.Getenv("AIRJAIL_CHILD_KEEP")}
		}

		result := make(chan error, 1)

		go func() {
			exitCode, err := runSupervisorChild(t.Context(),
				[]string{os.Args[0], "-test.run=^TestExecutedChildCapabilities$"}, options)
			if exitCode != 0 {
				t.Errorf("executed child exit status = %d", exitCode)
			}

			result <- err
		}()

		err := <-result
		if err != nil {
			t.Fatalf("run supervisor child: %v", err)
		}

		return
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}

	data := [2]unix.CapUserData{}

	err := unix.Capget(&header, &data[0])
	if err != nil {
		t.Fatalf("read test capabilities: %v", err)
	}

	if !capabilityEffective(data, unix.CAP_SETPCAP) {
		t.Skip("capability bounding-set tests require CAP_SETPCAP")
	}

	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("read no_new_privs: %v", err)
	}

	keptName := ""
	keptMask := uint64(0)

	for _, capability := range dangerousCapabilities {
		if capabilityPermitted(data, capability.value) {
			keptName = capability.name
			keptMask = uint64(1) << uint(capability.value)

			break
		}
	}

	for _, mode := range []string{"rootless", "preserve", "keep"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			if mode != "rootless" && keptName == "" {
				t.Skip("no dangerous capability is present to exercise dropping or preserving")
			}

			wantKept, wantNNP := uint64(0), noNewPrivileges
			if mode == "keep" {
				wantKept = keptMask
			}

			if mode == "rootless" {
				wantNNP = 1
			}

			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSupervisorChildCapabilities$")

			command.Env = append(os.Environ(), childCapabilitiesMode+"="+mode,
				"AIRJAIL_CHILD_KEEP="+keptName, "AIRJAIL_CHILD_MASK="+strconv.FormatUint(wantKept, 16),
				"AIRJAIL_CHILD_NNP="+strconv.Itoa(wantNNP))

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("capability subprocess: %v\n%s", err, output)
			}
		})
	}
}

func TestExecutedChildCapabilities(t *testing.T) {
	mode := os.Getenv(childCapabilitiesMode)
	if mode == "" {
		return
	}

	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read executed child status: %v", err)
	}

	want, err := strconv.ParseUint(os.Getenv("AIRJAIL_CHILD_MASK"), 16, 64)
	if err != nil {
		t.Fatalf("parse expected capabilities: %v", err)
	}

	mask := dangerousCapabilityMask
	if mode == "rootless" {
		mask = ^uint64(0)
	}

	checked := 0

	for line := range strings.SplitSeq(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}

		switch fields[0] {
		case "CapEff:", "CapPrm:", "CapInh:", "CapAmb:", "CapBnd:":
			value, parseErr := strconv.ParseUint(fields[1], 16, 64)
			if parseErr != nil || value&mask != want {
				t.Errorf("%s %s, %v; expected dangerous bits %x", fields[0], fields[1], parseErr, want)
			}

			checked++
		case "NoNewPrivs:":
			if fields[1] != os.Getenv("AIRJAIL_CHILD_NNP") {
				t.Errorf("no_new_privs = %s, want %s", fields[1], os.Getenv("AIRJAIL_CHILD_NNP"))
			}

			checked++
		}
	}

	if checked != 6 {
		t.Fatalf("missing capability or no_new_privs status fields: checked %d", checked)
	}
}
