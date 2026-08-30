package namespace

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"

	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sys/unix"
)

const (
	nonDumpableTestProcess    = "AIRJAIL_NON_DUMPABLE_TEST_PROCESS"
	capabilityDropTestProcess = "AIRJAIL_CAPABILITY_DROP_TEST_PROCESS"
)

func TestSetNonDumpable(t *testing.T) {
	t.Parallel()

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSetNonDumpableProcess$")

	command.Env = append(os.Environ(), nonDumpableTestProcess+"=1")

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("non-dumpable subprocess: %v\n%s", err, output)
	}
}

func TestSetNonDumpableProcess(t *testing.T) {
	if os.Getenv(nonDumpableTestProcess) == "" {
		return
	}

	err := SetNonDumpable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "SetNonDumpable: %v\n", err)
		os.Exit(2)
	}

	dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get dumpable state: %v\n", err)
		os.Exit(2)
	}

	if dumpable != 0 {
		fmt.Fprintf(os.Stderr, "dumpable state = %d, want 0\n", dumpable)
		os.Exit(2)
	}

	os.Exit(0)
}

func TestDropDangerousCapabilities(t *testing.T) {
	t.Parallel()

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestDropDangerousCapabilitiesProcess$")

	command.Env = append(os.Environ(), capabilityDropTestProcess+"=1")

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("capability-drop subprocess: %v\n%s", err, output)
	}
}

func TestDropDangerousCapabilitiesProcess(t *testing.T) {
	if os.Getenv(capabilityDropTestProcess) == "" {
		return
	}

	initialHeader := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	initialData := [2]unix.CapUserData{}

	err := unix.Capget(&initialHeader, &initialData[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read initial capabilities: %v\n", err)
		os.Exit(2)
	}

	if !capabilityEffective(initialData, unix.CAP_SETPCAP) {
		os.Exit(0)
	}

	noNewPrivilegesBefore, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get no_new_privs before capability drop: %v\n", err)
		os.Exit(2)
	}

	err = dropDangerousCapabilities(nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dropDangerousCapabilities: %v\n", err)
		os.Exit(2)
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	err = unix.Capget(&header, &data[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "read capabilities after drop: %v\n", err)
		os.Exit(2)
	}

	for _, capability := range dangerousCapabilities {
		if capabilityEffective(data, capability.value) || capabilityPermitted(data, capability.value) {
			fmt.Fprintf(os.Stderr, "%s remains in process capability sets\n", capability.name)
			os.Exit(2)
		}

		bounded, boundingErr := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(capability.value), 0, 0, 0)
		if boundingErr != nil {
			if errors.Is(boundingErr, unix.EINVAL) {
				continue
			}

			fmt.Fprintf(os.Stderr, "read %s bounding state: %v\n", capability.name, boundingErr)
			os.Exit(2)
		}

		if bounded != 0 {
			fmt.Fprintf(os.Stderr, "%s remains in capability bounding set\n", capability.name)
			os.Exit(2)
		}
	}

	noNewPrivilegesAfter, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "get no_new_privs after capability drop: %v\n", err)
		os.Exit(2)
	}

	if noNewPrivilegesAfter != noNewPrivilegesBefore {
		fmt.Fprintf(
			os.Stderr,
			"no_new_privs changed from %d to %d\n",
			noNewPrivilegesBefore,
			noNewPrivilegesAfter,
		)
		os.Exit(2)
	}

	os.Exit(0)
}

func TestParseUnsafeCapabilities(t *testing.T) {
	t.Parallel()

	parsed, err := parseUnsafeCapabilities([]string{"sys_admin", "CAP_NET_ADMIN", "cap_sys_admin"})
	if err != nil {
		t.Fatalf("parseUnsafeCapabilities: %v", err)
	}

	got := make([]string, 0, len(parsed))
	for _, capability := range parsed {
		got = append(got, capability.name)
	}

	want := []string{"CAP_SYS_ADMIN", "CAP_NET_ADMIN"}
	if !slices.Equal(got, want) {
		t.Errorf("capabilities = %v, want %v", got, want)
	}
}

func TestParseUnsafeCapabilitiesRejectsCapabilityNotDroppedByDefault(t *testing.T) {
	t.Parallel()

	_, err := parseUnsafeCapabilities([]string{"CAP_CHOWN"})
	if err == nil {
		t.Fatal("parseUnsafeCapabilities unexpectedly accepted CAP_CHOWN")
	}
}

func TestSelectUnsafeCapabilitiesWarnsWhenCallerDoesNotHaveCapability(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger, err := logging.New(&output, "warning", "")
	if err != nil {
		t.Fatalf("logging.New: %v", err)
	}

	requested, err := parseUnsafeCapabilities([]string{"CAP_SYS_ADMIN"})
	if err != nil {
		t.Fatalf("parseUnsafeCapabilities: %v", err)
	}

	kept := selectUnsafeCapabilities(requested, PermissionPreservingMode, [2]unix.CapUserData{}, logger)
	if len(kept) != 0 {
		t.Errorf("kept capabilities = %v, want none", kept)
	}

	if !strings.Contains(output.String(), "CAP_SYS_ADMIN") || !strings.Contains(output.String(), "will not be kept") {
		t.Errorf("warning = %q", output.String())
	}
}

func TestClearCapability(t *testing.T) {
	t.Parallel()

	data := [2]unix.CapUserData{
		{Effective: ^uint32(0), Permitted: ^uint32(0), Inheritable: ^uint32(0)},
		{Effective: ^uint32(0), Permitted: ^uint32(0), Inheritable: ^uint32(0)},
	}

	clearCapability(&data, unix.CAP_CHECKPOINT_RESTORE)

	if capabilityEffective(data, unix.CAP_CHECKPOINT_RESTORE) ||
		capabilityPermitted(data, unix.CAP_CHECKPOINT_RESTORE) {
		t.Fatal("CAP_CHECKPOINT_RESTORE remains in capability sets")
	}

	if !capabilityEffective(data, unix.CAP_SYS_ADMIN) {
		t.Fatal("clearCapability modified an unrelated capability")
	}
}
