package namespace

import (
	"os"
	"os/exec"
	"slices"
	"testing"

	"golang.org/x/sys/unix"
)

const nonDumpableTestProcess = "AIRJAIL_NON_DUMPABLE_TEST_PROCESS"

func TestSetNonDumpable(t *testing.T) {
	if os.Getenv(nonDumpableTestProcess) != "" {
		err := SetNonDumpable()
		if err != nil {
			t.Fatalf("make process non-dumpable: %v", err)
		}

		dumpable, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
		if err != nil || dumpable != 0 {
			t.Fatalf("dumpable state = %d, %v; want 0", dumpable, err)
		}

		return
	}

	t.Parallel()

	command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSetNonDumpable$")

	command.Env = append(os.Environ(), nonDumpableTestProcess+"=1")

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("non-dumpable subprocess: %v\n%s", err, output)
	}
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

func TestSelectUnsafeCapabilitiesRejectsCapabilitiesCallerDoesNotHave(t *testing.T) {
	t.Parallel()

	requested, err := parseUnsafeCapabilities([]string{"CAP_SYS_ADMIN"})
	if err != nil {
		t.Fatalf("parseUnsafeCapabilities: %v", err)
	}

	kept := selectUnsafeCapabilities(requested, PermissionPreservingMode, [2]unix.CapUserData{}, nil)
	if len(kept) != 0 {
		t.Errorf("kept capabilities = %v, want none", kept)
	}

}
