package namespace

import (
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"testing"

	"golang.org/x/sys/unix"
)

const (
	childCapabilitiesTestStage = "AIRJAIL_CHILD_CAPABILITIES_TEST_STAGE"
	childCapabilitiesRootless  = "rootless"
)

func TestSupervisorChildCapabilities(t *testing.T) {
	t.Parallel()

	for _, mode := range []string{childCapabilitiesRootless, "preserve", "keep"} {
		t.Run(mode, func(t *testing.T) {
			t.Parallel()

			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestSupervisorChildCapabilitiesProcess$")

			command.Env = append(os.Environ(),
				childCapabilitiesTestStage+"=launch",
				"AIRJAIL_CHILD_CAPABILITIES_TEST_MODE="+mode,
			)

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("child capability subprocess: %v\n%s", err, output)
			}
		})
	}
}

func TestSupervisorChildCapabilitiesProcess(t *testing.T) {
	switch os.Getenv(childCapabilitiesTestStage) {
	case "":
		return
	case "launch":
		launchCapabilityTestChild(t)
	case "check":
		checkExecutedChildCapabilities(t)
	default:
		t.Fatal("unexpected child capability test stage")
	}
}

func launchCapabilityTestChild(tb testing.TB) {
	tb.Helper()

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	err := unix.Capget(&header, &data[0])
	if err != nil {
		tb.Fatalf("read initial capabilities: %v", err)
	}

	if !capabilityEffective(data, unix.CAP_SETPCAP) {
		tb.Skip("dropping capability bounding sets requires CAP_SETPCAP")
	}

	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		tb.Fatalf("read initial no_new_privs: %v", err)
	}

	mode := os.Getenv("AIRJAIL_CHILD_CAPABILITIES_TEST_MODE")
	keptNames := []string{}

	if mode == "keep" {
		for _, capability := range dangerousCapabilities {
			if capabilityPermitted(data, capability.value) {
				keptNames = append(keptNames, capability.name)

				break
			}
		}

		if len(keptNames) == 0 {
			tb.Skip("no dangerous capability is available to preserve")
		}
	}

	keptName := ""
	if len(keptNames) != 0 {
		keptName = keptNames[0]
	}

	if mode == childCapabilitiesRootless {
		noNewPrivileges = 1
	}

	options := SupervisorOptions{
		PreservePermissions:    mode != childCapabilitiesRootless,
		KeepUnsafeCapabilities: keptNames,
		Environment: append(os.Environ(),
			childCapabilitiesTestStage+"=check",
			"AIRJAIL_CHILD_CAPABILITIES_TEST_KEEP="+keptName,
			"AIRJAIL_CHILD_CAPABILITIES_TEST_NNP="+strconv.Itoa(noNewPrivileges),
		),
	}

	// Match the supervisor's ownership: this goroutine exits with its modified
	// OS thread still locked, and reports the executed child's result.
	result := make(chan error, 1)

	go func() {
		exitCode, runErr := runSupervisorChild(tb.Context(),
			[]string{os.Args[0], "-test.run=^TestSupervisorChildCapabilitiesProcess$"}, options)
		if runErr == nil && exitCode != 0 {
			runErr = fmt.Errorf("child exit status %d", exitCode)
		}

		result <- runErr
	}()

	err = <-result
	if err != nil {
		tb.Fatalf("run supervisor child: %v", err)
	}
}

func checkExecutedChildCapabilities(tb testing.TB) {
	tb.Helper()

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	err := unix.Capget(&header, &data[0])
	if err != nil {
		tb.Fatalf("read executed child capabilities: %v", err)
	}

	rootless := os.Getenv("AIRJAIL_CHILD_CAPABILITIES_TEST_MODE") == childCapabilitiesRootless
	if rootless && data != [2]unix.CapUserData{} {
		tb.Fatalf("rootless child retains capabilities: %#v", data)
	}

	keptName := os.Getenv("AIRJAIL_CHILD_CAPABILITIES_TEST_KEEP")

	for capability := range 64 {
		bounded, boundingErr := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(capability), 0, 0, 0)
		if boundingErr == unix.EINVAL {
			break
		}

		if boundingErr != nil {
			tb.Fatalf("read child bounding capability %d: %v", capability, boundingErr)
		}

		ambient, ambientErr := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET,
			uintptr(capability), 0, 0)
		if ambientErr != nil {
			tb.Fatalf("read child ambient capability %d: %v", capability, ambientErr)
		}

		if rootless && (bounded != 0 || ambient != 0) {
			tb.Errorf("rootless capability %d: bounding=%d ambient=%d", capability, bounded, ambient)
		}

		for _, dangerous := range dangerousCapabilities {
			if dangerous.value != capability {
				continue
			}

			want := dangerous.name == keptName

			inheritable := data[capability/32].Inheritable&(uint32(1)<<uint(capability%32)) != 0
			if capabilityEffective(data, capability) != want || capabilityPermitted(data, capability) != want ||
				inheritable != want || (bounded != 0) != want || (ambient != 0) != want {
				tb.Errorf("unexpected child sets for %s (kept=%t): data=%#v bounding=%d ambient=%d",
					dangerous.name, want, data, bounded, ambient)
			}
		}
	}

	noNewPrivileges, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || strconv.Itoa(noNewPrivileges) != os.Getenv("AIRJAIL_CHILD_CAPABILITIES_TEST_NNP") {
		tb.Fatalf("executed child no_new_privs = %d, %v", noNewPrivileges, err)
	}
}
