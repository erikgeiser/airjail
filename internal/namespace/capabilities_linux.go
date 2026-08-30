package namespace

import (
	"errors"
	"fmt"
	"strings"

	"github.com/erikgeiser/airjail/internal/logging"
	"golang.org/x/sys/unix"
)

type dangerousCapability struct {
	name  string
	value int
}

var dangerousCapabilities = []dangerousCapability{
	{name: "CAP_SYS_ADMIN", value: unix.CAP_SYS_ADMIN},
	{name: "CAP_NET_ADMIN", value: unix.CAP_NET_ADMIN},
	{name: "CAP_SYS_PTRACE", value: unix.CAP_SYS_PTRACE},
	{name: "CAP_SYS_MODULE", value: unix.CAP_SYS_MODULE},
	{name: "CAP_SYS_RAWIO", value: unix.CAP_SYS_RAWIO},
	{name: "CAP_BPF", value: unix.CAP_BPF},
	{name: "CAP_PERFMON", value: unix.CAP_PERFMON},
	{name: "CAP_CHECKPOINT_RESTORE", value: unix.CAP_CHECKPOINT_RESTORE},
}

func resolveUnsafeCapabilities(
	requested []string,
	mode Mode,
	logger *logging.Logger,
) ([]string, error) {
	parsed, err := parseUnsafeCapabilities(requested)
	if err != nil {
		return nil, err
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	err = unix.Capget(&header, &data[0])
	if err != nil {
		return nil, fmt.Errorf("read caller capabilities: %w", err)
	}

	return selectUnsafeCapabilities(parsed, mode, data, logger), nil
}

func selectUnsafeCapabilities(
	requested []dangerousCapability,
	mode Mode,
	data [2]unix.CapUserData,
	logger *logging.Logger,
) []string {
	kept := make([]string, 0, len(requested))
	for _, capability := range requested {
		if !capabilityPermitted(data, capability.value) {
			logger.Warnf(
				"requested unsafe capability %s is not in the caller's permitted set and will not be kept",
				capability.name,
			)

			continue
		}

		if mode != PermissionPreservingMode {
			logger.Warnf("requested unsafe capability %s cannot be kept in rootless namespace mode", capability.name)

			continue
		}

		kept = append(kept, capability.name)
	}

	return kept
}

func parseUnsafeCapabilities(requested []string) ([]dangerousCapability, error) {
	capabilitiesByName := make(map[string]dangerousCapability, len(dangerousCapabilities))
	for _, capability := range dangerousCapabilities {
		capabilitiesByName[capability.name] = capability
	}

	parsed := make([]dangerousCapability, 0, len(requested))
	seen := make(map[int]struct{}, len(requested))

	for _, rawName := range requested {
		name := strings.ToUpper(strings.TrimSpace(rawName))
		if !strings.HasPrefix(name, "CAP_") {
			name = "CAP_" + name
		}

		capability, found := capabilitiesByName[name]
		if !found {
			return nil, fmt.Errorf("unsafe capability %q is not dropped by airjail", rawName)
		}

		_, found = seen[capability.value]
		if found {
			continue
		}

		seen[capability.value] = struct{}{}
		parsed = append(parsed, capability)
	}

	return parsed, nil
}

func unsafeCapabilityValues(names []string) ([]uintptr, error) {
	capabilities, err := parseUnsafeCapabilities(names)
	if err != nil {
		return nil, err
	}

	values := make([]uintptr, 0, len(capabilities))
	for _, capability := range capabilities {
		values = append(values, uintptr(capability.value))
	}

	return values, nil
}

func dropDangerousCapabilities(keptNames []string) error {
	keptCapabilities, err := parseUnsafeCapabilities(keptNames)
	if err != nil {
		return err
	}

	kept := make(map[int]struct{}, len(keptCapabilities))
	for _, capability := range keptCapabilities {
		kept[capability.value] = struct{}{}
	}

	for _, capability := range dangerousCapabilities {
		if _, found := kept[capability.value]; found {
			continue
		}

		err = unix.Prctl(unix.PR_CAPBSET_DROP, uintptr(capability.value), 0, 0, 0)
		if err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("drop %s from capability bounding set: %w", capability.name, err)
		}

		ambient, ambientErr := unix.PrctlRetInt(
			unix.PR_CAP_AMBIENT,
			unix.PR_CAP_AMBIENT_IS_SET,
			uintptr(capability.value),
			0,
			0,
		)
		if ambientErr != nil && !errors.Is(ambientErr, unix.EINVAL) {
			return fmt.Errorf("inspect ambient capability %s: %w", capability.name, ambientErr)
		}

		if ambient == 1 {
			err = unix.Prctl(
				unix.PR_CAP_AMBIENT,
				unix.PR_CAP_AMBIENT_LOWER,
				uintptr(capability.value),
				0,
				0,
			)
			if err != nil {
				return fmt.Errorf("drop ambient capability %s: %w", capability.name, err)
			}
		}
	}

	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	data := [2]unix.CapUserData{}

	err = unix.Capget(&header, &data[0])
	if err != nil {
		return fmt.Errorf("read capabilities before dropping dangerous capabilities: %w", err)
	}

	for _, capability := range dangerousCapabilities {
		_, found := kept[capability.value]
		if found {
			continue
		}

		clearCapability(&data, capability.value)
	}

	err = unix.Capset(&header, &data[0])
	if err != nil {
		return fmt.Errorf("drop dangerous capabilities: %w", err)
	}

	return nil
}

func capabilityPermitted(data [2]unix.CapUserData, capability int) bool {
	word := capability / 32
	bit := uint(capability % 32)

	return data[word].Permitted&(uint32(1)<<bit) != 0
}

func clearCapability(data *[2]unix.CapUserData, capability int) {
	word := capability / 32
	mask := ^(uint32(1) << uint(capability%32))

	data[word].Effective &= mask
	data[word].Permitted &= mask
	data[word].Inheritable &= mask
}

// SetNonDumpable prevents other same-UID processes from inspecting airjail
// through procfs or ptrace.
func SetNonDumpable() error {
	err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("make airjail process non-dumpable: %w", err)
	}

	return nil
}
