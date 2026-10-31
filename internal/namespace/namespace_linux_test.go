package namespace

import (
	"os"
	"slices"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestCapabilityEffective(t *testing.T) {
	t.Parallel()

	data := [2]unix.CapUserData{}
	data[0].Effective = uint32(1) << uint(unix.CAP_NET_ADMIN)
	data[1].Effective = uint32(1) << uint(unix.CAP_CHECKPOINT_RESTORE-32)

	if !capabilityEffective(data, unix.CAP_NET_ADMIN) || !capabilityEffective(data, unix.CAP_CHECKPOINT_RESTORE) {
		t.Fatal("effective capabilities were not detected across both words")
	}

	if capabilityEffective(data, unix.CAP_SYS_ADMIN) {
		t.Fatal("unset capability was detected")
	}
}

func TestNamespaceLaunchConfiguration(t *testing.T) {
	t.Parallel()

	preserving := namespaceProcessAttributes(PermissionPreservingMode)
	if preserving.Cloneflags != unix.CLONE_NEWNET || len(preserving.UidMappings) != 0 || len(preserving.GidMappings) != 0 {
		t.Fatal("permission-preserving mode changes the caller's user namespace")
	}

	rootless := namespaceProcessAttributes(RootlessMode)
	if rootless.Cloneflags != unix.CLONE_NEWUSER|unix.CLONE_NEWNET {
		t.Fatal("rootless mode does not isolate both user and network namespaces")
	}

	wantUID := []syscall.SysProcIDMap{{ContainerID: os.Getuid(), HostID: os.Getuid(), Size: 1}}

	wantGID := []syscall.SysProcIDMap{{ContainerID: os.Getgid(), HostID: os.Getgid(), Size: 1}}
	if !slices.Equal(rootless.UidMappings, wantUID) || !slices.Equal(rootless.GidMappings, wantGID) {
		t.Errorf("rootless ID mappings = %v, %v; want %v, %v", rootless.UidMappings, rootless.GidMappings, wantUID, wantGID)
	}

	for _, attributes := range []*syscall.SysProcAttr{rootless, preserving} {
		if attributes.Pdeathsig != syscall.SIGKILL {
			t.Error("supervisor can survive an abruptly killed parent")
		}
	}
}
