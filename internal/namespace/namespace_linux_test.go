package namespace

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestCapabilityEffective(t *testing.T) {
	t.Parallel()

	data := [2]unix.CapUserData{}
	data[0].Effective = uint32(1) << uint(unix.CAP_NET_ADMIN)
	data[1].Effective = uint32(1) << uint(40-32)

	if !capabilityEffective(data, unix.CAP_NET_ADMIN) {
		t.Fatal("CAP_NET_ADMIN was not detected")
	}

	if !capabilityEffective(data, 40) {
		t.Fatal("capability in second word was not detected")
	}

	if capabilityEffective(data, unix.CAP_SYS_ADMIN) {
		t.Fatal("unset CAP_SYS_ADMIN was detected")
	}
}

func TestShouldManageForeground(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name                   string
		terminal               bool
		joinParentProcessGroup bool
		foregroundProcessGroup int
		currentProcessGroup    int
		want                   bool
	}{
		{
			name:                   "foreground child process",
			terminal:               true,
			foregroundProcessGroup: 10,
			currentProcessGroup:    10,
			want:                   true,
		},
		{
			name:                   "namespace supervisor",
			terminal:               true,
			joinParentProcessGroup: true,
			foregroundProcessGroup: 10,
			currentProcessGroup:    10,
		},
		{
			name:                   "background process",
			terminal:               true,
			foregroundProcessGroup: 20,
			currentProcessGroup:    10,
		},
		{
			name:                   "no terminal",
			foregroundProcessGroup: 10,
			currentProcessGroup:    10,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			got := shouldManageForeground(
				test.terminal,
				test.joinParentProcessGroup,
				test.foregroundProcessGroup,
				test.currentProcessGroup,
			)
			if got != test.want {
				t.Errorf("shouldManageForeground() = %t, want %t", got, test.want)
			}
		})
	}
}

func TestNamespaceProcessAttributes(t *testing.T) {
	t.Parallel()

	permissionPreserving := namespaceProcessAttributes(PermissionPreservingMode)
	if permissionPreserving.Cloneflags != unix.CLONE_NEWNET {
		t.Errorf("permission-preserving clone flags = %#x", permissionPreserving.Cloneflags)
	}

	if len(permissionPreserving.UidMappings) != 0 || len(permissionPreserving.GidMappings) != 0 {
		t.Fatal("permission-preserving mode unexpectedly configures ID mappings")
	}

	rootless := namespaceProcessAttributes(RootlessMode)

	wantFlags := uintptr(unix.CLONE_NEWUSER | unix.CLONE_NEWNET)
	if rootless.Cloneflags != wantFlags {
		t.Errorf("rootless clone flags = %#x, want %#x", rootless.Cloneflags, wantFlags)
	}

	if len(rootless.UidMappings) != 1 || len(rootless.GidMappings) != 1 {
		t.Fatal("rootless mode does not configure single-ID mappings")
	}
}
