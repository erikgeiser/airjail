package namespace

import (
	"errors"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	landlockUnixSocketABI       = 9
	landlockAccessFSResolveUnix = uint64(1 << 16)
)

type landlockRulesetAttr struct {
	handledAccessFS  uint64
	handledAccessNet uint64
	scoped           uint64
}

func landlockABIVersion() (int, error) {
	version, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		0,
		0,
		unix.LANDLOCK_CREATE_RULESET_VERSION,
		0,
		0,
		0,
	)
	if errno != 0 {
		return 0, fmt.Errorf("query Landlock ABI: %w", errno)
	}

	return int(version), nil
}

func landlockUnixSocketsAvailable(abi int, architecture string) bool {
	// Seccomp cannot inspect the socketcall argument array on 386, so retaining
	// the legacy filter is necessary to keep denying AF_VSOCK there.
	return abi >= landlockUnixSocketABI && architecture != "386"
}

func landlockUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EOPNOTSUPP)
}

func restrictExternalUnixSockets() error {
	attributes := landlockRulesetAttr{
		handledAccessFS: landlockAccessFSResolveUnix,
		scoped:          unix.LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET,
	}

	ruleset, _, errno := unix.Syscall6(
		unix.SYS_LANDLOCK_CREATE_RULESET,
		uintptr(unsafe.Pointer(&attributes)),
		unsafe.Sizeof(attributes),
		0,
		0,
		0,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("create Unix socket Landlock ruleset: %w", errno)
	}

	fileDescriptor := int(ruleset)
	defer func() { _ = unix.Close(fileDescriptor) }()

	_, _, errno = unix.Syscall(
		unix.SYS_LANDLOCK_RESTRICT_SELF,
		uintptr(fileDescriptor),
		unix.LANDLOCK_RESTRICT_SELF_TSYNC,
		0,
	)
	if errno != 0 {
		return fmt.Errorf("enforce Unix socket Landlock ruleset: %w", errno)
	}

	return nil
}
