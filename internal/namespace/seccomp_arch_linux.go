package namespace

import (
	"fmt"
	"math"
	"unsafe"

	"github.com/elastic/go-seccomp-bpf/arch"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const seccompArchitectureOffset = 4

// loadNativeArchitectureGuard works around go-seccomp-bpf applying a policy's
// default action to syscalls from an unexpected audit architecture. Remove this
// filter when the upstream policy assembler rejects architecture mismatches.
func loadNativeArchitectureGuard() error {
	architecture, err := arch.GetInfo("")
	if err != nil {
		return fmt.Errorf("identify native seccomp architecture: %w", err)
	}

	instructions := nativeArchitectureGuard(uint32(architecture.ID))

	rawInstructions, err := bpf.Assemble(instructions)
	if err != nil {
		return fmt.Errorf("assemble native architecture guard: %w", err)
	}

	if len(rawInstructions) == 0 || len(rawInstructions) > math.MaxUint16 {
		return fmt.Errorf("assemble native architecture guard: invalid instruction count %d", len(rawInstructions))
	}

	filters := make([]unix.SockFilter, 0, len(rawInstructions))
	for _, instruction := range rawInstructions {
		filters = append(filters, unix.SockFilter{
			Code: instruction.Op,
			Jt:   instruction.Jt,
			Jf:   instruction.Jf,
			K:    instruction.K,
		})
	}

	program := unix.SockFprog{
		Len:    uint16(len(filters)),
		Filter: &filters[0],
	}

	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		unix.SECCOMP_SET_MODE_FILTER,
		unix.SECCOMP_FILTER_FLAG_TSYNC,
		uintptr(unsafe.Pointer(&program)),
	)
	if errno != 0 {
		return fmt.Errorf("load native architecture guard: %w", errno)
	}

	return nil
}

func nativeArchitectureGuard(nativeArchitecture uint32) []bpf.Instruction {
	return []bpf.Instruction{
		bpf.LoadAbsolute{Off: seccompArchitectureOffset, Size: 4},
		bpf.JumpIf{Cond: bpf.JumpEqual, Val: nativeArchitecture, SkipTrue: 1},
		bpf.RetConstant{Val: unix.SECCOMP_RET_KILL_PROCESS},
		bpf.RetConstant{Val: unix.SECCOMP_RET_ALLOW},
	}
}
