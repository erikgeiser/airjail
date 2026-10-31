package cli

import (
	"encoding/json/v2"
	"fmt"
	"strings"
)

const (
	SupervisorCommand     = "__netns-supervisor"
	RestrictedExecCommand = "__restricted-exec"
)

// RestrictedExecInvocation carries only settings needed by the socket-restricted child.
type RestrictedExecInvocation struct {
	Command  []string `json:"-"`
	LogLevel string   `json:"log_level"`
}

// SupervisorInvocation carries effective child settings and supervisor runtime decisions.
// Policy rules and upstream proxy credentials remain in the outer process.
type SupervisorInvocation struct {
	Command                []string `json:"-"`
	HTTPSocket             string   `json:"http_socket"`
	SOCKSocket             string   `json:"socks_socket"`
	DNSSocket              string   `json:"dns_socket"`
	LogLevel               string   `json:"log_level"`
	PreservePermissions    bool     `json:"preserve_permissions"`
	RestrictUnixSockets    bool     `json:"restrict_unix_sockets"`
	ManageForeground       bool     `json:"manage_foreground"`
	KeepUnsafeCapabilities []string `json:"keep_unsafe_capabilities"`
	TransparentTCP         bool     `json:"transparent_tcp"`
	TransparentIPv6        bool     `json:"transparent_ipv6"`
	PrivateLoopback        bool     `json:"private_loopback"`
}

// Args returns JSON settings followed by the unmodified child argv.
func (invocation SupervisorInvocation) Args() ([]string, error) {
	return internalArgs(invocation, invocation.Command)
}

// Args returns JSON settings followed by the unmodified child argv.
func (invocation RestrictedExecInvocation) Args() ([]string, error) {
	return internalArgs(invocation, invocation.Command)
}

// DecodeSupervisor decodes a hidden supervisor invocation without flag parsing.
func DecodeSupervisor(args []string) (SupervisorInvocation, error) {
	invocation := SupervisorInvocation{LogLevel: "warning"}

	err := decodeInternal(args, &invocation)
	if err != nil {
		return SupervisorInvocation{}, fmt.Errorf("decode supervisor invocation: %w", err)
	}

	invocation.Command = args[1:]

	if invocation.TransparentTCP && (invocation.SOCKSocket == "" || invocation.DNSSocket == "") {
		return SupervisorInvocation{}, fmt.Errorf("transparent TCP requires outer SOCKS and DNS sockets")
	}

	return invocation, nil
}

// DecodeRestrictedExec decodes a hidden restricted-exec invocation without flag parsing.
func DecodeRestrictedExec(args []string) (RestrictedExecInvocation, error) {
	invocation := RestrictedExecInvocation{LogLevel: "warning"}

	err := decodeInternal(args, &invocation)
	if err != nil {
		return RestrictedExecInvocation{}, fmt.Errorf("decode restricted-exec invocation: %w", err)
	}

	invocation.Command = args[1:]

	return invocation, nil
}

func internalArgs(settings any, command []string) ([]string, error) {
	if len(command) == 0 || command[0] == "" {
		return nil, fmt.Errorf("internal child command is required")
	}

	encoded, err := json.Marshal(settings)
	if err != nil {
		return nil, fmt.Errorf("encode internal settings: %w", err)
	}

	// Unix argv may contain non-UTF-8 bytes, which JSON strings cannot preserve.
	return append([]string{string(encoded)}, command...), nil
}

func decodeInternal(args []string, settings any) error {
	if len(args) < 2 || args[1] == "" {
		return fmt.Errorf("internal invocation requires JSON settings and a child command")
	}

	if !strings.HasPrefix(strings.TrimSpace(args[0]), "{") {
		return fmt.Errorf("internal settings must be a UTF-8 JSON object")
	}

	err := json.Unmarshal([]byte(args[0]), settings, json.RejectUnknownMembers(true))
	if err != nil {
		return fmt.Errorf("decode internal settings: %w", err)
	}

	return nil
}
