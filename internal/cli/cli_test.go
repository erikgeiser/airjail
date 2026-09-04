//nolint:goconst // Repeated flags keep complete command-line scenarios visible.
package cli

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestParseStopsAtChildCommand(t *testing.T) {
	t.Parallel()

	invocation, err := Parse([]string{"--allow", "example.com", "curl", "-v", "https://example.com"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !slices.Equal(invocation.Config.Allow, []string{"example.com"}) {
		t.Errorf("Allow = %v", invocation.Config.Allow)
	}

	wantCommand := []string{"curl", "-v", "https://example.com"}
	if !slices.Equal(invocation.Command, wantCommand) {
		t.Errorf("Command = %v, want %v", invocation.Command, wantCommand)
	}
}

func TestParseSupportsExplicitSeparator(t *testing.T) {
	t.Parallel()

	invocation, err := Parse([]string{"--block", "example.com", "--", "-child", "argument"})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !slices.Equal(invocation.Command, []string{"-child", "argument"}) {
		t.Errorf("Command = %v", invocation.Command)
	}
}

func TestParseMergesConfigAndCLI(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "airjail.yaml")

	contents := []byte(`
allow: [config.example]
block: [blocked.example]
log: debug
allow_unresolved_rules: true
restrict_sockets: true
keep_unsafe_capabilities: [CAP_SYS_PTRACE]
`)

	err := os.WriteFile(configPath, contents, 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	invocation, err := Parse([]string{
		"--config", configPath,
		"--allow", "cli.example",
		"--block", "cli-blocked.example",
		"--log", "info",
		"--allow-unresolved-rules=false",
		"--restrict-sockets=false",
		"--keep-unsafe-capability", "CAP_SYS_ADMIN",
		"command",
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	if !slices.Equal(invocation.Config.Allow, []string{"config.example", "cli.example"}) {
		t.Errorf("Allow = %v", invocation.Config.Allow)
	}

	if !slices.Equal(invocation.Config.Block, []string{"blocked.example", "cli-blocked.example"}) {
		t.Errorf("Block = %v", invocation.Config.Block)
	}

	if invocation.Config.Log != "info" {
		t.Errorf("Log = %s, want CLI override info", invocation.Config.Log)
	}

	if invocation.Config.AllowUnresolvedRules {
		t.Error("AllowUnresolvedRules = true, want CLI override false")
	}

	if invocation.Config.RestrictUnixSockets {
		t.Error("RestrictUnixSockets = true, want CLI override false")
	}

	wantCapabilities := []string{"CAP_SYS_PTRACE", "CAP_SYS_ADMIN"}
	if !slices.Equal(invocation.Config.KeepUnsafeCapabilities, wantCapabilities) {
		t.Errorf(
			"KeepUnsafeCapabilities = %v, want %v",
			invocation.Config.KeepUnsafeCapabilities,
			wantCapabilities,
		)
	}
}

func TestParseRejectsMissingCommand(t *testing.T) {
	t.Parallel()

	_, err := Parse([]string{"--allow", "example.com"})
	if err == nil {
		t.Fatal("Parse unexpectedly accepted a missing command")
	}
}

func TestParseSupervisor(t *testing.T) {
	t.Parallel()

	invocation, err := ParseSupervisor([]string{
		"--http-socket", "/run/http.sock",
		"--socks-socket", "/run/socks.sock",
		"--dns-socket", "/run/dns.sock",
		"--log-level", "debug",
		"--preserve-permissions",
		"--restrict-unix-sockets",
		"--keep-unsafe-capability", "CAP_SYS_ADMIN",
		"--transparent-tcp",
		"--",
		"command", "--child-flag",
	})
	if err != nil {
		t.Fatalf("ParseSupervisor: %v", err)
	}

	if invocation.HTTPSocket != "/run/http.sock" || invocation.SOCKSocket != "/run/socks.sock" ||
		invocation.DNSSocket != "/run/dns.sock" {
		t.Errorf("proxy sockets = %q, %q, %q", invocation.HTTPSocket, invocation.SOCKSocket, invocation.DNSSocket)
	}

	if invocation.LogLevel != "debug" || !invocation.PreservePermissions || !invocation.RestrictUnixSockets ||
		!invocation.TransparentTCP {
		t.Errorf("supervisor options = %#v", invocation)
	}

	if !slices.Equal(invocation.KeepUnsafeCapabilities, []string{"CAP_SYS_ADMIN"}) {
		t.Errorf("KeepUnsafeCapabilities = %v", invocation.KeepUnsafeCapabilities)
	}

	if !slices.Equal(invocation.Command, []string{"command", "--child-flag"}) {
		t.Errorf("Command = %v", invocation.Command)
	}
}

func TestParseSupervisorRejectsMissingCommand(t *testing.T) {
	t.Parallel()

	_, err := ParseSupervisor([]string{"--log-level", "debug"})
	if err == nil {
		t.Fatal("ParseSupervisor unexpectedly accepted a missing command")
	}
}

func TestParseRestrictedExec(t *testing.T) {
	t.Parallel()

	command, err := ParseRestrictedExec([]string{"--", "command", "--flag"})
	if err != nil {
		t.Fatalf("ParseRestrictedExec: %v", err)
	}

	if !slices.Equal(command, []string{"command", "--flag"}) {
		t.Errorf("command = %v", command)
	}
}

func TestParseRestrictedExecRejectsMissingCommand(t *testing.T) {
	t.Parallel()

	_, err := ParseRestrictedExec([]string{"--"})
	if err == nil {
		t.Fatal("ParseRestrictedExec unexpectedly accepted a missing command")
	}
}
