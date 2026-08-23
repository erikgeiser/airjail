//nolint:goconst // Repeated flags keep complete command-line scenarios visible.
package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
}

func TestParseHelp(t *testing.T) {
	t.Parallel()

	invocation, err := Parse([]string{"--help"})
	if err != nil {
		t.Fatalf("Parse help: %v", err)
	}

	if !invocation.Help {
		t.Fatal("Help = false")
	}

	var output bytes.Buffer
	WriteHelp(&output)

	help := output.String()
	for _, expected := range []string{"Usage: airjail", "--allow", "--config", "--verbose"} {
		if !strings.Contains(help, expected) {
			t.Errorf("help does not contain %q: %s", expected, help)
		}
	}
}

func TestParseRejectsMissingCommand(t *testing.T) {
	t.Parallel()

	_, err := Parse([]string{"--allow", "example.com"})
	if err == nil {
		t.Fatal("Parse unexpectedly accepted a missing command")
	}
}
