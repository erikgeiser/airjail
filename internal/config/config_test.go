package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
allow:
  - example.com
block:
  - "*.blocked.example:443"
log: debug
proxy: http://proxy.example:8080
connect_timeout: 3s
transparent_fallback: false
private_loopback: true
allow_unresolved_rules: true
allow_arbitrary_dns: true
restrict_sockets: true
keep_unsafe_capabilities: [CAP_SYS_ADMIN]
`)

	loaded, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if len(loaded.Allow) != 1 || loaded.Allow[0] != "example.com" {
		t.Errorf("Allow = %v", loaded.Allow)
	}

	if len(loaded.Block) != 1 || loaded.Block[0] != "*.blocked.example:443" {
		t.Errorf("Block = %v", loaded.Block)
	}

	if loaded.Log != "debug" {
		t.Errorf("Log = %s, want debug", loaded.Log)
	}

	if loaded.Proxy != "http://proxy.example:8080" {
		t.Errorf("Proxy = %q, want http://proxy.example:8080", loaded.Proxy)
	}

	if loaded.ConnectTimeout != 3*time.Second {
		t.Errorf("ConnectTimeout = %s, want 3s", loaded.ConnectTimeout)
	}

	if loaded.TransparentFallback {
		t.Error("TransparentFallback = true, want false")
	}

	if !loaded.PrivateLoopback {
		t.Error("PrivateLoopback = false, want true")
	}

	if !loaded.AllowUnresolvedRules {
		t.Error("AllowUnresolvedRules = false, want true")
	}

	if !loaded.AllowArbitraryDNS {
		t.Error("AllowArbitraryDNS = false, want true")
	}

	if !loaded.RestrictUnixSockets {
		t.Error("RestrictUnixSockets = false, want true")
	}

	if len(loaded.KeepUnsafeCapabilities) != 1 || loaded.KeepUnsafeCapabilities[0] != "CAP_SYS_ADMIN" {
		t.Errorf("KeepUnsafeCapabilities = %v", loaded.KeepUnsafeCapabilities)
	}
}

func TestLoadAppliesDefaults(t *testing.T) {
	t.Parallel()

	loaded, err := Load(writeConfig(t, "{}\n"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if !loaded.TransparentFallback {
		t.Error("TransparentFallback = false, want default true")
	}
}

func TestLoadRejectsUnknownFields(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "unknown: true\n")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly accepted an unknown field")
	}
}

func writeConfig(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "airjail.yaml")

	err := os.WriteFile(path, []byte(contents), 0o600)
	if err != nil {
		t.Fatalf("write config: %v", err)
	}

	return path
}
