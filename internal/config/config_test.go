package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, `
allow:
  - example.com
block:
  - "*.blocked.example:443"
verbose: debug
allow_unresolved_rules: true
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

	if !loaded.AllowUnresolvedRules {
		t.Error("AllowUnresolvedRules = false, want true")
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

func TestLoadRejectsMultipleDocuments(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "allow: [example.com]\n---\nblock: [blocked.example]\n")

	_, err := Load(path)
	if err == nil {
		t.Fatal("Load unexpectedly accepted multiple documents")
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
