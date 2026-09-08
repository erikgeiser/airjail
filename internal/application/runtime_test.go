package application

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestCreateAndClose(t *testing.T) {
	t.Parallel()

	runtimeDirectory := t.TempDir()

	created, err := createRuntimeDir(os.Getuid(), runtimeDirectory)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if filepath.Dir(created.HTTPSocket) != created.Directory {
		t.Errorf("HTTP socket = %q, not inside session", created.HTTPSocket)
	}

	if filepath.Dir(created.SOCKSocket) != created.Directory {
		t.Errorf("SOCKS socket = %q, not inside session", created.SOCKSocket)
	}

	if filepath.Dir(created.DNSSocket) != created.Directory {
		t.Errorf("DNS socket = %q, not inside session", created.DNSSocket)
	}

	info, err := os.Stat(created.Directory)
	if err != nil {
		t.Fatalf("stat session: %v", err)
	}

	if info.Mode().Perm() != 0o700 {
		t.Errorf("session permissions = %04o, want 0700", info.Mode().Perm())
	}

	err = created.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = os.Stat(created.Directory)
	if !os.IsNotExist(err) {
		t.Errorf("session still exists after Close: %v", err)
	}
}

func TestPrivateLoopbackChildEnvironment(t *testing.T) {
	t.Parallel()

	environment := childEnvironment([]string{"PATH=/bin", "NO_PROXY=original"}, true, true)

	for _, expected := range []string{
		"PATH=/bin",
		"NO_PROXY=localhost,.localhost,127.0.0.1,127.0.0.0/8,::1",
		"no_proxy=localhost,.localhost,127.0.0.1,127.0.0.0/8,::1",
	} {
		if !slices.Contains(environment, expected) {
			t.Errorf("environment does not contain %q: %v", expected, environment)
		}
	}
}

func TestCreateRejectsUnsafeRuntimeBase(t *testing.T) {
	t.Parallel()

	runtimeDirectory := t.TempDir()

	base := filepath.Join(runtimeDirectory, "airjail")

	err := os.Mkdir(base, 0o755)
	if err != nil {
		t.Fatalf("create unsafe base: %v", err)
	}

	_, err = createRuntimeDir(os.Getuid(), runtimeDirectory)
	if err == nil {
		t.Fatal("Create unexpectedly accepted an unsafe runtime base")
	}
}
