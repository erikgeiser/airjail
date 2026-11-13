package namespace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func assertFileReparentingAllowed(tb testing.TB) {
	tb.Helper()

	directory := tb.TempDir()

	source := filepath.Join(directory, "source")
	destination := filepath.Join(directory, "destination")

	for _, path := range []string{source, destination} {
		err := os.Mkdir(path, 0o700)
		if err != nil {
			tb.Fatalf("create directory: %v", err)
		}
	}

	file := filepath.Join(source, "file")

	err := os.WriteFile(file, []byte("contents"), 0o600)
	if err != nil {
		tb.Fatalf("create file: %v", err)
	}

	linked := filepath.Join(destination, "linked")

	err = os.Link(file, linked)
	if err != nil {
		tb.Fatalf("link file across directories: %v", err)
	}

	moved := filepath.Join(destination, "moved")

	err = os.Rename(file, moved)
	if err != nil {
		tb.Fatalf("rename file across directories: %v", err)
	}

	for _, path := range []string{linked, moved} {
		contents, readErr := os.ReadFile(path)
		if readErr != nil || string(contents) != "contents" {
			tb.Fatalf("read reparented file: contents=%q, error=%v", contents, readErr)
		}
	}

	err = os.Rename(destination, filepath.Join(source, "moved-directory"))
	if err != nil {
		tb.Fatalf("rename directory across directories: %v", err)
	}
}

func TestAllowedUnixSocketRejectsInvalidPaths(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	regularFile := filepath.Join(directory, "file")

	err := os.WriteFile(regularFile, nil, 0o600)
	if err != nil {
		t.Fatal(err)
	}

	for _, path := range []string{"", filepath.Join(directory, "missing"), directory, regularFile} {
		t.Run(path, func(t *testing.T) {
			t.Parallel()

			// Invalid paths must be rejected before attempting to install a rule.
			err := allowUnixSocket(-1, path)
			if err == nil || errors.Is(err, unix.EBADF) {
				t.Fatalf("invalid socket path was not rejected before adding its rule: %v", err)
			}
		})
	}
}
