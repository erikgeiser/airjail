package namespace

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

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
