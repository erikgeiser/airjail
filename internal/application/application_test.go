package application

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/erikgeiser/airjail/internal/config"
	"github.com/erikgeiser/airjail/internal/namespace"
	"github.com/erikgeiser/airjail/internal/policy"
)

func TestProxyChildFailureCleanup(t *testing.T) {
	runtimeDirectory := t.TempDir()
	t.Setenv("XDG_RUNTIME_DIR", runtimeDirectory)

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()

	networkPolicy, err := policy.New(ctx, []string{"192.0.2.1"}, nil, policy.Options{})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	configuration := config.Default()
	configuration.Proxy = "http://127.0.0.1:1"
	// Lookup fails after proxies start, but before creating namespaces or a child.
	child := namespace.ParentOptions{Executable: filepath.Join(runtimeDirectory, "missing-airjail"), Command: []string{"child"}}

	_, err = runWithProxies(ctx, configuration, child, networkPolicy, nil)
	if !errors.Is(err, os.ErrNotExist) || ctx.Err() != nil {
		t.Fatalf("setup error = %v, context = %v; want lookup failure and prompt shutdown", err, ctx.Err())
	}

	entries, err := os.ReadDir(filepath.Join(runtimeDirectory, "airjail"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("session cleanup: entries=%v, error=%v", entries, err)
	}
}
