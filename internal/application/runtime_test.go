//nolint:goconst // Literal proxy settings keep the expected environment explicit.
package application

import (
	"maps"
	"os"
	"path/filepath"
	"strings"
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

	sibling, err := createRuntimeDir(os.Getuid(), runtimeDirectory)
	if err != nil {
		t.Fatalf("create second session: %v", err)
	}
	defer func() { _ = sibling.Close() }()

	if sibling.Directory == created.Directory {
		t.Fatal("concurrent invocations share a session directory")
	}

	err = created.Close()
	if err != nil {
		t.Fatalf("Close: %v", err)
	}

	_, err = os.Stat(created.Directory)
	if !os.IsNotExist(err) {
		t.Errorf("session still exists after Close: %v", err)
	}

	_, err = os.Stat(sibling.Directory)
	if err != nil {
		t.Errorf("closing one session removed another: %v", err)
	}
}

func TestChildEnvironmentReplacesInheritedProxySettings(t *testing.T) {
	t.Parallel()

	proxyValues := map[string]string{
		"HTTP_PROXY": "http://127.97.105.114:19080", "HTTPS_PROXY": "http://127.97.105.114:19080",
		"GRPC_PROXY": "http://127.97.105.114:19080", "ALL_PROXY": "socks5h://127.97.105.114:19081",
		"FTP_PROXY": "socks5h://127.97.105.114:19081", "NO_PROXY": "",
	}

	for _, test := range []struct {
		name    string
		proxy   bool
		private bool
	}{
		{name: "no egress"},
		{name: "proxy mode", proxy: true},
		{name: "private loopback", proxy: true, private: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			original := []string{"PATH=/bin", "KEEP=value=rest"}
			want := map[string]string{"PATH": "/bin", "KEEP": "value=rest"}

			for name, value := range proxyValues {
				original = append(original, name+"=inherited", strings.ToLower(name)+"=inherited")

				if !test.proxy {
					continue
				}

				if name == "NO_PROXY" && test.private {
					value = "localhost,.localhost,127.0.0.1,127.0.0.0/8,::1"
				}

				want[name] = value
				want[strings.ToLower(name)] = value
			}

			got := make(map[string]string)

			for _, entry := range childEnvironment(original, test.proxy, test.private) {
				name, value, _ := strings.Cut(entry, "=")
				if _, duplicate := got[name]; duplicate {
					t.Errorf("duplicate environment variable %s", name)
				}

				got[name] = value
			}

			if !maps.Equal(got, want) {
				t.Errorf("environment = %v, want %v", got, want)
			}
		})
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
