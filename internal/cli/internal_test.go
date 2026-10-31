//nolint:goconst // Complete wire payloads keep protocol cases self-contained.
package cli

import (
	"reflect"
	"slices"
	"strings"
	"testing"
)

func TestSupervisorJSONSettingsAndNativeArgv(t *testing.T) {
	t.Parallel()

	// The aggregate command exceeds Linux's single-argument limit, and one
	// argument is not UTF-8. Neither belongs inside the JSON settings argument.
	command := []string{"-child", "--flag", "", "quotes '\" and spaces", string([]byte{0xff}),
		strings.Repeat("x", 70_000), strings.Repeat("y", 70_000)}
	wire := `{"http_socket":"/run/session space/http.sock","socks_socket":"/run/socks.sock",
		"dns_socket":"/run/dns.sock","log_level":"debug","preserve_permissions":true,
		"restrict_unix_sockets":true,"manage_foreground":true,"keep_unsafe_capabilities":["CAP_NET_ADMIN"],
		"transparent_tcp":true,"private_loopback":true}`
	want := SupervisorInvocation{
		Command: command, HTTPSocket: "/run/session space/http.sock", SOCKSocket: "/run/socks.sock",
		DNSSocket: "/run/dns.sock", LogLevel: "debug", PreservePermissions: true, RestrictUnixSockets: true,
		ManageForeground: true, KeepUnsafeCapabilities: []string{"CAP_NET_ADMIN"}, TransparentTCP: true, PrivateLoopback: true,
	}

	decoded, err := DecodeSupervisor(append([]string{wire}, command...))
	if err != nil || !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decode supervisor: error=%v, settings=%#v", err, decoded)
	}

	args, err := want.Args()
	if err != nil {
		t.Fatalf("encode supervisor: %v", err)
	}

	if !slices.Equal(args[1:], command) || len(args[0]) > 2048 {
		t.Fatal("supervisor encoding changed child argv or included it in the settings")
	}

	decoded, err = DecodeSupervisor(args)
	if err != nil || !reflect.DeepEqual(decoded, want) {
		t.Fatalf("forwarded supervisor settings changed: error=%v, settings=%#v", err, decoded)
	}
}

func TestRestrictedExecJSONSettingsAndNativeArgv(t *testing.T) {
	t.Parallel()

	want := RestrictedExecInvocation{Command: []string{"child", "--log-level", "", string([]byte{0xff})}, LogLevel: "debug"}

	decoded, err := DecodeRestrictedExec(append([]string{`{"log_level":"debug"}`}, want.Command...))
	if err != nil || !reflect.DeepEqual(decoded, want) {
		t.Fatalf("decode restricted exec: error=%v, settings=%#v", err, decoded)
	}

	args, err := want.Args()
	if err != nil {
		t.Fatalf("encode restricted exec: %v", err)
	}

	decoded, err = DecodeRestrictedExec(args)
	if err != nil || !reflect.DeepEqual(decoded, want) || !slices.Equal(args[1:], want.Command) {
		t.Fatalf("forwarded restricted-exec settings changed: error=%v, settings=%#v", err, decoded)
	}

	defaults, err := DecodeRestrictedExec([]string{"{}", "child"})
	if err != nil || defaults.LogLevel != "warning" {
		t.Fatalf("default restricted-exec log level = %q, %v", defaults.LogLevel, err)
	}
}

func TestInternalInvocationsRejectInvalidSettings(t *testing.T) {
	t.Parallel()

	for _, decoder := range []struct {
		name   string
		decode func([]string) error
	}{
		{name: "supervisor", decode: func(args []string) error {
			_, err := DecodeSupervisor(args)

			return err
		}},
		{name: "restricted exec", decode: func(args []string) error {
			_, err := DecodeRestrictedExec(args)

			return err
		}},
	} {
		t.Run(decoder.name, func(t *testing.T) {
			t.Parallel()

			for _, test := range []struct {
				name string
				args []string
			}{
				{name: "missing invocation"},
				{name: "missing command", args: []string{"{}"}},
				{name: "empty command", args: []string{"{}", ""}},
				{name: "malformed JSON", args: []string{"{", "child"}},
				{name: "null settings", args: []string{"null", "child"}},
				{name: "array settings", args: []string{"[]", "child"}},
				{name: "unknown member", args: []string{`{"proxy":"http://user:secret@proxy.test"}`, "child"}},
				{name: "duplicate member", args: []string{`{"log_level":"debug","log_level":"silent"}`, "child"}},
				{name: "wrong case", args: []string{`{"Log_Level":"debug"}`, "child"}},
				{name: "wrong type", args: []string{`{"log_level":true}`, "child"}},
				{name: "multiple objects", args: []string{"{} {}", "child"}},
				{name: "trailing garbage", args: []string{"{} trailing", "child"}},
				{name: "invalid UTF-8", args: []string{"{\"log_level\":\"\xff\"}", "child"}},
			} {
				t.Run(test.name, func(t *testing.T) {
					t.Parallel()

					err := decoder.decode(test.args)
					if err == nil {
						t.Fatal("invalid invocation was accepted")
					}
				})
			}
		})
	}
}

func TestSupervisorRequiresTransparentGatewaySockets(t *testing.T) {
	t.Parallel()

	for _, wire := range []string{
		`{"transparent_tcp":true}`,
		`{"transparent_tcp":true,"socks_socket":"/run/socks.sock"}`,
		`{"transparent_tcp":true,"dns_socket":"/run/dns.sock"}`,
	} {
		_, err := DecodeSupervisor([]string{wire, "child"})
		if err == nil {
			t.Fatalf("accepted transparent interception without both sockets: %s", wire)
		}
	}
}

func TestInternalEncodingRejectsInvalidSettings(t *testing.T) {
	t.Parallel()

	_, err := (SupervisorInvocation{Command: []string{"child"}, HTTPSocket: string([]byte{0xff})}).Args()
	if err == nil {
		t.Error("invalid socket path bytes were silently changed")
	}

	_, err = (RestrictedExecInvocation{}).Args()
	if err == nil {
		t.Error("missing child command was accepted")
	}
}
