// Package cli parses public flags and transports internal invocation settings.
package cli

import (
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/erikgeiser/airjail/internal/config"
	"github.com/spf13/pflag"
)

// Invocation contains effective configuration and the child command.
type Invocation struct {
	Config  config.Config
	Command []string
	Help    bool
	Version bool
}

type flagValues struct {
	configPath                 string
	allowRules                 []string
	blockRules                 []string
	logLevel                   string
	proxy                      string
	connectTimeout             time.Duration
	allowUnresolved            bool
	allowArbitraryDNS          bool
	disableTransparentFallback bool
	privateLoopback            bool
	allowSockets               []string
	allowAllSockets            bool
	allowVSocks                bool
	keepUnsafeCapabilities     []string
	version                    bool
}

func newFlagSet(output io.Writer, values *flagValues) *pflag.FlagSet {
	flags := pflag.NewFlagSet("airjail", pflag.ContinueOnError)
	flags.SetInterspersed(false)
	flags.SetOutput(output)
	flags.StringVar(&values.configPath, "config", "", "YAML config `path`")
	flags.StringArrayVar(&values.allowRules, "allow", nil, "Allowed `destination` (repeatable)")
	flags.StringArrayVar(&values.blockRules, "block", nil, "Blocked `destination` (repeatable)")
	flags.StringVarP(&values.logLevel, "log", "l", "warning",
		"Log messages with this `level` or lower (silent < warning < traffic < info < debug)")
	flags.StringVar(&values.proxy, "proxy", "", "Outer proxy `URL`")
	flags.DurationVar(&values.connectTimeout, "connect-timeout", config.DefaultConnectTimeout,
		"Maximum outbound connection establishment `duration`")
	flags.BoolVar(&values.allowUnresolved, "allow-unresolved-rules", false,
		"Do not fail when destination hostname does not resolve")
	flags.BoolVar(&values.allowArbitraryDNS, "allow-arbitrary-dns", false,
		"Allow arbitrary child-controlled names to reach upstream DNS resolvers")
	flags.BoolVar(&values.disableTransparentFallback, "disable-transparent-fallback", false,
		"Disable transparent TCP and DNS interception")
	flags.BoolVar(&values.privateLoopback, "private-loopback", false,
		"Keep loopback connections inside the child network namespace")
	flags.StringArrayVar(&values.allowSockets, "allow-socket", nil,
		"Allow access to an existing Unix socket `path` (repeatable; requires Landlock ABI 9)")
	flags.BoolVar(&values.allowAllSockets, "allow-all-sockets", false,
		"Allow access to all Unix sockets (not vsock)")
	flags.BoolVar(&values.allowVSocks, "allow-vsocks", false, "Allow vsock sockets")
	flags.StringArrayVar(&values.keepUnsafeCapabilities, "keep-unsafe-capability", nil,
		"Preserve an otherwise dropped dangerous `capability` (repeatable)")
	flags.BoolVar(&values.version, "version", false, "Print version and exit")

	return flags
}

// WriteHelp prints public command usage.
func WriteHelp(writer io.Writer) {
	_, _ = fmt.Fprintln(writer, "Usage: airjail [flags] [--] command [args...]")
	_, _ = fmt.Fprintln(writer, "\nFlags:")

	values := &flagValues{}
	newFlagSet(writer, values).PrintDefaults()
}

// Parse parses args using command-shim semantics.
func Parse(args []string) (Invocation, error) {
	values := &flagValues{}
	flags := newFlagSet(io.Discard, values)

	err := flags.Parse(args)
	if errors.Is(err, pflag.ErrHelp) {
		return Invocation{Help: true}, nil
	}

	if err != nil {
		return Invocation{}, fmt.Errorf("parse flags: %w", err)
	}

	if values.version {
		return Invocation{Version: true}, nil
	}

	effective := config.Default()

	if values.configPath != "" {
		loaded, err := config.Load(values.configPath)
		if err != nil {
			return Invocation{}, err
		}

		effective = loaded
	}

	effective.Allow = append(effective.Allow, values.allowRules...)

	effective.Block = append(effective.Block, values.blockRules...)

	effective.KeepUnsafeCapabilities = append(
		effective.KeepUnsafeCapabilities,
		values.keepUnsafeCapabilities...,
	)

	if flags.Changed("log") || effective.Log == "" {
		effective.Log = values.logLevel
	}

	if flags.Changed("proxy") {
		effective.Proxy = values.proxy
	}

	if flags.Changed("connect-timeout") || values.configPath == "" {
		effective.ConnectTimeout = values.connectTimeout
	}

	if effective.ConnectTimeout <= 0 {
		return Invocation{}, fmt.Errorf("connect timeout must be greater than zero")
	}

	if flags.Changed("allow-unresolved-rules") {
		effective.AllowUnresolvedRules = values.allowUnresolved
	}

	if flags.Changed("allow-arbitrary-dns") {
		effective.AllowArbitraryDNS = values.allowArbitraryDNS
	}

	if flags.Changed("disable-transparent-fallback") {
		effective.TransparentFallback = !values.disableTransparentFallback
	}

	if flags.Changed("private-loopback") {
		effective.PrivateLoopback = values.privateLoopback
	}

	effective.AllowSockets = append(effective.AllowSockets, values.allowSockets...)

	if flags.Changed("allow-all-sockets") {
		effective.AllowAllSockets = values.allowAllSockets
	}

	if flags.Changed("allow-vsocks") {
		effective.AllowVSocks = values.allowVSocks
	}

	command := flags.Args()
	if len(command) == 0 {
		return Invocation{}, fmt.Errorf("child command is required")
	}

	return Invocation{Config: effective, Command: command}, nil
}
