// Package cli parses the public airjail command line.
package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/erikgeiser/airjail/internal/config"
	"github.com/spf13/pflag"
)

const (
	SupervisorCommand                   = "__netns-supervisor"
	RestrictedExecCommand               = "__restricted-exec"
	SupervisorHTTPSocketOption          = "http-socket"
	SupervisorSOCKSSocketOption         = "socks-socket"
	SupervisorDNSSocketOption           = "dns-socket"
	SupervisorPreservePermissionsOption = "preserve-permissions"
	SupervisorRestrictSocketsOption     = "restrict-unix-sockets"
	SupervisorKeepUnsafeCapability      = "keep-unsafe-capability"
	SupervisorTransparentTCPOption      = "transparent-tcp"
	SupervisorLogLevel                  = "log-level"
)

// Invocation contains effective configuration and the child command.
type Invocation struct {
	Config  config.Config
	Command []string
	Help    bool
	Version bool
}

// SupervisorInvocation contains configuration for the hidden namespace supervisor command.
type SupervisorInvocation struct {
	Command                []string
	HTTPSocket             string
	SOCKSocket             string
	DNSSocket              string
	LogLevel               string
	PreservePermissions    bool
	RestrictUnixSockets    bool
	KeepUnsafeCapabilities []string
	TransparentTCP         bool
}

type flagValues struct {
	configPath             string
	allowRules             []string
	blockRules             []string
	logLevel               string
	allowUnresolved        bool
	restrictUnixSockets    bool
	keepUnsafeCapabilities []string
	version                bool
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
	flags.BoolVar(&values.allowUnresolved, "allow-unresolved-rules", false,
		"Do not fail when destination hostname does not resolve")
	flags.BoolVar(&values.restrictUnixSockets, "restrict-sockets", false,
		"Restrict creation of Unix and vsock sockets")
	flags.StringArrayVar(&values.keepUnsafeCapabilities, "keep-unsafe-capability", nil,
		"Preserve an otherwise dropped dangerous `capability` (repeatable)")
	flags.BoolVar(&values.version, "version", false, "Print version and exit")

	return flags
}

// ParseSupervisor parses the hidden namespace supervisor command line.
func ParseSupervisor(args []string) (SupervisorInvocation, error) {
	flags := pflag.NewFlagSet(SupervisorCommand, pflag.ContinueOnError)
	flags.SetInterspersed(false)
	flags.SetOutput(io.Discard)

	invocation := SupervisorInvocation{}
	flags.StringVar(&invocation.HTTPSocket, SupervisorHTTPSocketOption, "", "outer HTTP proxy socket")
	flags.StringVar(&invocation.SOCKSocket, SupervisorSOCKSSocketOption, "", "outer SOCKS proxy socket")
	flags.StringVar(&invocation.DNSSocket, SupervisorDNSSocketOption, "", "outer DNS proxy socket")
	flags.StringVar(&invocation.LogLevel, SupervisorLogLevel, "warning", "log level")
	flags.BoolVar(
		&invocation.PreservePermissions,
		SupervisorPreservePermissionsOption,
		false,
		"preserve caller permissions",
	)
	flags.BoolVar(
		&invocation.RestrictUnixSockets,
		SupervisorRestrictSocketsOption,
		false,
		"restrict child local sockets",
	)
	flags.StringArrayVar(
		&invocation.KeepUnsafeCapabilities,
		SupervisorKeepUnsafeCapability,
		nil,
		"dangerous capability to preserve",
	)
	flags.BoolVar(
		&invocation.TransparentTCP,
		SupervisorTransparentTCPOption,
		false,
		"redirect non-proxy TCP connections",
	)

	err := flags.Parse(args)
	if err != nil {
		return SupervisorInvocation{}, fmt.Errorf("parse supervisor flags: %w", err)
	}

	invocation.Command = flags.Args()
	if len(invocation.Command) == 0 {
		return SupervisorInvocation{}, fmt.Errorf("supervisor child command is required")
	}

	return invocation, nil
}

// ParseRestrictedExec parses the hidden restricted-exec command line.
func ParseRestrictedExec(args []string) ([]string, error) {
	if len(args) > 0 && args[0] == "--" {
		args = args[1:]
	}

	if len(args) == 0 {
		return nil, fmt.Errorf("restricted child command is required")
	}

	return args, nil
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

	effective := config.Config{}

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

	if flags.Changed("allow-unresolved-rules") {
		effective.AllowUnresolvedRules = values.allowUnresolved
	}

	if flags.Changed("restrict-sockets") {
		effective.RestrictUnixSockets = values.restrictUnixSockets
	}

	command := flags.Args()
	if len(command) == 0 {
		return Invocation{}, fmt.Errorf("child command is required")
	}

	return Invocation{Config: effective, Command: command}, nil
}
