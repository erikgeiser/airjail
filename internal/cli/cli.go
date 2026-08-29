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
	SupervisorPreservePermissionsOption = "preserve-permissions"
	SupervisorRestrictSocketsOption     = "restrict-unix-sockets"
	SupervisorLogLevel                  = "log-level"
)

// Invocation contains effective configuration and the child command.
type Invocation struct {
	Config  config.Config
	Command []string
	Help    bool
	Version bool
}

type flagValues struct {
	configPath          string
	allowRules          []string
	blockRules          []string
	logLevel            string
	allowUnresolved     bool
	restrictUnixSockets bool
	version             bool
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
		"Restrict connection to unix domain sockets")
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
