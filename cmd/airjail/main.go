package main

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/erikgeiser/airjail/internal/application"
	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/namespace"
	"github.com/spf13/pflag"
)

const setupErrorExitCode = 125

func main() {
	exitCode, err := run(context.Background(), os.Args[1:])
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "Error: %v\n", err)

		os.Exit(setupErrorExitCode)
	}

	os.Exit(exitCode)
}

func run(ctx context.Context, args []string) (int, error) {
	if len(args) > 0 {
		switch args[0] {
		case cli.SupervisorCommand:
			return runSupervisor(ctx, args[1:])
		case cli.RestrictedExecCommand:
			return 0, namespace.ExecRestricted(args[1:])
		}
	}

	return application.Run(ctx, args)
}

func runSupervisor(ctx context.Context, args []string) (int, error) {
	flags := pflag.NewFlagSet(cli.SupervisorCommand, pflag.ContinueOnError)
	flags.SetInterspersed(false)
	flags.SetOutput(io.Discard)

	var (
		httpSocket          string
		socksSocket         string
		preservePermissions bool
		restrictUnixSockets bool
	)

	flags.StringVar(&httpSocket, cli.SupervisorHTTPSocketOption, "", "outer HTTP proxy socket")
	flags.StringVar(&socksSocket, cli.SupervisorSOCKSSocketOption, "", "outer SOCKS proxy socket")
	flags.BoolVar(
		&preservePermissions,
		cli.SupervisorPreservePermissionsOption,
		false,
		"preserve caller permissions",
	)
	flags.BoolVar(
		&restrictUnixSockets,
		cli.SupervisorRestrictSocketsOption,
		false,
		"restrict child Unix sockets",
	)

	err := flags.Parse(args)
	if err != nil {
		return 0, fmt.Errorf("parse supervisor flags: %w", err)
	}

	command := flags.Args()
	if len(command) == 0 {
		return 0, fmt.Errorf("supervisor child command is required")
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("get supervisor working directory: %w", err)
	}

	return namespace.RunSupervisor(ctx, namespace.SupervisorOptions{
		Command:             command,
		Environment:         os.Environ(),
		Directory:           workingDirectory,
		HTTPSocket:          httpSocket,
		SOCKSocket:          socksSocket,
		PreservePermissions: preservePermissions,
		RestrictUnixSockets: restrictUnixSockets,
	})
}
