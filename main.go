package main

import (
	"context"
	"fmt"
	"os"

	"github.com/erikgeiser/airjail/internal/application"
	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/namespace"
)

const setupErrorExitCode = 125

var version = "(custom build from git)"

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
			command, err := cli.ParseRestrictedExec(args[1:])
			if err != nil {
				return 0, err
			}

			return 0, namespace.ExecRestricted(command)
		}
	}

	return application.Run(ctx, args, version)
}

func runSupervisor(ctx context.Context, args []string) (int, error) {
	invocation, err := cli.ParseSupervisor(args)
	if err != nil {
		return 0, err
	}

	logger, err := logging.New(os.Stderr, invocation.LogLevel, "supervisor")
	if err != nil {
		return 0, fmt.Errorf("setup supervisor logger: %w", err)
	}

	// Prevent a socket-restricted child from tracing the supervisor and using
	// its unrestricted Unix socket access as a local-networking deputy.
	err = namespace.SetNonDumpable()
	if err != nil {
		return 0, err
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("get supervisor working directory: %w", err)
	}

	return namespace.RunSupervisor(ctx, namespace.SupervisorOptions{
		Command:                invocation.Command,
		Environment:            os.Environ(),
		Directory:              workingDirectory,
		HTTPSocket:             invocation.HTTPSocket,
		SOCKSocket:             invocation.SOCKSocket,
		DNSSocket:              invocation.DNSSocket,
		PreservePermissions:    invocation.PreservePermissions,
		RestrictUnixSockets:    invocation.RestrictUnixSockets,
		KeepUnsafeCapabilities: invocation.KeepUnsafeCapabilities,
		TransparentTCP:         invocation.TransparentTCP,
		Logger:                 logger,
	})
}
