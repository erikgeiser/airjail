// Package application wires airjail's policy, proxies, namespace, and command supervision.
package application

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/namespace"
	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/proxyhttp"
	"github.com/erikgeiser/airjail/internal/proxysocks"
	"github.com/erikgeiser/airjail/internal/session"
)

// Run executes one public airjail invocation.
func Run(ctx context.Context, args []string) (int, error) {
	invocation, err := cli.Parse(args)
	if err != nil {
		return 0, err
	}

	if invocation.Help {
		cli.WriteHelp(os.Stdout)

		return 0, nil
	}

	workingDirectory, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("get current working directory: %w", err)
	}

	executable, err := os.Executable()
	if err != nil {
		return 0, fmt.Errorf("locate airjail executable: %w", err)
	}

	logger, err := logging.New(os.Stderr, invocation.Config.Log, "")
	if err != nil {
		return 0, fmt.Errorf("setup logger: %w", err)
	}

	namespaceMode, err := namespace.DetectMode()
	if err != nil {
		return 0, err
	}

	if namespaceMode == namespace.RootlessMode {
		logger.Log(logging.Info, "using rootless user and network namespaces")
		logSupplementaryGroupLimitation(logger)
	} else {
		logger.Log(logging.Info, "using permission-preserving network namespace")
	}

	networkPolicy, err := policy.New(ctx, invocation.Config.Allow, invocation.Config.Block, policy.Options{
		AllowUnresolved: invocation.Config.AllowUnresolvedRules,
		Warn: func(message string) {
			logger.Log(logging.Warning, "warning: %s", message)
		},
	})
	if err != nil {
		return 0, err
	}

	environment := childEnvironment(os.Environ(), !networkPolicy.Empty())
	if networkPolicy.Empty() {
		logger.Log(logging.Info, "empty policy: starting child in loopback-only namespace without proxies")

		return namespace.Run(ctx, namespace.ParentOptions{
			Executable:  executable,
			Command:     invocation.Command,
			Environment: environment,
			Directory:   workingDirectory,
			Mode:        namespaceMode,
		})
	}

	return runWithProxies(
		ctx,
		executable,
		workingDirectory,
		environment,
		invocation.Command,
		networkPolicy,
		namespaceMode,
		logger,
	)
}

func runWithProxies(
	ctx context.Context,
	executable string,
	workingDirectory string,
	environment []string,
	command []string,
	networkPolicy *policy.Policy,
	namespaceMode namespace.Mode,
	logger *logging.Logger,
) (int, error) {
	runtimeSession, err := session.Create(os.Getuid(), os.Getenv("XDG_RUNTIME_DIR"))
	if err != nil {
		return 0, err
	}
	defer func() {
		closeErr := runtimeSession.Close()
		if closeErr != nil {
			logger.Log(logging.Warning, "warning: %v", closeErr)
		}
	}()

	listenConfig := net.ListenConfig{}

	httpListener, err := listenConfig.Listen(ctx, "unix", runtimeSession.HTTPSocket)
	if err != nil {
		return 0, fmt.Errorf("listen on outer HTTP proxy socket: %w", err)
	}

	defer func() { _ = httpListener.Close() }()

	socksListener, err := listenConfig.Listen(ctx, "unix", runtimeSession.SOCKSocket)
	if err != nil {
		return 0, fmt.Errorf("listen on outer SOCKS proxy socket: %w", err)
	}
	defer func() { _ = socksListener.Close() }()

	logger.Log(logging.Debug, "session dir %s", runtimeSession.Directory)
	logger.Log(logging.Debug, "HTTP proxy listening inside network namespace at %s", namespace.HTTPAddress)
	logger.Log(logging.Debug, "SOCKS proxy listening inside network namespace at %s", namespace.SOCKAddress)

	router, err := outbound.NewEnvironmentRouter(os.Environ())
	if err != nil {
		return 0, err
	}

	connector := outbound.NewRouted(networkPolicy, nil, router.Dial)
	connector.LogDecisions(func(allowed bool, hostname string, address netip.Addr, port uint16) {
		decision := "block"
		if allowed {
			decision = "allow"
		}

		target := hostname
		if target == "" {
			target = address.String()
		}

		logger.Log(logging.Debug, "%s tcp %s:%d -> %s", decision, target, port, address)
	})
	httpServer := proxyhttp.New(connector)

	socksServer, err := proxysocks.New(connector)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverErrors := make(chan error, 2)

	var waitGroup sync.WaitGroup

	waitGroup.Add(2)
	go func() {
		defer waitGroup.Done()

		serverErrors <- httpServer.Serve(ctx, httpListener)
	}()
	go func() {
		defer waitGroup.Done()

		serverErrors <- socksServer.Serve(ctx, socksListener)
	}()

	type commandResult struct {
		exitCode int
		err      error
	}

	commandResults := make(chan commandResult, 1)

	go func() {
		exitCode, runErr := namespace.Run(ctx, namespace.ParentOptions{
			Executable:  executable,
			Command:     command,
			Environment: environment,
			Directory:   workingDirectory,
			HTTPSocket:  runtimeSession.HTTPSocket,
			SOCKSocket:  runtimeSession.SOCKSocket,
			Mode:        namespaceMode,
		})
		commandResults <- commandResult{exitCode: exitCode, err: runErr}
	}()

	var result commandResult
	select {
	case result = <-commandResults:
		cancel()
	case serverErr := <-serverErrors:
		if serverErr == nil {
			serverErr = fmt.Errorf("outer proxy server stopped unexpectedly")
		}

		cancel()

		result = <-commandResults
		if result.err == nil {
			result.err = serverErr
		}
	}

	cancel()
	waitGroup.Wait()

	if result.err != nil {
		return 0, result.err
	}

	return result.exitCode, nil
}

func logSupplementaryGroupLimitation(logger *logging.Logger) {
	groups, err := os.Getgroups()
	if err != nil {
		logger.Log(logging.Warning, "warning: inspect supplementary groups: %v", err)

		return
	}

	primaryGroup := os.Getgid()
	for _, group := range groups {
		if group != primaryGroup {
			logger.Log(logging.Warning, "warning: supplementary groups cannot be preserved by the rootless single-GID mapping")

			return
		}
	}
}

func childEnvironment(original []string, proxyMode bool) []string {
	proxyNames := []string{
		"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "GRPC_PROXY", "FTP_PROXY", "NO_PROXY",
		"http_proxy", "https_proxy", "all_proxy", "grpc_proxy", "ftp_proxy", "no_proxy",
	}

	environment := make([]string, 0, len(original)+len(proxyNames))
	for _, entry := range original {
		name, _, found := strings.Cut(entry, "=")
		if found && slices.Contains(proxyNames, name) {
			continue
		}

		environment = append(environment, entry)
	}

	if !proxyMode {
		return environment
	}

	return append(environment,
		"HTTP_PROXY=http://"+namespace.HTTPAddress,
		"HTTPS_PROXY=http://"+namespace.HTTPAddress,
		"ALL_PROXY=http://"+namespace.HTTPAddress,
		"GRPC_PROXY=http://"+namespace.HTTPAddress,
		"FTP_PROXY=socks5h://"+namespace.SOCKAddress,
		"http_proxy=http://"+namespace.HTTPAddress,
		"https_proxy=http://"+namespace.HTTPAddress,
		"all_proxy=http://"+namespace.HTTPAddress,
		"grpc_proxy=http://"+namespace.HTTPAddress,
		"ftp_proxy=socks5h://"+namespace.SOCKAddress,
		"NO_PROXY=",
		"no_proxy=",
	)
}
