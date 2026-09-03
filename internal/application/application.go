// Package application wires airjail's policy, proxies, namespace, and command supervision.
package application

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/namespace"
	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/proxydns"
	"github.com/erikgeiser/airjail/internal/proxyhttp"
	"github.com/erikgeiser/airjail/internal/proxysocks"
)

// Run executes one public airjail invocation.
func Run(ctx context.Context, args []string, version string) (int, error) {
	invocation, err := cli.Parse(args)
	if err != nil {
		return 0, err
	}

	if invocation.Help {
		cli.WriteHelp(os.Stdout)

		return 0, nil
	}

	if invocation.Version {
		_, _ = fmt.Fprintf(os.Stdout, "airjail %s\n", version)

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

	if namespaceMode == namespace.PermissionPreservingMode {
		// make airjail non-dumpable in rootless mode in order to prevent the
		// child process from tracing airjail and meassing with the rules.
		err = namespace.SetNonDumpable()
		if err != nil {
			return 0, err
		}
	}

	if namespaceMode == namespace.RootlessMode {
		logger.Infof("using rootless user and network namespaces")
		logSupplementaryGroupLimitation(logger)
	} else {
		logger.Infof("using permission-preserving network namespace")
	}

	networkPolicy, err := policy.New(ctx, invocation.Config.Allow, invocation.Config.Block, policy.Options{
		AllowUnresolved: invocation.Config.AllowUnresolvedRules,
		Logger:          logger,
	})
	if err != nil {
		return 0, err
	}

	environment := childEnvironment(os.Environ(), !networkPolicy.Empty())
	if networkPolicy.Empty() {
		logger.Infof("empty policy: starting child in loopback-only namespace without proxies")

		return namespace.Run(ctx, namespace.ParentOptions{
			Executable:             executable,
			Command:                invocation.Command,
			Environment:            environment,
			Directory:              workingDirectory,
			Mode:                   namespaceMode,
			RestrictUnixSockets:    invocation.Config.RestrictUnixSockets,
			KeepUnsafeCapabilities: invocation.Config.KeepUnsafeCapabilities,
			Logger:                 logger,
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
		invocation.Config.RestrictUnixSockets,
		invocation.Config.KeepUnsafeCapabilities,
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
	restrictUnixSockets bool,
	keepUnsafeCapabilities []string,
	logger *logging.Logger,
) (int, error) {
	runDir, err := createRuntimeDir(os.Getuid(), os.Getenv("XDG_RUNTIME_DIR"))
	if err != nil {
		return 0, err
	}

	logger.Debugf("created network sockets in session directory %s", runDir.Directory)

	defer func() {
		closeErr := runDir.Close()
		if closeErr != nil {
			logger.Warnf("%v", closeErr)
		} else {
			logger.Debugf("cleaned up session directory %s", runDir.Directory)
		}
	}()

	listenConfig := net.ListenConfig{}

	httpListener, err := listenConfig.Listen(ctx, "unix", runDir.HTTPSocket)
	if err != nil {
		return 0, fmt.Errorf("listen on outer HTTP proxy socket: %w", err)
	}

	defer func() {
		err := httpListener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Warnf("could not close HTTP listener: %v", err)
		} else {
			logger.Debugf("closed HTTP listener")
		}
	}()

	socksListener, err := listenConfig.Listen(ctx, "unix", runDir.SOCKSocket)
	if err != nil {
		return 0, fmt.Errorf("listen on outer SOCKS proxy socket: %w", err)
	}
	defer func() {
		err := socksListener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Warnf("could not close SOCKS listener: %v", err)
		} else {
			logger.Debugf("closed SOCKS listener")
		}
	}()

	dnsListener, err := listenConfig.Listen(ctx, "unix", runDir.DNSSocket)
	if err != nil {
		return 0, fmt.Errorf("listen on outer DNS proxy socket: %w", err)
	}
	defer func() {
		err := dnsListener.Close()
		if err != nil && !errors.Is(err, net.ErrClosed) {
			logger.Warnf("could not close DNS listener: %v", err)
		} else {
			logger.Debugf("closed DNS listener")
		}
	}()

	logger.Debugf("session dir %s", runDir.Directory)
	logger.Debugf("HTTP proxy listening inside network namespace at %s", namespace.HTTPAddress)
	logger.Debugf("SOCKS proxy listening inside network namespace at %s", namespace.SOCKAddress)

	router, err := outbound.NewEnvironmentRouter(os.Environ())
	if err != nil {
		return 0, err
	}

	connector := outbound.NewRouted(networkPolicy, nil, router.Dial, logger)
	httpServer := proxyhttp.New(connector)

	socksServer, err := proxysocks.New(connector)
	if err != nil {
		return 0, err
	}

	dnsUpstream, err := proxydns.NewSystemUpstream("/etc/resolv.conf")
	if err != nil {
		return 0, err
	}

	dnsServer, err := proxydns.New(networkPolicy, dnsUpstream, logger)
	if err != nil {
		return 0, err
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	serverErrors := make(chan error, 3)

	var waitGroup sync.WaitGroup

	waitGroup.Go(func() {
		serverErrors <- httpServer.Serve(ctx, httpListener)
	})
	waitGroup.Go(func() {
		serverErrors <- socksServer.Serve(ctx, socksListener)
	})
	waitGroup.Go(func() {
		serverErrors <- dnsServer.Serve(ctx, dnsListener)
	})

	type commandResult struct {
		exitCode int
		err      error
	}

	commandResults := make(chan commandResult, 1)

	go func() {
		exitCode, runErr := namespace.Run(ctx, namespace.ParentOptions{
			Executable:             executable,
			Command:                command,
			Environment:            environment,
			Directory:              workingDirectory,
			HTTPSocket:             runDir.HTTPSocket,
			SOCKSocket:             runDir.SOCKSocket,
			DNSSocket:              runDir.DNSSocket,
			Mode:                   namespaceMode,
			RestrictUnixSockets:    restrictUnixSockets,
			KeepUnsafeCapabilities: keepUnsafeCapabilities,
			TransparentTCP:         true,
			Logger:                 logger,
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
		logger.Warnf("inspect supplementary groups: %v", err)

		return
	}

	var (
		primaryGroup               = os.Getgid()
		supplementaryGroups        = make([]string, 0, max(0, len(groups)-1))
		supplementaryGroupsPresent = false
	)

	for _, group := range groups {
		if group == primaryGroup {
			continue
		}

		supplementaryGroupsPresent = true

		g, err := user.LookupGroupId(strconv.Itoa(group))
		if err != nil {
			supplementaryGroups = append(supplementaryGroups, strconv.Itoa(group))
		} else {
			supplementaryGroups = append(supplementaryGroups, g.Name)
		}
	}

	if !supplementaryGroupsPresent {
		return
	}

	logger.Infof(
		"supplementary groups (%s) cannot be preserved by the rootless single-GID mapping",
		strings.Join(supplementaryGroups, ", "))
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
		"ALL_PROXY=socks5h://"+namespace.SOCKAddress,
		"GRPC_PROXY=http://"+namespace.HTTPAddress,
		"FTP_PROXY=socks5h://"+namespace.SOCKAddress,
		"http_proxy=http://"+namespace.HTTPAddress,
		"https_proxy=http://"+namespace.HTTPAddress,
		"all_proxy=socks5h://"+namespace.SOCKAddress,
		"grpc_proxy=http://"+namespace.HTTPAddress,
		"ftp_proxy=socks5h://"+namespace.SOCKAddress,
		"NO_PROXY=",
		"no_proxy=",
	)
}
