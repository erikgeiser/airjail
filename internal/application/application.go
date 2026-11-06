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

	"github.com/erikgeiser/airjail/internal/cli"
	"github.com/erikgeiser/airjail/internal/config"
	"github.com/erikgeiser/airjail/internal/logging"
	"github.com/erikgeiser/airjail/internal/namespace"
	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/proxydns"
	"github.com/erikgeiser/airjail/internal/proxyhttp"
	"github.com/erikgeiser/airjail/internal/proxysocks"
	"golang.org/x/sync/errgroup"
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

	requiresResolver, err := policy.RulesRequireResolver(
		invocation.Config.Allow,
		invocation.Config.Block,
		invocation.Config.AllowArbitraryDNS,
	)
	if err != nil {
		return 0, err
	}

	var dnsResolver *proxydns.Resolver

	if requiresResolver {
		dnsUpstream, upstreamErr := proxydns.NewSystemUpstream("/etc/resolv.conf")
		if upstreamErr != nil {
			return 0, upstreamErr
		}

		dnsResolver, err = proxydns.NewResolver(dnsUpstream)
		if err != nil {
			return 0, err
		}
	}

	policyOptions := policy.Options{
		AllowUnresolved:   invocation.Config.AllowUnresolvedRules,
		AllowArbitraryDNS: invocation.Config.AllowArbitraryDNS,
		Logger:            logger,
	}
	if dnsResolver != nil {
		policyOptions.Resolver = dnsResolver
		policyOptions.ChainResolver = dnsResolver
	}

	networkPolicy, err := policy.New(ctx, invocation.Config.Allow, invocation.Config.Block, policyOptions)
	if err != nil {
		return 0, err
	}

	child := namespace.ParentOptions{
		Executable:             executable,
		Command:                invocation.Command,
		Environment:            childEnvironment(os.Environ(), !networkPolicy.Empty(), invocation.Config.PrivateLoopback),
		Directory:              workingDirectory,
		Mode:                   namespaceMode,
		AllowSockets:           invocation.Config.AllowSockets,
		AllowAllSockets:        invocation.Config.AllowAllSockets,
		AllowVSocks:            invocation.Config.AllowVSocks,
		KeepUnsafeCapabilities: invocation.Config.KeepUnsafeCapabilities,
		PrivateLoopback:        invocation.Config.PrivateLoopback,
		Logger:                 logger,
	}

	if invocation.Config.AllowArbitraryDNS {
		logger.Infof("arbitrary DNS resolution enabled")
	}

	if networkPolicy.Empty() {
		logger.Infof("empty policy: starting child in loopback-only namespace without proxies")

		return namespace.Run(ctx, child)
	}

	return runWithProxies(ctx, invocation.Config, child, networkPolicy, dnsResolver)
}

func runWithProxies(
	ctx context.Context,
	configuration config.Config,
	child namespace.ParentOptions,
	networkPolicy *policy.Policy,
	dnsResolver *proxydns.Resolver,
) (int, error) {
	logger := child.Logger
	if !configuration.TransparentFallback {
		logger.Infof("transparent fallback disabled: only proxy-aware applications can use network egress")
	}

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

	child.HTTPSocket = runDir.HTTPSocket
	child.SOCKSocket = runDir.SOCKSocket
	child.DNSSocket = ""
	child.TransparentTCP = configuration.TransparentFallback

	listeners := make([]net.Listener, 0, 3)
	defer func() {
		for _, listener := range listeners {
			err := listener.Close()
			if err != nil && !errors.Is(err, net.ErrClosed) {
				logger.Warnf("close proxy listener %s: %v", listener.Addr(), err)
			} else {
				logger.Debugf("closed proxy listener %s", listener.Addr())
			}
		}
	}()

	listen := func(name, path string) (net.Listener, error) {
		listener, err := (&net.ListenConfig{}).Listen(ctx, "unix", path)
		if err != nil {
			return nil, fmt.Errorf("listen on outer %s proxy socket: %w", name, err)
		}

		listeners = append(listeners, listener)

		logger.Debugf("%s proxy listening on %s", name, path)

		return listener, nil
	}

	httpListener, err := listen("HTTP", child.HTTPSocket)
	if err != nil {
		return 0, err
	}

	socksListener, err := listen("SOCKS", child.SOCKSocket)
	if err != nil {
		return 0, err
	}

	var dnsListener net.Listener

	if child.TransparentTCP {
		child.DNSSocket = runDir.DNSSocket

		dnsListener, err = listen("DNS", child.DNSSocket)
		if err != nil {
			return 0, err
		}
	}

	router, err := outbound.NewProxyAwareRouter(os.Environ(), configuration.Proxy, configuration.ConnectTimeout)
	if err != nil {
		return 0, err
	}

	connector := outbound.NewRouted(networkPolicy, dnsResolver, router.Dial, logger)
	httpServer := proxyhttp.New(connector.WithLoggerPrefix("HTTP proxy"))

	socksServer, err := proxysocks.New(connector.WithLoggerPrefix("SOCKS proxy"), configuration.ConnectTimeout)
	if err != nil {
		return 0, err
	}

	var dnsServer *proxydns.Server

	if child.TransparentTCP {
		dnsServer, err = proxydns.NewWithResolver(
			networkPolicy,
			dnsResolver,
			child.PrivateLoopback,
			logger.WithPrefix("DNS proxy"),
		)
		if err != nil {
			return 0, err
		}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	group, groupCtx := errgroup.WithContext(ctx)

	runServer := func(
		name string,
		listener net.Listener,
		serve func(context.Context, net.Listener) error,
	) func() error {
		return func() error {
			err := serve(groupCtx, listener)
			if err != nil {
				return err
			}

			if groupCtx.Err() == nil {
				return fmt.Errorf("%s proxy server stopped unexpectedly", name)
			}

			return nil
		}
	}

	group.Go(runServer("HTTP", httpListener, httpServer.Serve))
	group.Go(runServer("SOCKS", socksListener, socksServer.Serve))

	if child.TransparentTCP {
		group.Go(runServer("DNS", dnsListener, dnsServer.Serve))
	}

	var (
		childExitCode int
		childErr      error
	)

	group.Go(func() error {
		defer cancel()

		childExitCode, childErr = namespace.Run(groupCtx, child)

		return nil
	})

	serverErr := group.Wait()

	if childErr != nil {
		return 0, childErr
	}

	if serverErr != nil {
		return 0, serverErr
	}

	return childExitCode, nil
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

func childEnvironment(original []string, proxyMode, privateLoopback bool) []string {
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

	noProxy := ""
	if privateLoopback {
		noProxy = "localhost,.localhost,127.0.0.1,127.0.0.0/8,::1"
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
		"NO_PROXY="+noProxy,
		"no_proxy="+noProxy,
	)
}
