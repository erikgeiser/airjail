// Package proxyhttp implements airjail's child-facing HTTP forward proxy.
package proxyhttp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"strconv"
	"sync"
	"time"

	"github.com/erikgeiser/airjail/internal/outbound"
	"github.com/erikgeiser/airjail/internal/policy"
	"github.com/erikgeiser/airjail/internal/stream"
)

const (
	readHeaderTimeout = 10 * time.Second
	maxHeaderBytes    = 16 * 1024
)

// Connector establishes a policy-checked destination connection.
type Connector interface {
	Dial(ctx context.Context, destination policy.Destination, port uint16) (net.Conn, error)
}

// Server is an HTTP forward proxy.
type Server struct {
	connector  Connector
	operations *stream.ConnGroup
}

// New creates an HTTP forward proxy.
func New(connector Connector) *Server {
	return &Server{
		connector:  connector,
		operations: stream.NewConnGroup(),
	}
}

// Serve handles requests on listener until ctx is canceled.
func (server *Server) Serve(ctx context.Context, listener net.Listener) error {
	httpServer := &http.Server{
		Handler:           server,
		ReadHeaderTimeout: readHeaderTimeout,
		MaxHeaderBytes:    maxHeaderBytes,
	}

	serveResult := make(chan error, 1)
	go func() {
		serveResult <- httpServer.Serve(listener)
	}()

	select {
	case err := <-serveResult:
		server.operations.Close()

		closeErr := httpServer.Close()

		server.operations.Wait()

		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return fmt.Errorf("close HTTP proxy after serve stopped: %w", closeErr)
		}

		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}

		return fmt.Errorf("serve HTTP proxy: %w", err)
	case <-ctx.Done():
		server.operations.Close()

		closeErr := httpServer.Close()
		err := <-serveResult

		server.operations.Wait()

		if closeErr != nil && !errors.Is(closeErr, net.ErrClosed) {
			return fmt.Errorf("close HTTP proxy: %w", closeErr)
		}

		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
			return fmt.Errorf("serve HTTP proxy during shutdown: %w", err)
		}

		return nil
	}
}

// ServeHTTP handles CONNECT and absolute-form HTTP requests.
func (server *Server) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	operation, ok := server.operations.Acquire()
	if !ok {
		http.Error(response, "proxy is shutting down", http.StatusServiceUnavailable)

		return
	}
	defer operation.Done()

	if request.Method == http.MethodConnect {
		server.serveConnect(response, request, operation)

		return
	}

	server.servePlainHTTP(response, request, operation)
}

func (server *Server) serveConnect(
	response http.ResponseWriter,
	request *http.Request,
	operation *stream.ConnScope,
) {
	destination, port, err := parseAuthority(request.Host)
	if err != nil {
		http.Error(response, "malformed CONNECT target", http.StatusBadRequest)

		return
	}

	upstream, err := server.connector.Dial(request.Context(), destination, port)
	if err != nil {
		writeDialError(response, err)

		return
	}

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		_ = upstream.Close()

		http.Error(response, "connection hijacking unavailable", http.StatusInternalServerError)

		return
	}

	client, buffered, err := hijacker.Hijack()
	if err != nil {
		_ = upstream.Close()

		return
	}

	defer func() { _ = client.Close() }()
	defer func() { _ = upstream.Close() }()

	if !operation.Add(client) || !operation.Add(upstream) {
		return
	}

	_, err = buffered.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err != nil {
		return
	}

	err = buffered.Flush()
	if err != nil {
		return
	}

	_ = stream.Bidirectional(request.Context(), client, buffered.Reader, upstream)
}

func (server *Server) servePlainHTTP(
	response http.ResponseWriter,
	request *http.Request,
	operation *stream.ConnScope,
) {
	if !request.URL.IsAbs() || request.URL.Scheme != "http" || request.URL.Host == "" || request.URL.User != nil {
		http.Error(response, "absolute-form http URL required", http.StatusBadRequest)

		return
	}

	destination, port, err := parseURLAuthority(request.URL.Hostname(), request.URL.Port(), 80)
	if err != nil {
		http.Error(response, "malformed HTTP target", http.StatusBadRequest)

		return
	}

	upstream, err := server.connector.Dial(request.Context(), destination, port)
	if err != nil {
		writeDialError(response, err)

		return
	}
	defer func() { _ = upstream.Close() }()

	if !operation.Add(upstream) {
		return
	}

	authority := canonicalAuthority(destination, port, request.URL.Port() != "")

	transport := &http.Transport{
		DisableKeepAlives:      true,
		DialContext:            oneConnectionDialer(upstream),
		MaxResponseHeaderBytes: maxHeaderBytes,
		ResponseHeaderTimeout:  readHeaderTimeout,
	}
	defer transport.CloseIdleConnections()

	reverseProxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(proxyRequest *httputil.ProxyRequest) {
			proxyRequest.Out.URL.Scheme = "http"
			proxyRequest.Out.URL.Host = authority
			proxyRequest.Out.Host = authority
		},
		ErrorHandler: func(writer http.ResponseWriter, _ *http.Request, _ error) {
			http.Error(writer, "upstream request failed", http.StatusBadGateway)
		},
	}
	reverseProxy.ServeHTTP(response, request)
}

func parseAuthority(authority string) (policy.Destination, uint16, error) {
	host, rawPort, err := net.SplitHostPort(authority)
	if err != nil {
		return policy.Destination{}, 0, fmt.Errorf("split authority: %w", err)
	}

	return parseURLAuthority(host, rawPort, 0)
}

func parseURLAuthority(host, rawPort string, defaultPort uint16) (policy.Destination, uint16, error) {
	if host == "" {
		return policy.Destination{}, 0, fmt.Errorf("host is empty")
	}

	port := defaultPort

	if rawPort != "" {
		parsedPort, err := strconv.ParseUint(rawPort, 10, 16)
		if err != nil || parsedPort == 0 {
			return policy.Destination{}, 0, fmt.Errorf("port must be from 1 through 65535")
		}

		port = uint16(parsedPort)
	}

	if port == 0 {
		return policy.Destination{}, 0, fmt.Errorf("port is required")
	}

	destination, err := policy.ParseDestination(host)
	if err != nil {
		return policy.Destination{}, 0, fmt.Errorf("parse destination: %w", err)
	}

	return destination, port, nil
}

func canonicalAuthority(destination policy.Destination, port uint16, includePort bool) string {
	host := destination.Hostname()
	if !destination.IsHostname() {
		host = destination.RoutingAddress().String()
		if destination.Address().Is6() && !includePort {
			return "[" + host + "]"
		}
	}

	if includePort {
		return net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	return host
}

func oneConnectionDialer(connection net.Conn) func(context.Context, string, string) (net.Conn, error) {
	var mutex sync.Mutex

	used := false

	return func(_ context.Context, _, _ string) (net.Conn, error) {
		mutex.Lock()
		defer mutex.Unlock()

		if used {
			return nil, fmt.Errorf("prepared connection already used")
		}

		used = true

		return connection, nil
	}
}

func writeDialError(response http.ResponseWriter, err error) {
	if errors.Is(err, outbound.ErrDenied) {
		http.Error(response, "destination denied by policy", http.StatusForbidden)

		return
	}

	http.Error(response, "destination connection failed", http.StatusBadGateway)
}
