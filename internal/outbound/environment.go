package outbound

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/http/httpproxy"
	xproxy "golang.org/x/net/proxy"
)

const (
	connectTimeout       = 30 * time.Second
	maxConnectHeaderSize = 16 * 1024
	proxyHTTPScheme      = "https"
)

// EnvironmentRouter routes approved addresses according to the outer proxy environment.
type EnvironmentRouter struct {
	proxyURL *url.URL
	bypass   func(*url.URL) (*url.URL, error)
	dialer   net.Dialer
}

// NewEnvironmentRouter snapshots HTTP(S)/ALL_PROXY and NO_PROXY from environment.
func NewEnvironmentRouter(environment []string) (*EnvironmentRouter, error) {
	values := environmentMap(environment)
	proxyValue := firstEnvironment(
		values,
		"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy",
	)

	proxyURL, err := parseProxyURL(proxyValue)
	if err != nil {
		return nil, err
	}

	noProxy := firstEnvironment(values, "NO_PROXY", "no_proxy")
	bypassConfig := &httpproxy.Config{
		HTTPProxy:  "http://airjail-proxy-selection.invalid",
		HTTPSProxy: "http://airjail-proxy-selection.invalid",
		NoProxy:    noProxy,
	}

	return &EnvironmentRouter{
		proxyURL: proxyURL,
		bypass:   bypassConfig.ProxyFunc(),
		dialer:   net.Dialer{Timeout: connectTimeout},
	}, nil
}

// Dial connects directly or through the configured outer proxy.
func (router *EnvironmentRouter) Dial(
	ctx context.Context,
	hostname string,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	destinationHost := hostname
	if destinationHost == "" {
		destinationHost = address.String()
	}

	destinationURL := &url.URL{
		Scheme: proxyHTTPScheme,
		Host:   net.JoinHostPort(destinationHost, strconv.Itoa(int(port))),
	}

	selected, err := router.bypass(destinationURL)
	if err != nil {
		return nil, fmt.Errorf("evaluate NO_PROXY for %s: %w", destinationURL.Host, err)
	}

	if router.proxyURL == nil || selected == nil {
		return router.dialer.DialContext(
			ctx,
			"tcp",
			net.JoinHostPort(address.String(), strconv.Itoa(int(port))),
		)
	}

	proxyURL := router.proxyURL
	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https":
		return router.dialHTTPProxy(ctx, proxyURL, address, port)
	case "socks5", "socks5h":
		return router.dialSOCKSProxy(ctx, proxyURL, address, port)
	default:
		return nil, fmt.Errorf("outer proxy scheme %q is unsupported", proxyURL.Scheme)
	}
}

func (router *EnvironmentRouter) dialSOCKSProxy(
	ctx context.Context,
	proxyURL *url.URL,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	proxyDialer, err := xproxy.FromURL(proxyURL, &router.dialer)
	if err != nil {
		return nil, fmt.Errorf("configure outer SOCKS proxy: %w", err)
	}

	target := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))

	contextDialer, ok := proxyDialer.(xproxy.ContextDialer)
	if !ok {
		return nil, fmt.Errorf("configure outer SOCKS proxy: dialer does not support context cancellation")
	}

	connection, dialErr := contextDialer.DialContext(ctx, "tcp", target)
	if dialErr != nil {
		return nil, fmt.Errorf("dial through outer SOCKS proxy: %w", dialErr)
	}

	return connection, nil
}

func (router *EnvironmentRouter) dialHTTPProxy(
	ctx context.Context,
	proxyURL *url.URL,
	address netip.Addr,
	port uint16,
) (net.Conn, error) {
	proxyHost := proxyURL.Hostname()

	proxyPort := proxyURL.Port()
	if proxyPort == "" {
		if strings.EqualFold(proxyURL.Scheme, proxyHTTPScheme) {
			proxyPort = "443"
		} else {
			proxyPort = "80"
		}
	}

	handshakeContext, cancel := context.WithTimeout(ctx, connectTimeout)
	defer cancel()

	connection, err := router.dialer.DialContext(
		handshakeContext,
		"tcp",
		net.JoinHostPort(proxyHost, proxyPort),
	)
	if err != nil {
		return nil, fmt.Errorf("dial outer HTTP proxy: %w", err)
	}

	keepConnection := false
	defer func() {
		if !keepConnection {
			_ = connection.Close()
		}
	}()

	deadline, hasDeadline := handshakeContext.Deadline()
	if hasDeadline {
		err = connection.SetDeadline(deadline)
		if err != nil {
			return nil, fmt.Errorf("set outer proxy CONNECT deadline: %w", err)
		}
	}

	if strings.EqualFold(proxyURL.Scheme, proxyHTTPScheme) {
		tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12}
		if net.ParseIP(proxyHost) == nil {
			tlsConfig.ServerName = proxyHost
		}

		tlsConnection := tls.Client(connection, tlsConfig)

		err = tlsConnection.HandshakeContext(handshakeContext)
		if err != nil {
			return nil, fmt.Errorf("negotiate TLS with outer HTTPS proxy: %w", err)
		}

		connection = tlsConnection
	}

	authority := net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
	request := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: authority},
		Host:   authority,
		Header: make(http.Header),
	}

	if proxyURL.User != nil {
		password, _ := proxyURL.User.Password()
		credentials := proxyURL.User.Username() + ":" + password
		request.Header.Set("Proxy-Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(credentials)))
	}

	err = request.Write(connection)
	if err != nil {
		return nil, fmt.Errorf("write outer proxy CONNECT request: %w", err)
	}

	header, err := readConnectHeader(connection)
	if err != nil {
		return nil, err
	}

	response, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(header)), request)
	if err != nil {
		return nil, fmt.Errorf("parse outer proxy CONNECT response: %w", err)
	}

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		_ = response.Body.Close()

		return nil, fmt.Errorf("outer proxy CONNECT returned %s", response.Status)
	}

	err = response.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("close outer proxy CONNECT response: %w", err)
	}

	err = connection.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("clear outer proxy CONNECT deadline: %w", err)
	}

	keepConnection = true

	return connection, nil
}

func readConnectHeader(reader io.Reader) ([]byte, error) {
	header := make([]byte, 0, 512)

	oneByte := []byte{0}
	for len(header) < maxConnectHeaderSize {
		read, err := reader.Read(oneByte)
		if err != nil {
			return nil, fmt.Errorf("read outer proxy CONNECT response: %w", err)
		}

		if read == 0 {
			continue
		}

		header = append(header, oneByte[0])
		if len(header) >= 4 && bytes.Equal(header[len(header)-4:], []byte("\r\n\r\n")) {
			return header, nil
		}
	}

	return nil, fmt.Errorf("outer proxy CONNECT response headers exceed %d bytes", maxConnectHeaderSize)
}

func parseProxyURL(rawURL string) (*url.URL, error) {
	if rawURL == "" {
		return nil, nil
	}

	if !strings.Contains(rawURL, "://") {
		rawURL = "http://" + rawURL
	}

	proxyURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("parse outer proxy URL: %w", err)
	}

	if proxyURL.Host == "" || proxyURL.Path != "" && proxyURL.Path != "/" ||
		proxyURL.RawQuery != "" || proxyURL.Fragment != "" {
		return nil, fmt.Errorf("parse outer proxy URL: proxy must contain only scheme, authority, and optional credentials")
	}

	switch strings.ToLower(proxyURL.Scheme) {
	case "http", "https", "socks5", "socks5h":
		return proxyURL, nil
	default:
		return nil, fmt.Errorf("outer proxy scheme %q is unsupported", proxyURL.Scheme)
	}
}

func environmentMap(environment []string) map[string]string {
	values := make(map[string]string, len(environment))
	for _, entry := range environment {
		name, value, found := strings.Cut(entry, "=")
		if found {
			values[name] = value
		}
	}

	return values
}

func firstEnvironment(values map[string]string, names ...string) string {
	for _, name := range names {
		if value := values[name]; value != "" {
			return value
		}
	}

	return ""
}
