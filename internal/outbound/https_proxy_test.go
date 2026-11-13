//nolint:goconst // Proxy authorities are repeated across subprocess boundaries.
package outbound

import (
	"crypto/tls"
	"encoding/pem"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestHTTPSProxyCertificateVerification(t *testing.T) {
	t.Parallel()

	//nolint:nestif // Isolated client connection and certificate checks.
	if proxyURL := os.Getenv("AIRJAIL_TEST_HTTPS_PROXY"); proxyURL != "" {
		router, err := NewProxyAwareRouter(nil, proxyURL, defaultConnectTimeout)
		if err != nil {
			t.Fatalf("create router: %v", err)
		}

		connection, err := router.Dial(t.Context(), "service.example", netip.MustParseAddr("192.0.2.10"), 443)
		if connection != nil {
			t.Cleanup(func() { _ = connection.Close() })
		}

		if os.Getenv("AIRJAIL_TEST_TLS_FAILURE") == "true" {
			if _, ok := errors.AsType[*tls.CertificateVerificationError](err); !ok {
				t.Fatalf("invalid proxy certificate: got %v, want certificate verification error", err)
			}

			return
		}

		if err != nil {
			t.Fatalf("connect through trusted IP proxy: %v", err)
		}

		payload := make([]byte, 5)

		_, err = io.ReadFull(connection, payload)
		if err != nil || string(payload) != "hello" {
			t.Fatalf("tunnel payload = %q, %v", payload, err)
		}

		return
	}

	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "192.0.2.10:443" {
			t.Errorf("unexpected proxy request: %s %s", request.Method, request.Host)
			http.Error(writer, "unexpected target", http.StatusBadRequest)

			return
		}

		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("proxy does not support hijacking")

			return
		}

		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack proxy connection: %v", err)

			return
		}
		defer func() { _ = connection.Close() }()

		_, _ = io.WriteString(connection, "HTTP/1.1 200 Connection Established\r\n\r\nhello")
	}))
	proxy.Config.ErrorLog = log.New(io.Discard, "", 0)
	proxy.StartTLS()
	t.Cleanup(proxy.Close)

	for _, test := range []struct {
		name    string
		trusted bool
		url     string
		reject  bool
	}{
		{name: "trusted IP", trusted: true, url: proxy.URL},
		{name: "untrusted IP", url: proxy.URL, reject: true},
		{name: "wrong identity", trusted: true, url: strings.Replace(proxy.URL, "127.0.0.1", "localhost", 1), reject: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()

			rootsPath := filepath.Join(directory, "roots.pem")
			if test.trusted {
				err := os.WriteFile(rootsPath, pem.EncodeToMemory(&pem.Block{
					Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw,
				}), 0o600)
				if err != nil {
					t.Fatalf("write trusted roots: %v", err)
				}
			}

			// System certificate roots are cached, so each trust case needs a fresh process.
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHTTPSProxyCertificateVerification$")

			command.Env = append(os.Environ(), "AIRJAIL_TEST_HTTPS_PROXY="+test.url,
				"AIRJAIL_TEST_TLS_FAILURE="+strconv.FormatBool(test.reject),
				"SSL_CERT_FILE="+rootsPath, "SSL_CERT_DIR="+directory)

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("HTTPS proxy subprocess: %v\n%s", err, output)
			}
		})
	}
}
