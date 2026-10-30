package outbound

import (
	"crypto/x509"
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
	"strings"
	"testing"
)

const httpsProxyTestURL = "AIRJAIL_HTTPS_PROXY_TEST_URL"

func TestHTTPSProxyCertificateVerification(t *testing.T) {
	t.Parallel()

	proxy := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodConnect || request.Host != "192.0.2.10:443" {
			t.Errorf("unexpected proxy request: %s %s", request.Method, request.Host)
			http.Error(writer, "unexpected target", http.StatusBadRequest)

			return
		}

		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Error("proxy response writer does not support hijacking")

			return
		}

		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Errorf("hijack CONNECT: %v", err)

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
	}{
		{name: "trusted IP", trusted: true, url: proxy.URL},
		{name: "untrusted IP", url: proxy.URL},
		{name: "mismatched name", trusted: true, url: strings.Replace(proxy.URL, "127.0.0.1", "localhost", 1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			directory := t.TempDir()
			certificatePath := filepath.Join(directory, "roots.pem")
			certificate := []byte{}

			if test.trusted {
				certificate = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: proxy.Certificate().Raw})
			}

			err := os.WriteFile(certificatePath, certificate, 0o600)
			if err != nil {
				t.Fatalf("write test roots: %v", err)
			}

			// A fresh process avoids the standard library's cached system roots.
			command := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHTTPSProxyProcess$")

			command.Env = append(os.Environ(),
				httpsProxyTestURL+"="+test.url,
				"AIRJAIL_HTTPS_PROXY_TEST_CASE="+test.name,
				"SSL_CERT_FILE="+certificatePath,
				"SSL_CERT_DIR="+directory,
			)

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("HTTPS proxy subprocess: %v\n%s", err, output)
			}
		})
	}
}

func TestHTTPSProxyProcess(t *testing.T) {
	proxyURL := os.Getenv(httpsProxyTestURL)
	if proxyURL == "" {
		return
	}

	router, err := NewProxyAwareRouter(nil, proxyURL, defaultConnectTimeout)
	if err != nil {
		t.Fatalf("NewProxyAwareRouter: %v", err)
	}

	connection, err := router.Dial(t.Context(), "service.example", netip.MustParseAddr("192.0.2.10"), 443)
	if connection != nil {
		defer func() { _ = connection.Close() }()
	}

	switch os.Getenv("AIRJAIL_HTTPS_PROXY_TEST_CASE") {
	case "untrusted IP":
		var certificateError x509.UnknownAuthorityError
		if !errors.As(err, &certificateError) {
			t.Fatalf("Dial error = %v, want unknown certificate authority", err)
		}
	case "mismatched name":
		var certificateError x509.HostnameError
		if !errors.As(err, &certificateError) {
			t.Fatalf("Dial error = %v, want certificate hostname mismatch", err)
		}
	case "trusted IP":
		if err != nil {
			t.Fatalf("Dial: %v", err)
		}

		payload := make([]byte, 5)

		_, err = io.ReadFull(connection, payload)
		if err != nil || string(payload) != "hello" {
			t.Fatalf("read tunnel payload = %q, %v, want hello", payload, err)
		}
	default:
		t.Fatal("unexpected HTTPS proxy test case")
	}
}
