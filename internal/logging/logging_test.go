package logging

import (
	"bytes"
	"strings"
	"testing"
)

func TestLoggerLevelHierarchyAndFormatting(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger, err := New(&output, "info", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Debugf("hidden")
	logger.Infof("started %s", "service")
	logger.Allowf("tcp example.com:443")
	logger.Warnf("connection closed")

	want := "airjail: info: started service\n" +
		"airjail: allowed: tcp example.com:443\n" +
		"airjail: warning: connection closed\n"
	if output.String() != want {
		t.Errorf("output = %q, want %q", output.String(), want)
	}
}

func TestTrafficLevelHierarchy(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger, err := New(&output, "traffic", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Debugf("hidden debug")
	logger.Infof("hidden info")
	logger.Allowf("tcp allowed.example:443")
	logger.Blockf("tcp blocked.example:80")
	logger.Warnf("visible warning")

	want := "airjail: allowed: tcp allowed.example:443\n" +
		"airjail: blocked: tcp blocked.example:80\n" +
		"airjail: warning: visible warning\n"
	if output.String() != want {
		t.Errorf("output = %q, want %q", output.String(), want)
	}
}

func TestNilLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	var logger *Logger

	logger.Debugf("debug")
	logger.Infof("info")
	logger.Allowf("allow")
	logger.Blockf("block")
	logger.Warnf("warning")
	logger.WithPrefix("child").Warnf("prefixed warning")

	if logger.LevelName() != "silent" {
		t.Errorf("nil logger level = %q, want silent", logger.LevelName())
	}
}

func TestLoggerColors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		log        func(*Logger)
		wantPrefix string
	}{
		{name: "allow green", log: func(logger *Logger) { logger.Allowf("message") }, wantPrefix: "\033[32m"},
		{name: "block red", log: func(logger *Logger) { logger.Blockf("message") }, wantPrefix: "\033[31m"},
		{name: "info cyan", log: func(logger *Logger) { logger.Infof("message") }, wantPrefix: "\033[36m"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			var output bytes.Buffer

			logger, err := New(&output, "info", "")
			if err != nil {
				t.Fatalf("New: %v", err)
			}

			logger.Colored = true
			test.log(logger)

			if !strings.HasPrefix(output.String(), test.wantPrefix) {
				t.Errorf("colored output = %q, want prefix %q", output.String(), test.wantPrefix)
			}
		})
	}
}
