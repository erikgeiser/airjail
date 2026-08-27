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
	logger.Warnf("connection closed")

	want := "airjail: info: started service\nairjail: warning: connection closed\n"
	if output.String() != want {
		t.Errorf("output = %q, want %q", output.String(), want)
	}
}

func TestNilLoggerIsNoOp(t *testing.T) {
	t.Parallel()

	var logger *Logger

	logger.Debugf("debug")
	logger.Infof("info")
	logger.Warnf("warning")
	logger.WithPrefix("child").Warnf("prefixed warning")

	if logger.LevelName() != "silent" {
		t.Errorf("nil logger level = %q, want silent", logger.LevelName())
	}
}

func TestLoggerColorsInfoBlue(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	logger, err := New(&output, "info", "")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	logger.Colored = true
	logger.Infof("message")

	if !strings.HasPrefix(output.String(), "\033[34mairjail: info: message") {
		t.Errorf("colored info output = %q, want blue prefix", output.String())
	}
}
