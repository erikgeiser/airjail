// Package logging provides airjail's small human-readable stderr logger.
package logging

import (
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

type Level uint

const (
	Silent  Level = 0
	Warning Level = 1
	Info    Level = 2
	Debug   Level = 3
)

// Logger emits operational messages only when verbose mode is enabled.
type Logger struct {
	Colored bool
	Level   Level
	prefix  string
	writer  io.Writer
}

// New creates a logger.
func New(writer io.Writer, level string, prefix string) (*Logger, error) {
	l := &Logger{writer: writer, prefix: "airjail"}

	switch strings.ToLower(strings.TrimSpace(level)) {
	case "silent":
		l.Level = Silent
	case "warning":
		l.Level = Warning
	case "info":
		l.Level = Info
	case "debug":
		l.Level = Debug
	default:
		return nil, fmt.Errorf("invalid log level: %q", level)
	}

	f, ok := writer.(*os.File)
	if ok {
		l.Colored = term.IsTerminal(int(f.Fd()))
	}

	if prefix == "" {
		return l, nil
	}

	return l.WithPrefix(prefix), nil
}

func (logger *Logger) WithPrefix(prefix string) *Logger {
	if logger.prefix != "" {
		prefix = logger.prefix + ": " + prefix
	}

	return &Logger{
		Colored: logger.Colored,
		Level:   logger.Level,
		prefix:  prefix,
		writer:  logger.writer,
	}
}

func (logger *Logger) Log(level Level, format string, arguments ...any) {
	if logger.writer == nil || level == Silent || level > logger.Level {
		return
	}

	logString := strings.TrimSpace(format)
	if len(arguments) > 0 {
		logString = fmt.Sprintf(logString, arguments...)
	}

	var (
		color = ""
		reset = ""
	)

	if logger.Colored {
		color = "\033[2m"
		reset = "\033[0m"
	}

	if level == Warning {
		color = "\033[33m"
	}

	_, _ = fmt.Fprintf(logger.writer, "%s%s: %s%s\n", color, logger.prefix, logString, reset)
}
