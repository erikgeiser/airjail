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

func (level Level) String() string {
	switch level {
	case Silent:
		return "silent"
	case Warning:
		return "warning"
	case Info:
		return "info"
	case Debug:
		return "debug"
	default:
		return Warning.String()
	}
}

// Logger emits operational messages at or below its configured level.
type Logger struct {
	Colored bool
	Level   Level
	prefix  string
	writer  io.Writer
}

// New creates a logger.
func New(writer io.Writer, level string, prefix string) (*Logger, error) {
	l := &Logger{writer: writer}

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
	if logger == nil {
		return nil
	}

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

// LevelName returns the configured level name, or silent for a nil logger.
func (logger *Logger) LevelName() string {
	if logger == nil {
		return Silent.String()
	}

	return logger.Level.String()
}

// Debugf logs a debug message when debug logging is enabled.
func (logger *Logger) Debugf(format string, arguments ...any) {
	logger.logf(Debug, format, arguments...)
}

// Infof logs an informational message when info or debug logging is enabled.
func (logger *Logger) Infof(format string, arguments ...any) {
	logger.logf(Info, format, arguments...)
}

// Warnf logs a warning when warning, info, or debug logging is enabled.
func (logger *Logger) Warnf(format string, arguments ...any) {
	logger.logf(Warning, format, arguments...)
}

func (logger *Logger) logf(level Level, format string, arguments ...any) {
	if logger == nil || logger.writer == nil || level == Silent || level > logger.Level {
		return
	}

	logString := strings.TrimSpace(format)
	if len(arguments) > 0 {
		logString = fmt.Sprintf(logString, arguments...)
	}

	var (
		style = ""
		reset = ""
	)

	if logger.Colored {
		reset = "\033[0m"

		switch level {
		case Warning:
			style = "\033[2;33m"
		case Info:
			style = "\033[34m"
		default:
			style = "\033[2m"
		}
	}

	prefix := ""
	if logger.prefix != "" {
		prefix = logger.prefix + ": "
	}

	_, _ = fmt.Fprintf(logger.writer, "%sairjail: %s: %s%s%s\n", style, level, prefix, logString, reset)
}
