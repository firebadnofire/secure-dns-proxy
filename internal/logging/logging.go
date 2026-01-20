// Package logging provides a small wrapper around slog with a simplified
// interface used throughout the proxy.
package logging

import (
	"log/slog"
	"os"
	"sync"
)

// Logger exposes a minimal structured logging contract used across the proxy.
type Logger interface {
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	Debug(msg string, args ...any)
}

// Level represents supported verbosity settings.
type Level string

const (
	LevelInfo  Level = "info"
	LevelWarn  Level = "warn"
	LevelError Level = "error"
	LevelDebug Level = "debug"
)

// StructuredLogger wraps slog.Logger for simple use throughout the codebase.
// It also tracks the configured level for cheaper debug checks.
type StructuredLogger struct {
	logger *slog.Logger
	level  slog.Level
}

// default logger is lazily initialized to avoid global init side effects.
var (
	defaultOnce sync.Once
	defaultLog  Logger
)

// New returns a StructuredLogger honoring the provided level.
// The logger emits text logs to stdout.
func New(level Level) Logger {
	l := slog.LevelInfo
	switch level {
	case LevelDebug:
		l = slog.LevelDebug
	case LevelWarn:
		l = slog.LevelWarn
	case LevelError:
		l = slog.LevelError
	case LevelInfo:
		l = slog.LevelInfo
	}
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: l})
	return &StructuredLogger{logger: slog.New(handler), level: l}
}

// Default returns a package-level logger initialized once at info level.
func Default() Logger {
	defaultOnce.Do(func() {
		defaultLog = New(LevelInfo)
	})
	return defaultLog
}

// Info/Warn/Error proxy to the underlying slog.Logger.
func (s *StructuredLogger) Info(msg string, args ...any)  { s.logger.Info(msg, args...) }
func (s *StructuredLogger) Warn(msg string, args ...any)  { s.logger.Warn(msg, args...) }
func (s *StructuredLogger) Error(msg string, args ...any) { s.logger.Error(msg, args...) }
func (s *StructuredLogger) Debug(msg string, args ...any) {
	// Debug is guarded so we avoid string formatting when debug is disabled.
	if s.level <= slog.LevelDebug {
		s.logger.Debug(msg, args...)
	}
}
