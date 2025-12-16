package logging

import (
	"context"
	"log/slog"
	"os"
	"strings"
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

// ParseLevel normalizes incoming level strings and defaults to info on unknown
// input.
func ParseLevel(level string) Level {
	switch strings.ToLower(level) {
	case string(LevelDebug):
		return LevelDebug
	case string(LevelWarn):
		return LevelWarn
	case string(LevelError):
		return LevelError
	default:
		return LevelInfo
	}
}

// StructuredLogger wraps slog.Logger for simple use throughout the codebase.
type StructuredLogger struct {
	logger *slog.Logger
	level  slog.Level
}

var (
	defaultOnce sync.Once
	defaultLog  Logger
)

// New returns a StructuredLogger honoring the provided level.
func New(level Level) Logger {
	l := slog.LevelInfo
	switch ParseLevel(string(level)) {
	case LevelDebug:
		l = slog.LevelDebug
	case LevelWarn:
		l = slog.LevelWarn
	case LevelError:
		l = slog.LevelError
	case LevelInfo:
		l = slog.LevelInfo
	}
	return &StructuredLogger{logger: slog.New(newHumanHandler(l)), level: l}
}

// Default returns a package-level logger initialized once at info level.
func Default() Logger {
	defaultOnce.Do(func() {
		defaultLog = New(LevelInfo)
	})
	return defaultLog
}

func (s *StructuredLogger) Info(msg string, args ...any)  { s.logger.Info(msg, args...) }
func (s *StructuredLogger) Warn(msg string, args ...any)  { s.logger.Warn(msg, args...) }
func (s *StructuredLogger) Error(msg string, args ...any) { s.logger.Error(msg, args...) }
func (s *StructuredLogger) Debug(msg string, args ...any) {
	if s.level <= slog.LevelDebug {
		s.logger.Debug(msg, args...)
	}
}

type humanHandler struct {
	level slog.Leveler
	attrs []slog.Attr
	mu    sync.Mutex
}

func newHumanHandler(level slog.Leveler) slog.Handler {
	return &humanHandler{level: level}
}

func (h *humanHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.level.Level()
}

func (h *humanHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()

	b := strings.Builder{}
	b.WriteString(strings.ToUpper(r.Level.String()))

	if r.Message != "" {
		b.WriteString(" ")
		b.WriteString(r.Message)
	}

	attrs := make([]slog.Attr, 0, len(h.attrs)+r.NumAttrs())
	attrs = append(attrs, h.attrs...)
	r.Attrs(func(a slog.Attr) bool {
		attrs = append(attrs, a)
		return true
	})

	if len(attrs) > 0 {
		b.WriteString(" ")
		for i, a := range attrs {
			if i > 0 {
				b.WriteString(" ")
			}
			b.WriteString(a.Key)
			b.WriteString("=")
			b.WriteString(a.Value.String())
		}
	}

	_, _ = os.Stdout.WriteString(b.String() + "\n")
	return nil
}

func (h *humanHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	copyAttrs := make([]slog.Attr, 0, len(h.attrs)+len(attrs))
	copyAttrs = append(copyAttrs, h.attrs...)
	copyAttrs = append(copyAttrs, attrs...)
	return &humanHandler{level: h.level, attrs: copyAttrs}
}

func (h *humanHandler) WithGroup(_ string) slog.Handler { return h }
