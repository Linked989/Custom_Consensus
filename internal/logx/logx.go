package logx

import (
    "log/slog"
    "os"
)

// Configure sets the default slog logger with the given level and format.
// level: "debug", "info", "warn", "error"
// format: "text" or "json"
// time format is compact (HH:MM:SS.mmm).
func Configure(level, format string) {
    var lvl slog.Level
    switch level {
    case "debug": lvl = slog.LevelDebug
    case "warn": lvl = slog.LevelWarn
    case "error": lvl = slog.LevelError
    default: lvl = slog.LevelInfo
    }
    opts := &slog.HandlerOptions{Level: lvl, ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
        if a.Key == slog.TimeKey {
            // Compact time
            if t, ok := a.Value.Time(); ok {
                a.Value = slog.StringValue(t.Format("15:04:05.000"))
            }
        }
        return a
    }}
    var h slog.Handler
    if format == "json" {
        h = slog.NewJSONHandler(os.Stdout, opts)
    } else {
        h = slog.NewTextHandler(os.Stdout, opts)
    }
    slog.SetDefault(slog.New(h))
}

func Debug(msg string, args ...any) { slog.Default().Debug(msg, args...) }
func Info(msg string, args ...any)  { slog.Default().Info(msg, args...) }
func Warn(msg string, args ...any)  { slog.Default().Warn(msg, args...) }
func Error(msg string, args ...any) { slog.Default().Error(msg, args...) }

