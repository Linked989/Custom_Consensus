package logx

import (
    "io"
    "os"
    "strings"
    "sync/atomic"
    "time"

    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

var (
    verbose atomic.Bool
)

// Configure sets up zerolog with the given level and format.
// level: "debug", "info", "warn", "error"
// format: "text" or "json"; time format is compact (HH:MM:SS.mmm).
func Configure(level, format string) {
    zerolog.TimeFieldFormat = "15:04:05.000"

    var w io.Writer = os.Stdout
    if strings.ToLower(format) == "text" {
        cw := zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: "15:04:05.000"}
        // Keep message then key=val pairs
        cw.FormatTimestamp = func(i interface{}) string { return i.(string) }
        w = cw
    }

    lvl := zerolog.InfoLevel
    switch strings.ToLower(level) {
    case "debug": lvl = zerolog.DebugLevel
    case "warn": lvl = zerolog.WarnLevel
    case "error": lvl = zerolog.ErrorLevel
    case "info": lvl = zerolog.InfoLevel
    }
    l := zerolog.New(w).With().Timestamp().Logger().Level(lvl)
    log.Logger = l
}

// SetVerbose enables or disables regular logs. When false, Debug/Info/Warn/Error are no-ops.
func SetVerbose(v bool) { if v { verbose.Store(true) } else { verbose.Store(false) } }

// Startup always logs regardless of verbosity, intended for the one-time startup line.
func Startup(msg string, args ...any) { emit(log.Logger, msg, args...) }

func Debug(msg string, args ...any) { if !verbose.Load() { return }; logEvt(log.Logger.Debug(), msg, args...) }
func Info(msg string, args ...any)  { if !verbose.Load() { return }; logEvt(log.Logger.Info(), msg, args...) }
func Warn(msg string, args ...any)  { if !verbose.Load() { return }; logEvt(log.Logger.Warn(), msg, args...) }
func Error(msg string, args ...any) { if !verbose.Load() { return }; logEvt(log.Logger.Error(), msg, args...) }

// logEvt attaches fields from alternating key/value args and emits the event with message.
func logEvt(evt *zerolog.Event, msg string, args ...any) {
    if evt == nil { return }
    addFields(evt, args...)
    evt.Msg(msg)
}

// emit logs with level inferred from context; used by Startup to always print.
func emit(l zerolog.Logger, msg string, args ...any) {
    evt := l.Info()
    addFields(evt, args...)
    evt.Msg(msg)
}

func addFields(evt *zerolog.Event, args ...any) {
    // Expect key, value pairs; ignore trailing odd arg
    for i := 0; i+1 < len(args); i += 2 {
        key, ok := args[i].(string)
        if !ok { continue }
        val := args[i+1]
        switch v := val.(type) {
        case string:
            evt.Str(key, v)
        case int:
            evt.Int(key, v)
        case int64:
            evt.Int64(key, v)
        case uint64:
            evt.Uint64(key, v)
        case uint:
            evt.Uint(key, v)
        case bool:
            evt.Bool(key, v)
        case time.Duration:
            evt.Dur(key, v)
        default:
            evt.Interface(key, v)
        }
    }
}
