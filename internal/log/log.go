package log

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
)

func New(levelStr string) *slog.Logger {
	var logLevel slog.LevelVar
	logLevel.Set(slog.LevelInfo)
	handler := slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: &logLevel,
	})
	log := slog.New(handler)

	level, err := parseLogLevel(levelStr)
	if err != nil {
		log.Warn("Unknown log level", "err", err)
	}
	logLevel.Set(level)

	return log
}

// Map string to slog.Level
func parseLogLevel(level string) (slog.Level, error) {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug, nil
	case "INFO":
		return slog.LevelInfo, nil
	case "WARNING", "WARN":
		return slog.LevelWarn, nil
	case "ERROR":
		return slog.LevelError, nil
	default:
		return slog.LevelInfo, fmt.Errorf("unknown log level %s", level)
	}
}
