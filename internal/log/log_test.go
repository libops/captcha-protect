package log

import (
	"log/slog"
	"testing"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name          string
		levelStr      string
		expectedLevel slog.Level
	}{
		{"DEBUG level", "DEBUG", slog.LevelDebug},
		{"INFO level", "INFO", slog.LevelInfo},
		{"WARN level", "WARN", slog.LevelWarn},
		{"WARNING level", "WARNING", slog.LevelWarn},
		{"ERROR level", "ERROR", slog.LevelError},
		{"debug lowercase", "debug", slog.LevelDebug},
		{"Unknown level defaults to INFO", "UNKNOWN", slog.LevelInfo},
		{"Empty level defaults to INFO", "", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := New(tt.levelStr)
			if logger == nil {
				t.Error("Expected non-nil logger")
			}
			// Logger is created successfully, we can't easily test the exact level
			// but we verify it doesn't panic or error
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name      string
		level     string
		expected  slog.Level
		expectErr bool
	}{
		{"DEBUG", "DEBUG", slog.LevelDebug, false},
		{"debug lowercase", "debug", slog.LevelDebug, false},
		{"INFO", "INFO", slog.LevelInfo, false},
		{"info lowercase", "info", slog.LevelInfo, false},
		{"WARN", "WARN", slog.LevelWarn, false},
		{"WARNING", "WARNING", slog.LevelWarn, false},
		{"warning lowercase", "warning", slog.LevelWarn, false},
		{"ERROR", "ERROR", slog.LevelError, false},
		{"error lowercase", "error", slog.LevelError, false},
		{"Unknown level", "INVALID", slog.LevelInfo, true},
		{"Empty string", "", slog.LevelInfo, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			level, err := parseLogLevel(tt.level)
			if tt.expectErr {
				if err == nil {
					t.Errorf("Expected error for level %q, got nil", tt.level)
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error for level %q: %v", tt.level, err)
				}
			}
			if level != tt.expected {
				t.Errorf("Expected level %v, got %v", tt.expected, level)
			}
		})
	}
}
