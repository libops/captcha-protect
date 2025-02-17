package log

import (
	"errors"
	"io"
	"log"
	"os"
	"strings"
)

type LogLevel int

const (
	ERROR LogLevel = iota
	WARNING
	INFO
	DEBUG
)

func ParseLevel(level string) (LogLevel, error) {
	switch strings.ToUpper(level) {
	case "ERROR":
		return ERROR, nil
	case "WARNING":
		return WARNING, nil
	case "INFO":
		return INFO, nil
	case "DEBUG":
		return DEBUG, nil
	default:
		return -1, errors.New("Invalid LogLevel")
	}

}

type Logger struct {
	ErrorLogger   log.Logger
	WarningLogger log.Logger
	InfoLogger    log.Logger
	DebugLogger   log.Logger
	Level         LogLevel
}

func New(out io.Writer, prefix string, flag int, level LogLevel) *Logger {
	if len(prefix) != 0 {
		prefix = prefix + " "
	}
	return &Logger{
		ErrorLogger:   *log.New(out, prefix+"ERROR: ", flag),
		WarningLogger: *log.New(out, prefix+"WARNING: ", flag),
		InfoLogger:    *log.New(out, prefix+"INFO: ", flag),
		DebugLogger:   *log.New(out, prefix+"DEBUG: ", flag),
		Level:         level,
	}
}

var std = New(os.Stdout, "Bad Bot Blocker", log.LstdFlags|log.Lmsgprefix, INFO)

func Default() *Logger {
	return std
}

func Error(v ...any) {
	if std.Level >= ERROR {
		std.ErrorLogger.Println(v...)
	}
}

func Warning(v ...any) {
	if std.Level >= WARNING {
		std.WarningLogger.Println(v...)
	}
}

func Info(v ...any) {
	if std.Level >= INFO {
		std.InfoLogger.Println(v...)
	}
}

func Debug(v ...any) {
	if std.Level >= DEBUG {
		std.DebugLogger.Println(v...)
	}
}

func Errorf(format string, v ...any) {
	if std.Level >= ERROR {
		std.ErrorLogger.Printf(format, v...)
	}
}

func Warningf(format string, v ...any) {
	if std.Level >= WARNING {
		std.WarningLogger.Printf(format, v...)
	}
}

func Infof(format string, v ...any) {
	if std.Level >= INFO {
		std.InfoLogger.Printf(format, v...)
	}
}

func Debugf(format string, v ...any) {
	if std.Level >= DEBUG {
		std.DebugLogger.Printf(format, v...)
	}
}
