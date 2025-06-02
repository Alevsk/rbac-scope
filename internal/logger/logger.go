package logger

import (
	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// Init initializes the logger using the application configuration
func Init(cfg *config.Config) {
	// Default level for this example is info, unless debug flag is present
	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	if cfg.Debug {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	}
}

// Debug logs a debug message if debug mode is enabled
func Debug() *zerolog.Event {
	return log.Debug()
}

// Info logs an info message
func Info() *zerolog.Event {
	return log.Info()
}

// Warn logs a warning message
func Warn() *zerolog.Event {
	return log.Warn()
}

// Error logs an error message
func Error() *zerolog.Event {
	return log.Error()
}

// Fatal logs a fatal message and exits with status code 1
func Fatal() *zerolog.Event {
	return log.Fatal()
}
