package logger

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/alevsk/rbac-ops/internal/config"
	"github.com/rs/zerolog"
)

func TestLogger(t *testing.T) {
	// Create a custom writer that doesn't include timestamps
	var buf bytes.Buffer

	tests := []struct {
		name    string
		debug   bool
		logFunc func() *zerolog.Event
		message string
		level   string
		wantLog bool
	}{
		{
			name:    "debug log with debug mode on",
			debug:   true,
			logFunc: Debug,
			message: "debug message",
			level:   "debug",
			wantLog: true,
		},
		{
			name:    "debug log with debug mode off",
			debug:   false,
			logFunc: Debug,
			message: "debug message",
			level:   "debug",
			wantLog: false,
		},
		{
			name:    "info log",
			debug:   false,
			logFunc: Info,
			message: "info message",
			level:   "info",
			wantLog: true,
		},
		{
			name:    "warn log",
			debug:   false,
			logFunc: Warn,
			message: "warn message",
			level:   "warn",
			wantLog: true,
		},
		{
			name:    "error log",
			debug:   false,
			logFunc: Error,
			message: "error message",
			level:   "error",
			wantLog: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			buf.Reset()
			// Set up a new logger for each test
			log = zerolog.New(&buf).Level(zerolog.DebugLevel)

			// Initialize with config
			Init(&config.Config{Debug: tt.debug})

			// Write log message
			tt.logFunc().Msg(tt.message)

			// Get output and trim any whitespace
			output := strings.TrimSpace(buf.String())
			if tt.wantLog {
				if output == "" {
					t.Error("Expected log output but got none")
					return
				}
				if !strings.Contains(output, fmt.Sprintf(`"level":"%s"`, tt.level)) {
					t.Errorf("Expected log level %s not found in output: %s", tt.level, output)
				}
				if !strings.Contains(output, fmt.Sprintf(`"message":"%s"`, tt.message)) {
					t.Errorf("Expected message %q not found in output: %s", tt.message, output)
				}
			} else if output != "" {
				t.Errorf("Expected no log output, but got: %s", output)
			}
		})
	}
}
