//go:build !integration

package logger

import (
	"bytes"
	"log"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewLogger(t *testing.T) {
	logger := NewLogger(INFO)
	assert.NotNil(t, logger)
	assert.Equal(t, INFO, logger.level)
}

func TestLogLevels(t *testing.T) {
	tests := []struct {
		level    LogLevel
		expected string
	}{
		{DEBUG, "DEBUG"},
		{INFO, "INFO"},
		{WARN, "WARN"},
		{ERROR, "ERROR"},
		{LogLevel(999), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, getLogLevelString(tt.level))
		})
	}
}

func TestGetLogLevelFromString(t *testing.T) {
	tests := []struct {
		input    string
		expected LogLevel
	}{
		{"DEBUG", DEBUG},
		{"INFO", INFO},
		{"WARN", WARN},
		{"ERROR", ERROR},
		{"INVALID", INFO},
		{"", INFO},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			assert.Equal(t, tt.expected, GetLogLevelFromString(tt.input))
		})
	}
}

func TestLogger_LogMethods(t *testing.T) {
	tests := []struct {
		name     string
		logLevel LogLevel
		logFunc  func(*Logger, string, ...interface{})
		message  string
		expected string
	}{
		{"Debug", DEBUG, (*Logger).Debug, "test debug", "[DEBUG] test debug"},
		{"Info", INFO, (*Logger).Info, "test info", "[INFO] test info"},
		{"Warn", WARN, (*Logger).Warn, "test warn", "[WARN] test warn"},
		{"Error", ERROR, (*Logger).Error, "test error", "[ERROR] test error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			logger := &Logger{
				Logger: log.New(&buf, "", 0), // Use 0 to omit date and time
				level:  tt.logLevel,
			}

			tt.logFunc(logger, tt.message)

			output := strings.TrimSpace(buf.String())
			assert.Contains(t, output, tt.expected)
		})
	}
}

func TestLogger_LogLevelFiltering(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "", 0), // Use 0 to omit date and time
		level:  WARN,
	}

	logger.Debug("This should not be logged")
	logger.Info("This should not be logged")
	logger.Warn("This should be logged")
	logger.Error("This should be logged")

	output := buf.String()
	assert.NotContains(t, output, "This should not be logged")
	assert.Contains(t, output, "[WARN] This should be logged")
	assert.Contains(t, output, "[ERROR] This should be logged")
}

func TestLogger_Formatting(t *testing.T) {
	var buf bytes.Buffer
	logger := &Logger{
		Logger: log.New(&buf, "", 0), // Use 0 to omit date and time
		level:  DEBUG,
	}

	logger.Info("Test %s %d", "formatting", 123)

	output := strings.TrimSpace(buf.String())
	assert.Equal(t, "[INFO] Test formatting 123", output)
}
