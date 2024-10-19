package collector

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/iul1an/ecr-scan-collector/internal/logger"
)

// StdoutCollector implements the LogCollector interface
// and prints the log data to stdout.
type StdoutCollector struct {
	logger *logger.Logger
}

// NewStdoutCollector creates a new StdoutCollector.
func NewStdoutCollector(l *logger.Logger) *StdoutCollector {
	return &StdoutCollector{
		logger: l,
	}
}

// Index implements the LogCollector interface
// It prints the log data to stdout as pretty-printed JSON.
//
//nolint:forbidigo // ok
func (s *StdoutCollector) Index(_ context.Context, jsonData []byte) error {
	// Unmarshal the JSON data
	var data map[string]interface{}
	if err := json.Unmarshal(jsonData, &data); err != nil {
		s.logger.Error("Failed to unmarshal JSON data", err)
		return fmt.Errorf("failed to unmarshal JSON data: %w", err)
	}

	// Marshal the data back to JSON with indentation
	prettyJSON, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.logger.Error("Failed to marshal JSON data", err)
		return fmt.Errorf("failed to marshal JSON data: %w", err)
	}

	// Print the pretty JSON
	s.logger.Info("Printing ECR scan report on stdout")
	fmt.Println(string(prettyJSON))

	return nil
}
