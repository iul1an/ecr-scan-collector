//go:build !integration

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iul1an/ecr-scan-collector/internal/logger"
	"github.com/iul1an/ecr-scan-collector/internal/types"
)

func TestStdoutCollector(t *testing.T) {
	l := logger.NewLogger(logger.DEBUG)
	l.Debug("Starting TestStdoutCollector")

	scanCompletedAt, err := time.Parse(time.RFC3339, "2022-03-23T14:00:00Z")
	require.NoError(t, err)

	imagePushedAt, err := time.Parse(time.RFC3339, "2022-03-23T13:57:00Z")
	require.NoError(t, err)

	tests := []struct {
		name    string
		input   types.ECRScanReport
		wantErr bool
	}{
		{
			name: "Valid ECR Scan Report",
			input: types.ECRScanReport{
				RegistryId:           aws.String("123456789012"),
				RepositoryName:       "my-shiny-repo",
				ImageDigest:          "sha256:6a5a5368e0c2d3e5909184129962d126c0f20ce69b335531f30a6b760cdcf60b",
				ImageScanCompletedAt: &scanCompletedAt,
				ImagePushedAt:        &imagePushedAt,
				ScanFindings: []types.EcrScanFinding{
					{
						Name:           aws.String("ALAS2023-2024-609"),
						Severity:       "HIGH",
						PackageName:    aws.String("git"),
						PackageVersion: aws.String("2.40.1-1.amzn2023.0.1"),
					},
				},
				FindingSeverityCounts: map[string]int32{
					"HIGH": 1,
				},
				FindingsTotal: 1,
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l.Debug("Starting test case: %s", tt.name)

			collector := NewStdoutCollector(l)
			l.Debug("Created StdoutCollector")

			// Convert input to JSON
			inputJSON, err := json.Marshal(tt.input)
			require.NoError(t, err)

			// Capture stdout
			old := os.Stdout
			r, w, _ := os.Pipe()
			os.Stdout = w //nolint:reassign //ok
			l.Debug("Captured stdout")

			err = collector.Index(context.Background(), inputJSON)
			l.Debug("Executed Index method")

			// Restore stdout
			_ = w.Close()
			os.Stdout = old //nolint:reassign //ok
			l.Debug("Restored stdout")

			if tt.wantErr {
				assert.Error(t, err)
				l.Debug("Expected error occurred: %v", err)
				return
			}

			require.NoError(t, err)
			l.Debug("No error occurred as expected")

			var buf bytes.Buffer
			_, err = io.Copy(&buf, r)
			require.NoError(t, err)
			output := buf.String()
			l.Debug("Captured output:\n%s", output)

			// Extract JSON part
			jsonStart := strings.Index(output, "{")
			jsonEnd := strings.LastIndex(output, "}")
			jsonOutput := output[jsonStart : jsonEnd+1]

			// Unmarshal captured output
			var capturedData types.ECRScanReport
			err = json.Unmarshal([]byte(jsonOutput), &capturedData)
			require.NoError(t, err)

			// Compare expected and actual output
			assert.Equal(t, tt.input, capturedData, "Unexpected output content")

			// Check JSON formatting
			expectedJSON, err := json.MarshalIndent(tt.input, "", "  ")
			require.NoError(t, err)
			assert.JSONEq(t, string(expectedJSON), jsonOutput, "JSON formatting or content mismatch")

			l.Debug("Completed test case: %s", tt.name)
		})
	}

	l.Debug("Completed TestStdoutCollector")
}
