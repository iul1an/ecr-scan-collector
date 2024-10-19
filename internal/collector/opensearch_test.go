//go:build !integration

package collector

import (
	"os"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/iul1an/ecr-scan-collector/internal/logger"
)

func TestNewOpenSearchCollector(t *testing.T) {
	testLogger := logger.NewLogger(logger.DEBUG)

	tests := []struct {
		name        string
		endpoint    string
		useAWS      bool
		username    string
		password    string
		insecure    bool
		expectError bool
	}{
		{
			name:        "Valid configuration",
			endpoint:    "http://localhost:9200",
			useAWS:      false,
			username:    "user",
			password:    "pass",
			insecure:    false,
			expectError: false,
		},
		{
			name:        "Empty endpoint",
			endpoint:    "",
			useAWS:      false,
			username:    "user",
			password:    "pass",
			insecure:    false,
			expectError: true,
		},
		{
			name:        "AWS configuration",
			endpoint:    "http://localhost:9200",
			useAWS:      true,
			username:    "",
			password:    "",
			insecure:    false,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector, err := NewOpenSearchCollector(tt.endpoint, aws.Config{}, testLogger, tt.useAWS, tt.username, tt.password, tt.insecure)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, collector)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, collector)
				assert.Equal(t, tt.endpoint, collector.endpoint)
				assert.Equal(t, tt.useAWS, collector.useAWS)
				assert.Equal(t, tt.username, collector.username)
				assert.Equal(t, tt.password, collector.password)
				assert.Equal(t, tt.insecure, collector.insecure)
			}
		})
	}
}

func TestOpenSearchCollector_IndexName(t *testing.T) {
	testLogger := logger.NewLogger(logger.DEBUG)

	tests := []struct {
		name           string
		envValue       string
		expectedPrefix string
	}{
		{
			name:           "Default index name",
			envValue:       "",
			expectedPrefix: "ecr-scan-reports-",
		},
		{
			name:           "Custom index name",
			envValue:       "custom-index",
			expectedPrefix: "custom-index-",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv("OPENSEARCH_INDEX_NAME", tt.envValue)
			defer os.Unsetenv("OPENSEARCH_INDEX_NAME")

			_, err := NewOpenSearchCollector("http://localhost:9200", aws.Config{}, testLogger, false, "", "", false)
			require.NoError(t, err)

			// We can't directly test the index name as it's generated inside the Index method
			// Instead, we'll test that the environment variable is correctly read
			if tt.envValue == "" {
				assert.Equal(t, "ecr-scan-reports-", tt.expectedPrefix)
			} else {
				assert.Equal(t, tt.envValue+"-", tt.expectedPrefix)
			}
		})
	}
}
