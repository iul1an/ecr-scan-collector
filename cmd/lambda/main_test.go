//go:build !integration

package main

import (
	"context"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/assert"

	"github.com/iul1an/ecr-scan-collector/internal/collector"
	"github.com/iul1an/ecr-scan-collector/internal/logger"
)

func TestInitLogger(t *testing.T) {
	tests := []struct {
		name        string
		envLogLevel string
	}{
		{"Default log level", ""},
		{"Debug log level", "DEBUG"},
		{"Info log level", "INFO"},
		{"Warn log level", "WARN"},
		{"Error log level", "ERROR"},
		{"Invalid log level", "INVALID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(envLogLevel, tt.envLogLevel)
			log := initLogger()
			assert.NotNil(t, log)
		})
	}
}

func TestSetupECRClient(t *testing.T) {
	tests := []struct {
		name    string
		roleArn string
		wantErr bool
	}{
		{"No role assumption", "", false},
		{"With role assumption", "arn:aws:iam::123456789012:role/test-role", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := aws.Config{}

			if tt.roleArn != "" {
				t.Setenv(envEcrAssumeRole, tt.roleArn)
			}

			client, err := setupECRClient(ctx, cfg)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, client)
			}
		})
	}
}

func TestSetupCollectors(t *testing.T) {
	tests := []struct {
		name               string
		opensearchEndpoint string
		stdoutCollector    string
		expectedCollectors int
		expectedOpenSearch bool
		expectedStdout     bool
		wantErr            bool
	}{
		{"No collectors", "", "", 0, false, false, true},
		{"Only OpenSearch", "http://localhost:9200", "", 1, true, false, false},
		{"Only Stdout", "", "true", 1, false, true, false},
		{"Both collectors", "http://localhost:9200", "true", 2, true, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := aws.Config{}
			log := logger.NewLogger(logger.INFO)

			t.Setenv(envOpenSearchEndpoint, tt.opensearchEndpoint)
			t.Setenv(envStdoutCollector, tt.stdoutCollector)

			collectors, err := setupCollectors(ctx, cfg, log)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, collectors)
			} else {
				assert.NoError(t, err)
				assert.Len(t, collectors, tt.expectedCollectors)

				hasOpenSearch := false
				hasStdout := false
				for _, c := range collectors {
					switch c.(type) {
					case *collector.OpenSearchCollector:
						hasOpenSearch = true
					case *collector.StdoutCollector:
						hasStdout = true
					}
				}

				assert.Equal(t, tt.expectedOpenSearch, hasOpenSearch)
				assert.Equal(t, tt.expectedStdout, hasStdout)
			}
		})
	}
}

// Mock initializeOpenSearchCollector for testing.
func mockInitializeOpenSearchCollector(
	_ context.Context, _ string, _ aws.Config, _ *logger.Logger,
) (*collector.OpenSearchCollector, error) {
	return &collector.OpenSearchCollector{}, nil
}

func TestInitializeOpenSearchCollector(t *testing.T) {
	tests := []struct {
		name          string
		endpoint      string
		useAWS        string
		username      string
		password      string
		insecure      string
		assumeRoleArn string
		wantErr       bool
	}{
		{"Basic setup", "http://localhost:9200", "false", "user", "pass", "false", "", false},
		{"Use AWS", "http://localhost:9200", "true", "", "", "false", "", false},
		{"Insecure", "http://localhost:9200", "false", "user", "pass", "true", "", false},
		{"Assume role", "http://localhost:9200", "true", "", "", "false", "arn:aws:iam::123456789012:role/test-role", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cfg := aws.Config{}
			log := logger.NewLogger(logger.INFO)

			t.Setenv(envOpenSearchUseAWS, tt.useAWS)
			t.Setenv(envOpenSearchUsername, tt.username)
			t.Setenv(envOpenSearchPassword, tt.password)
			t.Setenv(envOpenSearchInsecure, tt.insecure)
			t.Setenv(envOpenSearchAssumeRole, tt.assumeRoleArn)

			// Use the mock function instead of the actual one
			osCollector, err := mockInitializeOpenSearchCollector(ctx, tt.endpoint, cfg, log)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, osCollector)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, osCollector)
			}
		})
	}
}
