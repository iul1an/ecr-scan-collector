//go:build integration

package collector

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/iul1an/ecr-scan-collector/internal/logger"
	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupOpenSearchContainer(ctx context.Context) (testcontainers.Container, string, error) {
	req := testcontainers.ContainerRequest{
		Image:        "opensearchproject/opensearch:2",
		ExposedPorts: []string{"9200/tcp"},
		Env: map[string]string{
			"discovery.type":              "single-node",
			"DISABLE_SECURITY_PLUGIN":     "true",
			"DISABLE_INSTALL_DEMO_CONFIG": "true",
		},
		WaitingFor: wait.ForHTTP("/").WithPort("9200/tcp"),
	}

	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, "", fmt.Errorf("failed to create and start OpenSearch container: %w", err)
	}

	ip, err := container.Host(ctx)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get OpenSearch container IP: %w", err)
	}

	mappedPort, err := container.MappedPort(ctx, "9200")
	if err != nil {
		return nil, "", fmt.Errorf("failed to get OpenSearch container port: %w", err)
	}

	url := fmt.Sprintf("http://%s:%s", ip, mappedPort.Port())

	return container, url, nil
}

func TestOpenSearchCollector_Integration(t *testing.T) {
	ctx := context.Background()

	container, url, err := setupOpenSearchContainer(ctx)
	require.NoError(t, err)
	defer container.Terminate(ctx)

	testLogger := logger.NewLogger(logger.DEBUG)

	collector, err := NewOpenSearchCollector(url, aws.Config{}, testLogger, false, "", "", false)
	require.NoError(t, err)

	// Test indexing
	timestamp := time.Now().Format(time.RFC3339)
	desiredDoc := map[string]interface{}{
		"test":      "data",
		"timestamp": timestamp,
	}
	jsonData, err := json.Marshal(desiredDoc)
	require.NoError(t, err)

	t.Logf("Desired document: %s", string(jsonData))

	err = collector.Index(ctx, jsonData)
	require.NoError(t, err)

	// Allow some time for indexing
	time.Sleep(1 * time.Second)

	// Create an OpenSearch client for querying
	osClient, err := opensearch.NewClient(opensearch.Config{
		Addresses: []string{url},
	})
	require.NoError(t, err)

	// Query OpenSearch to verify the document was indexed
	searchBody := map[string]interface{}{
		"query": map[string]interface{}{
			"match": map[string]interface{}{
				"timestamp": timestamp,
			},
		},
	}
	searchJSON, err := json.Marshal(searchBody)
	require.NoError(t, err)

	searchReq := opensearchapi.SearchRequest{
		Index: []string{"ecr-scan-reports-" + time.Now().Format("2006.01.02")},
		Body:  bytes.NewReader(searchJSON),
	}

	searchRes, err := searchReq.Do(ctx, osClient)
	require.NoError(t, err)
	defer searchRes.Body.Close()

	var searchResult map[string]interface{}
	err = json.NewDecoder(searchRes.Body).Decode(&searchResult)
	require.NoError(t, err)

	hits, ok := searchResult["hits"].(map[string]interface{})["hits"].([]interface{})
	require.True(t, ok, "Expected hits in search result")
	require.Equal(t, 1, len(hits), "Expected one document to be found")

	// Debugging: Print the entire search result
	searchResultJSON, _ := json.MarshalIndent(searchResult, "", "  ")
	t.Logf("Search result: %s", string(searchResultJSON))

	// Check document content
	if len(hits) > 0 {
		source, ok := hits[0].(map[string]interface{})["_source"].(map[string]interface{})
		require.True(t, ok, "Expected _source in hit")

		// Debugging: Print the actual document
		actualDocJSON, _ := json.MarshalIndent(source, "", "  ")
		t.Logf("Actual document in OpenSearch: %s", string(actualDocJSON))

		assert.Equal(t, desiredDoc["test"], source["test"], "Expected 'test' field to match")
		assert.Equal(t, desiredDoc["timestamp"], source["timestamp"], "Expected 'timestamp' to match")

		// Debugging: Detailed field comparison
		for key, desiredValue := range desiredDoc {
			actualValue, exists := source[key]
			assert.True(t, exists, "Field '%s' is missing in the actual document", key)
			if exists {
				assert.Equal(t, desiredValue, actualValue, "Field '%s' mismatch", key)
			}
		}
	} else {
		t.Error("No documents found in OpenSearch")
	}
}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			collector, err := NewOpenSearchCollector(tt.endpoint, aws.Config{}, testLogger, tt.useAWS, tt.username, tt.password, tt.insecure)

			if tt.expectError {
				require.Error(t, err)
				require.Nil(t, collector)
			} else {
				require.NoError(t, err)
				require.NotNil(t, collector)
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

	// Save the current env var and restore it after the test
	origEnv := os.Getenv("OPENSEARCH_INDEX_NAME")
	defer os.Setenv("OPENSEARCH_INDEX_NAME", origEnv)

	tests := []struct {
		name          string
		envValue      string
		expectedIndex string
	}{
		{
			name:          "Default index name",
			envValue:      "",
			expectedIndex: "ecr-scan-reports-" + time.Now().Format("2006.01.02"),
		},
		{
			name:          "Custom index name",
			envValue:      "custom-index",
			expectedIndex: "custom-index-" + time.Now().Format("2006.01.02"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("OPENSEARCH_INDEX_NAME", tt.envValue)

			ctx := context.Background()
			container, url, err := setupOpenSearchContainer(ctx)
			require.NoError(t, err)
			defer container.Terminate(ctx)

			collector, err := NewOpenSearchCollector(url, aws.Config{}, testLogger, false, "", "", false)
			require.NoError(t, err)

			// Index a document to trigger the index name generation
			jsonData := []byte(`{"test": "data"}`)
			err = collector.Index(ctx, jsonData)
			require.NoError(t, err)

			// Allow some time for indexing
			time.Sleep(1 * time.Second)

			// Create an OpenSearch client for querying
			osClient, err := opensearch.NewClient(opensearch.Config{
				Addresses: []string{url},
			})
			require.NoError(t, err)

			// Query OpenSearch to verify the index name
			catReq := opensearchapi.CatIndicesRequest{
				Format: "json",
			}

			catRes, err := catReq.Do(ctx, osClient)
			require.NoError(t, err)
			defer catRes.Body.Close()

			var indices []map[string]interface{}
			err = json.NewDecoder(catRes.Body).Decode(&indices)
			require.NoError(t, err)

			foundExpectedIndex := false
			for _, index := range indices {
				if index["index"] == tt.expectedIndex {
					foundExpectedIndex = true
					break
				}
			}

			assert.True(t, foundExpectedIndex, "Expected index %s was not found", tt.expectedIndex)
		})
	}
}
