//go:build !integration

package handler

import (
	"context"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/iul1an/ecr-scan-collector/internal/logger"
	"github.com/iul1an/ecr-scan-collector/internal/types"
)

var debugLogger = logger.NewLogger(logger.DEBUG)

// MockECRClient is a mock of ECRAPIClient interface.
type MockECRClient struct {
	mock.Mock
}

func (m *MockECRClient) DescribeImageScanFindings(
	ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options),
) (*ecr.DescribeImageScanFindingsOutput, error) {
	args := m.Called(ctx, params, optFns)
	return args.Get(0).(*ecr.DescribeImageScanFindingsOutput), args.Error(1)
}

func (m *MockECRClient) DescribeImages(
	ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options),
) (*ecr.DescribeImagesOutput, error) {
	args := m.Called(ctx, params, optFns)
	return args.Get(0).(*ecr.DescribeImagesOutput), args.Error(1)
}

func TestUnmarshalEvent(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	testCases := []struct {
		name          string
		input         json.RawMessage
		expected      *events.ECRScanEventDetailType
		expectedError bool
	}{
		{
			name:  "Valid input",
			input: json.RawMessage(`{"repository-name":"test-repo","image-digest":"sha256:1234567890abcdef","image-tags":["latest"]}`),
			expected: &events.ECRScanEventDetailType{
				RepositoryName: "test-repo",
				ImageDigest:    "sha256:1234567890abcdef",
				ImageTags:      []string{"latest"},
			},
			expectedError: false,
		},
		{
			name:          "Invalid input",
			input:         json.RawMessage(`{"invalid":"json"`),
			expected:      nil,
			expectedError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := handler.unmarshalEvent(tc.input)
			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected, result)
			}
		})
	}
}

func TestGetImageMetadata(t *testing.T) {
	mockECR := new(MockECRClient)
	handler := &LambdaHandler{
		ecrClient: mockECR,
		logger:    debugLogger,
	}

	ctx := context.Background()
	ecrEvent := &events.ECRScanEventDetailType{
		RepositoryName: "test-repo",
		ImageDigest:    "sha256:1234567890abcdef",
	}

	expectedOutput := &ecr.DescribeImagesOutput{
		ImageDetails: []awsTypes.ImageDetail{
			{
				ImageDigest:   aws.String("sha256:1234567890abcdef"),
				ImagePushedAt: aws.Time(time.Now()),
				RegistryId:    aws.String("123456789012"),
			},
		},
	}

	mockECR.On("DescribeImages", ctx, mock.AnythingOfType("*ecr.DescribeImagesInput"), mock.Anything).Return(expectedOutput, nil)

	result, err := handler.getImageMetadata(ctx, ecrEvent)

	require.NoError(t, err)
	assert.Equal(t, expectedOutput, result)
	mockECR.AssertExpectations(t)
}

func TestGetScanFindings(t *testing.T) {
	mockECR := new(MockECRClient)
	handler := &LambdaHandler{
		ecrClient: mockECR,
		logger:    debugLogger,
	}

	ctx := context.Background()
	ecrEvent := &events.ECRScanEventDetailType{
		RepositoryName: "test-repo",
		ImageDigest:    "sha256:1234567890abcdef",
	}

	now := time.Now()
	expectedOutput := &ecr.DescribeImageScanFindingsOutput{
		ImageScanFindings: &awsTypes.ImageScanFindings{
			FindingSeverityCounts: map[string]int32{
				"HIGH": 1,
				"LOW":  2,
			},
			Findings: []awsTypes.ImageScanFinding{
				{
					Name:     aws.String("CVE-2021-44228"),
					Severity: awsTypes.FindingSeverityHigh,
				},
			},
			ImageScanCompletedAt: &now,
		},
	}

	mockECR.On(
		"DescribeImageScanFindings",
		ctx, mock.AnythingOfType("*ecr.DescribeImageScanFindingsInput"),
		mock.Anything,
	).Return(expectedOutput, nil)

	findings, severityCounts, completedAt, err := handler.getScanFindings(ctx, ecrEvent)

	require.NoError(t, err)
	assert.Equal(t, expectedOutput.ImageScanFindings.Findings, findings)
	assert.Equal(t, expectedOutput.ImageScanFindings.FindingSeverityCounts, severityCounts)
	assert.Equal(t, expectedOutput.ImageScanFindings.ImageScanCompletedAt, completedAt)
	mockECR.AssertExpectations(t)
}

func TestParseScanFindings(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	input := []awsTypes.ImageScanFinding{
		{
			Name:     aws.String("CVE-2021-44228"),
			Severity: awsTypes.FindingSeverityHigh,
			Attributes: []awsTypes.Attribute{
				{Key: aws.String("package_name"), Value: aws.String("log4j")},
				{Key: aws.String("package_version"), Value: aws.String("2.0-beta9")},
			},
			Uri: aws.String("https://nvd.nist.gov/vuln/detail/CVE-2021-44228"),
		},
		{
			Name:     aws.String("CVE-2021-12345"),
			Severity: awsTypes.FindingSeverityLow,
			Attributes: []awsTypes.Attribute{
				{Key: aws.String("package_name"), Value: aws.String("openssl")},
				{Key: aws.String("package_version"), Value: aws.String("1.1.1")},
			},
			Uri: aws.String("https://nvd.nist.gov/vuln/detail/CVE-2021-12345"),
		},
	}

	severityCounts := map[string]int32{
		"HIGH": 1,
		"LOW":  1,
	}

	testCases := []struct {
		name               string
		severities         []string
		expectedFindings   int
		expectedSeverities map[string]int32
	}{
		{
			name:               "No severity filter",
			severities:         []string{},
			expectedFindings:   2,
			expectedSeverities: severityCounts,
		},
		{
			name:               "Filter HIGH severity",
			severities:         []string{"HIGH"},
			expectedFindings:   1,
			expectedSeverities: map[string]int32{"HIGH": 1},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resultFindings, resultSeverityCounts := handler.parseScanFindings(input, severityCounts, tc.severities)
			assert.Len(t, resultFindings, tc.expectedFindings)
			assert.Equal(t, tc.expectedSeverities, resultSeverityCounts)
		})
	}
}

func TestGetSeverityCounts(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	testCases := []struct {
		name               string
		scanSeverityCounts map[string]int32
		severities         []string
		expected           map[string]int32
	}{
		{
			name: "All severities",
			scanSeverityCounts: map[string]int32{
				"HIGH": 1,
				"LOW":  2,
			},
			severities: []string{},
			expected: map[string]int32{
				"HIGH": 1,
				"LOW":  2,
			},
		},
		{
			name: "Filtered severities",
			scanSeverityCounts: map[string]int32{
				"HIGH": 1,
				"LOW":  2,
			},
			severities: []string{"HIGH"},
			expected: map[string]int32{
				"HIGH": 1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := handler.getSeverityCounts(tc.scanSeverityCounts, tc.severities)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCreateReport(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	ecrEvent := &events.ECRScanEventDetailType{
		RepositoryName: "test-repo",
		ImageDigest:    "sha256:1234567890abcdef",
		ImageTags:      []string{"latest"},
	}

	now := time.Now()
	imageMetadata := &ecr.DescribeImagesOutput{
		ImageDetails: []awsTypes.ImageDetail{
			{
				ImagePushedAt: &now,
				RegistryId:    aws.String("123456789012"),
			},
		},
	}

	scanFindings := []types.EcrScanFinding{
		{
			Name:     aws.String("CVE-2021-44228"),
			Severity: awsTypes.FindingSeverityHigh,
		},
	}

	severityCounts := map[string]int32{
		"HIGH": 1,
		"LOW":  2,
	}

	expected := types.ECRScanReport{
		RegistryId:            aws.String("123456789012"),
		RepositoryName:        "test-repo",
		ImageDigest:           "sha256:1234567890abcdef",
		ImageTags:             []string{"latest"},
		ImagePushedAt:         &now,
		ImageScanCompletedAt:  &now,
		ScanFindings:          scanFindings,
		FindingSeverityCounts: severityCounts,
		FindingsTotal:         1,
	}

	result := handler.createReport(ecrEvent, imageMetadata, scanFindings, severityCounts, &now)

	assert.Equal(t, expected, result)
}

func TestGetSeveritiesFromEnv(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	testCases := []struct {
		name     string
		envValue string
		expected []string
	}{
		{
			name:     "Empty environment variable",
			envValue: "",
			expected: nil,
		},
		{
			name:     "Single severity",
			envValue: "HIGH",
			expected: []string{"HIGH"},
		},
		{
			name:     "Multiple severities",
			envValue: "HIGH,MEDIUM,LOW",
			expected: []string{"HIGH", "MEDIUM", "LOW"},
		},
		{
			name:     "Mixed case and spaces",
			envValue: "High, medium ,low",
			expected: []string{"HIGH", "MEDIUM", "LOW"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(envSeverityLevels, tc.envValue)
			defer os.Unsetenv(envSeverityLevels)

			result := handler.getSeveritiesFromEnv()
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestValidateSeverities(t *testing.T) {
	handler := &LambdaHandler{logger: debugLogger}

	testCases := []struct {
		name        string
		severities  []string
		expectError bool
	}{
		{
			name:        "Valid severities",
			severities:  []string{"INFORMATIONAL", "LOW", "MEDIUM", "HIGH", "CRITICAL"},
			expectError: false,
		},
		{
			name:        "Invalid severity",
			severities:  []string{"HIGH", "INVALID"},
			expectError: true,
		},
		{
			name:        "Empty list",
			severities:  []string{},
			expectError: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := handler.validateSeverities(tc.severities)
			if tc.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
