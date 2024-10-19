package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	awsTypes "github.com/aws/aws-sdk-go-v2/service/ecr/types"

	"github.com/iul1an/ecr-scan-collector/internal/collector"
	"github.com/iul1an/ecr-scan-collector/internal/logger"
	"github.com/iul1an/ecr-scan-collector/internal/types"
)

const (
	envSeverityLevels = "SEVERITY_LEVELS"
	maxResultsPerPage = 100
)

type LambdaHandler struct {
	ecrClient     types.ECRAPIClient
	logger        *logger.Logger
	logCollectors []collector.LogCollector
}

func NewLambdaHandler(
	ecrClient types.ECRAPIClient, l *logger.Logger, collectors []collector.LogCollector,
) *LambdaHandler {
	return &LambdaHandler{
		ecrClient:     ecrClient,
		logger:        l,
		logCollectors: collectors,
	}
}

func (h *LambdaHandler) unmarshalEvent(detail json.RawMessage) (*events.ECRScanEventDetailType, error) {
	var ecrEvent events.ECRScanEventDetailType
	if err := json.Unmarshal(detail, &ecrEvent); err != nil {
		return nil, fmt.Errorf("failed to unmarshal event detail: %w", err)
	}
	return &ecrEvent, nil
}

func (h *LambdaHandler) getImageMetadata(ctx context.Context, ecrEvent *events.ECRScanEventDetailType) (*ecr.DescribeImagesOutput, error) {
	input := &ecr.DescribeImagesInput{
		RepositoryName: &ecrEvent.RepositoryName,
		ImageIds: []awsTypes.ImageIdentifier{
			{
				ImageDigest: &ecrEvent.ImageDigest,
			},
		},
	}
	return h.ecrClient.DescribeImages(ctx, input)
}

func (h *LambdaHandler) getScanFindings(
	ctx context.Context, ecrEvent *events.ECRScanEventDetailType,
) ([]awsTypes.ImageScanFinding, map[string]int32, *time.Time, error) {
	var allFindings []awsTypes.ImageScanFinding
	var nextToken *string

	for {
		input := &ecr.DescribeImageScanFindingsInput{
			RepositoryName: &ecrEvent.RepositoryName,
			ImageId: &awsTypes.ImageIdentifier{
				ImageDigest: &ecrEvent.ImageDigest,
			},
			MaxResults: aws.Int32(maxResultsPerPage),
			NextToken:  nextToken,
		}

		scanOutput, err := h.ecrClient.DescribeImageScanFindings(ctx, input)
		if err != nil {
			return nil, nil, nil, fmt.Errorf("failed to get scan findings: %w", err)
		}

		allFindings = append(allFindings, scanOutput.ImageScanFindings.Findings...)

		if scanOutput.NextToken == nil {
			h.logger.Debug(
				fmt.Sprintf("Retrieved scan findings, repository: %s, imageDigest: %s", ecrEvent.RepositoryName, ecrEvent.ImageDigest),
			)
			return allFindings,
				scanOutput.ImageScanFindings.FindingSeverityCounts,
				scanOutput.ImageScanFindings.ImageScanCompletedAt,
				nil
		}

		nextToken = scanOutput.NextToken
	}
}

func (h *LambdaHandler) parseScanFindings(
	findings []awsTypes.ImageScanFinding, scanSeverityCounts map[string]int32, severities []string,
) ([]types.EcrScanFinding, map[string]int32) {
	severitySet := make(map[string]struct{}, len(severities))
	for _, severity := range severities {
		severitySet[severity] = struct{}{}
	}

	scanFindings := make([]types.EcrScanFinding, 0, len(findings))
	for _, finding := range findings {
		// If severities are specified, filter by them
		if len(severities) > 0 {
			if _, ok := severitySet[string(finding.Severity)]; !ok {
				// Skip findings that don't match the specified severities
				continue
			}
		}

		packageAttrs := make(map[string]*string)
		for _, attr := range finding.Attributes {
			if attr.Key != nil && (*attr.Key == "package_name" || *attr.Key == "package_version") {
				packageAttrs[*attr.Key] = attr.Value
			}
		}

		scanFindings = append(scanFindings, types.EcrScanFinding{
			Name:           finding.Name,
			Severity:       finding.Severity,
			PackageName:    packageAttrs["package_name"],
			PackageVersion: packageAttrs["package_version"],
			Uri:            finding.Uri,
		})
	}

	severityCounts := h.getSeverityCounts(scanSeverityCounts, severities)
	return scanFindings, severityCounts
}

func (h *LambdaHandler) getSeverityCounts(scanSeverityCounts map[string]int32, severities []string) map[string]int32 {
	// If no severities provided, return all severities
	if len(severities) == 0 {
		return scanSeverityCounts
	}

	data := make(map[string]int32)
	for _, severity := range severities {
		// Check if the severity exists in the findings and has a non-zero value
		if count, ok := scanSeverityCounts[severity]; ok && count > 0 {
			// If it exists and is non-zero, assign the count to the data map
			data[severity] = count
		}
	}
	return data
}

func (h *LambdaHandler) createReport(
	ecrEvent *events.ECRScanEventDetailType, imageMetadata *ecr.DescribeImagesOutput, scanFindings []types.EcrScanFinding,
	severityCounts map[string]int32, imageScanCompletedAt *time.Time,
) types.ECRScanReport {
	return types.ECRScanReport{
		RegistryId:            imageMetadata.ImageDetails[0].RegistryId,
		RepositoryName:        ecrEvent.RepositoryName,
		ImageDigest:           ecrEvent.ImageDigest,
		ImageTags:             ecrEvent.ImageTags,
		ImagePushedAt:         imageMetadata.ImageDetails[0].ImagePushedAt,
		ImageScanCompletedAt:  imageScanCompletedAt,
		ScanFindings:          scanFindings,
		FindingSeverityCounts: severityCounts,
		FindingsTotal:         len(scanFindings),
	}
}

func (h *LambdaHandler) getSeveritiesFromEnv() []string {
	severitiesStr := os.Getenv(envSeverityLevels)
	if severitiesStr == "" {
		h.logger.Debug("No severities provided in environment variable", "envVar", envSeverityLevels)
		return nil
	}

	severities := strings.Split(severitiesStr, ",")
	for i, severity := range severities {
		severities[i] = strings.TrimSpace(strings.ToUpper(severity))
	}

	h.logger.Debug(
		fmt.Sprintf("Retrieved severities from environment variable, envVar: %s, severities: %s",
			envSeverityLevels, strings.Join(severities, ", "),
		),
	)
	return severities
}

func (h *LambdaHandler) validateSeverities(severities []string) error {
	validSeverities := map[string]struct{}{
		string(awsTypes.FindingSeverityInformational): {},
		string(awsTypes.FindingSeverityLow):           {},
		string(awsTypes.FindingSeverityMedium):        {},
		string(awsTypes.FindingSeverityHigh):          {},
		string(awsTypes.FindingSeverityCritical):      {},
	}

	var invalidSeverities []string
	for _, severity := range severities {
		if _, isValid := validSeverities[severity]; !isValid {
			invalidSeverities = append(invalidSeverities, severity)
		}
	}

	if len(invalidSeverities) > 0 {
		return fmt.Errorf("invalid severity levels: %s", strings.Join(invalidSeverities, ", "))
	}

	return nil
}

func (h *LambdaHandler) HandleRequest(ctx context.Context, event events.CloudWatchEvent) (string, error) {
	ecrEvent, err := h.unmarshalEvent(event.Detail)
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal event: %w", err)
	}

	h.logger.Debug(
		fmt.Sprintf("Received ECR scan event, repository: %v, imageDigest: %v", ecrEvent.RepositoryName, ecrEvent.ImageDigest),
	)

	imageMetadata, err := h.getImageMetadata(ctx, ecrEvent)
	if err != nil {
		return "", fmt.Errorf("failed to get image metadata: %w", err)
	}

	scanOutputFindings, scanOutputSeverityCounts, scanOutputImageScanCompletedAt, err := h.getScanFindings(ctx, ecrEvent)
	if err != nil {
		return "", fmt.Errorf("failed to get scan findings: %w", err)
	}

	severities := h.getSeveritiesFromEnv()
	if err := h.validateSeverities(severities); err != nil {
		return "", fmt.Errorf("failed to validate severities: %w", err)
	}

	scanFindings, scanSeverityCounts := h.parseScanFindings(scanOutputFindings, scanOutputSeverityCounts, severities)
	report := h.createReport(ecrEvent, imageMetadata, scanFindings, scanSeverityCounts, scanOutputImageScanCompletedAt)

	jsonData, err := json.Marshal(report)
	if err != nil {
		return "", fmt.Errorf("failed to marshal report to JSON: %w", err)
	}

	for _, logCollector := range h.logCollectors {
		if err := logCollector.Index(ctx, jsonData); err != nil {
			return "", fmt.Errorf("failed to index with a logCollector: %w", err)
		}
	}

	return "Lambda was called successfully", nil
}
