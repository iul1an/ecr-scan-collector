package types

import (
	"context"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"
)

type EcrScanFinding struct {
	Name           *string
	Severity       types.FindingSeverity
	PackageName    *string `json:"PackageName,omitempty"`
	PackageVersion *string `json:"PackageVersion,omitempty"`
	Uri            *string `json:"Uri,omitempty"`
}

type ECRScanReport struct {
	RegistryId            *string `json:"RegistryId,omitempty"`
	RepositoryName        string
	ImagePushedAt         *time.Time
	ImageScanCompletedAt  *time.Time
	ImageDigest           string
	ImageTags             []string         `json:"ImageTags,omitempty"`
	ScanFindings          []EcrScanFinding `json:"ScanFindings,omitempty"`
	FindingSeverityCounts map[string]int32 `json:"FindingSeverityCounts,omitempty"`
	FindingsTotal         int
}

//nolint:lll //ok
type ECRAPIClient interface {
	DescribeImageScanFindings(ctx context.Context, params *ecr.DescribeImageScanFindingsInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImageScanFindingsOutput, error)
	DescribeImages(ctx context.Context, params *ecr.DescribeImagesInput, optFns ...func(*ecr.Options)) (*ecr.DescribeImagesOutput, error)
}
