package awsutils

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

const (
	defaultSessionDurationSeconds = 3600 // 1 hour
)

// AssumeRole assumes a role and returns a new AWS configuration with the temporary credentials.
func AssumeRole(ctx context.Context, awsCfg aws.Config, assumeRoleArn, sessionName string) (aws.Config, error) {
	stsClient := sts.NewFromConfig(awsCfg)

	creds := stscreds.NewAssumeRoleProvider(stsClient, assumeRoleArn, func(o *stscreds.AssumeRoleOptions) {
		o.RoleSessionName = sessionName
		o.Duration = time.Duration(defaultSessionDurationSeconds) * time.Second
	})

	assumedRoleConfig, err := config.LoadDefaultConfig(ctx, config.WithCredentialsProvider(creds))
	if err != nil {
		return aws.Config{}, fmt.Errorf("unable to load config with assumed role (ARN: %s, SessionName: %s): %w", assumeRoleArn, sessionName, err)
	}

	return assumedRoleConfig, nil
}
