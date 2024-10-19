package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/lambda"
	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"

	"github.com/iul1an/ecr-scan-collector/internal/collector"
	"github.com/iul1an/ecr-scan-collector/internal/handler"
	"github.com/iul1an/ecr-scan-collector/internal/logger"
	"github.com/iul1an/ecr-scan-collector/pkg/awsutils"
)

const (
	lambdaTimeout = 5 * time.Minute

	envLogLevel             = "LOG_LEVEL"
	envOpenSearchEndpoint   = "OPENSEARCH_ENDPOINT"
	envOpenSearchUseAWS     = "OPENSEARCH_USE_AWS"
	envOpenSearchUsername   = "OPENSEARCH_USERNAME"
	envOpenSearchPassword   = "OPENSEARCH_PASSWORD"
	envOpenSearchInsecure   = "OPENSEARCH_INSECURE"
	envOpenSearchAssumeRole = "OPENSEARCH_ASSUME_ROLE_ARN"
	envStdoutCollector      = "STDOUT_COLLECTOR"
	envEcrAssumeRole        = "ECR_ASSUME_ROLE_ARN"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), lambdaTimeout)
	defer cancel()

	newLogger := initLogger()

	awsCfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		newLogger.Error("Failed to load AWS config: %v", err)
		return
	}

	ecrClient, err := setupECRClient(ctx, awsCfg)
	if err != nil {
		newLogger.Error("Failed to setup ECR client: %v", err)
		return
	}

	collectors, err := setupCollectors(ctx, awsCfg, newLogger)
	if err != nil {
		newLogger.Error("Failed to setup collectors: %v", err)
		return
	}

	h := handler.NewLambdaHandler(ecrClient, newLogger, collectors)
	lambda.Start(h.HandleRequest)
}

func initLogger() *logger.Logger {
	logLevelStr := strings.ToUpper(os.Getenv(envLogLevel))
	logLevel := logger.GetLogLevelFromString(logLevelStr)
	return logger.NewLogger(logLevel)
}

func setupECRClient(ctx context.Context, awsCfg aws.Config) (*ecr.Client, error) {
	if roleArn := os.Getenv(envEcrAssumeRole); roleArn != "" {
		sessionName := "ecr-session-" + time.Now().Format("20060102150405")
		assumedCfg, err := awsutils.AssumeRole(ctx, awsCfg, roleArn, sessionName)
		if err != nil {
			return nil, fmt.Errorf("failed to assume IAM role: %w", err)
		}
		return ecr.NewFromConfig(assumedCfg), nil
	}
	return ecr.NewFromConfig(awsCfg), nil
}

func setupCollectors(ctx context.Context, awsCfg aws.Config, newLogger *logger.Logger) ([]collector.LogCollector, error) {
	var collectors []collector.LogCollector

	// OpenSearch
	opensearchEndpoint := os.Getenv(envOpenSearchEndpoint)
	if opensearchEndpoint != "" {
		osCollector, err := initializeOpenSearchCollector(ctx, opensearchEndpoint, awsCfg, newLogger)
		if err != nil {
			return nil, fmt.Errorf("failed to initialize OpenSearch collector: %w", err)
		}
		collectors = append(collectors, osCollector)
		newLogger.Info("OpenSearch collector added.")
	}

	// stdout
	if stdoutCollector := os.Getenv(envStdoutCollector); stdoutCollector != "" {
		collectors = append(collectors, collector.NewStdoutCollector(newLogger))
		newLogger.Info("Stdout collector added.")
	}

	if len(collectors) == 0 {
		return nil, errors.New("no collectors configured")
	}

	return collectors, nil
}

func initializeOpenSearchCollector(
	ctx context.Context, endpoint string, cfg aws.Config, newLogger *logger.Logger,
) (*collector.OpenSearchCollector, error) {
	useAWS, _ := strconv.ParseBool(os.Getenv(envOpenSearchUseAWS))
	username := os.Getenv(envOpenSearchUsername)
	password := os.Getenv(envOpenSearchPassword)
	insecure, _ := strconv.ParseBool(os.Getenv(envOpenSearchInsecure))
	openSearchAwsCfg := cfg.Copy()

	if roleArn := os.Getenv(envOpenSearchAssumeRole); roleArn != "" && useAWS {
		sessionName := "opensearch-session-" + time.Now().Format("20060102150405")
		var assumeErr error
		openSearchAwsCfg, assumeErr = awsutils.AssumeRole(ctx, cfg, roleArn, sessionName)
		if assumeErr != nil {
			return nil, fmt.Errorf("failed to assume IAM role: %w", assumeErr)
		}
	}

	osCollector, err := collector.NewOpenSearchCollector(endpoint, openSearchAwsCfg, newLogger, useAWS, username, password, insecure)
	if err != nil {
		return nil, fmt.Errorf("failed to create OpenSearch collector: %w", err)
	}

	newLogger.Info("OpenSearch collector added. UseAWS: %v, HasCredentials: %v, Insecure: %v",
		useAWS, username != "" && password != "", insecure)

	return osCollector, nil
}
