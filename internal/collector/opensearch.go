package collector

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/opensearch-project/opensearch-go/v2"
	"github.com/opensearch-project/opensearch-go/v2/opensearchapi"
	requestsigner "github.com/opensearch-project/opensearch-go/v2/signer/awsv2"

	"github.com/iul1an/ecr-scan-collector/internal/logger"
)

const (
	EnvOpenSearchIndexName = "OPENSEARCH_INDEX_NAME"
)

type OpenSearchCollector struct {
	endpoint  string
	awsConfig aws.Config
	logger    *logger.Logger
	useAWS    bool
	username  string
	password  string
	insecure  bool
}

func NewOpenSearchCollector(
	endpoint string, awsConfig aws.Config, l *logger.Logger, useAWS bool, username, password string, insecure bool,
) (*OpenSearchCollector, error) {
	if endpoint == "" {
		return nil, errors.New("OpenSearch endpoint is not set")
	}

	return &OpenSearchCollector{
		endpoint:  endpoint,
		awsConfig: awsConfig,
		logger:    l,
		useAWS:    useAWS,
		username:  username,
		password:  password,
		insecure:  insecure,
	}, nil
}

func (o *OpenSearchCollector) Index(ctx context.Context, jsonData []byte) error {
	indexName := o.getIndexName()
	o.logger.Debug(fmt.Sprintf("Indexing to OpenSearch, endpoint: %s, index: %s", o.endpoint, indexName))

	client, err := o.createClient()
	if err != nil {
		return fmt.Errorf("failed to create OpenSearch client: %w", err)
	}

	req := opensearchapi.IndexRequest{
		Index: indexName,
		Body:  strings.NewReader(string(jsonData)),
	}
	res, err := req.Do(ctx, client)
	if err != nil {
		return fmt.Errorf("failed to execute index request: %w", err)
	}
	defer o.closeResponseBody(res)

	if res.IsError() {
		body, _ := io.ReadAll(res.Body)
		return fmt.Errorf("error indexing document: status: %s, body: %s", res.Status(), body)
	}

	var r map[string]interface{}
	if err := json.NewDecoder(res.Body).Decode(&r); err != nil {
		return fmt.Errorf("error parsing the response body: %w", err)
	}

	if r["result"] != "created" && r["result"] != "updated" {
		return fmt.Errorf("unexpected result when indexing document: %v", r["result"])
	}

	o.logger.Info(fmt.Sprintf("ECR scan report successfully inserted in OpenSearch, id: %s", r["_id"]))

	return nil
}

func (o *OpenSearchCollector) getIndexName() string {
	date := time.Now().Format("2006.01.02")
	if customName := os.Getenv(EnvOpenSearchIndexName); customName != "" {
		return fmt.Sprintf("%s-%s", customName, date)
	}
	return "ecr-scan-reports-" + date
}

func (o *OpenSearchCollector) createClient() (*opensearch.Client, error) {
	if o.useAWS {
		return o.createAWSClient()
	}
	return o.createNonAWSClient()
}

func (o *OpenSearchCollector) createAWSClient() (*opensearch.Client, error) {
	signer, err := requestsigner.NewSignerWithService(o.awsConfig, "es")
	if err != nil {
		return nil, fmt.Errorf("failed to create AWS signer: %w", err)
	}

	return opensearch.NewClient(opensearch.Config{
		Addresses: []string{o.endpoint},
		Signer:    signer,
	})
}

func (o *OpenSearchCollector) createNonAWSClient() (*opensearch.Client, error) {
	config := opensearch.Config{
		Addresses: []string{o.endpoint},
	}

	if o.username != "" && o.password != "" {
		config.Username = o.username
		config.Password = o.password
	}

	if o.insecure {
		config.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec //ok
		}
	}

	return opensearch.NewClient(config)
}

func (o *OpenSearchCollector) closeResponseBody(res *opensearchapi.Response) {
	if err := res.Body.Close(); err != nil {
		o.logger.Error("Error closing response body, error: " + err.Error())
	}
}
