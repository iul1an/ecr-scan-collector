# ECR Scan Collector

## Overview

ECR Scan Collector is an AWS Lambda function that collects, processes, and stores Amazon Elastic Container Registry (ECR) image **basic scan** reports.
It offers a flexible and extensible solution for handling ECR scan events, extracting relevant information, and storing results in various backends.

## Table of Contents

- [Features](#features)
- [Architecture](#architecture)
- [Prerequisites](#prerequisites)
- [Getting Started](#getting-started)
  - [Installation](#installation)
  - [Configuration](#configuration)
  - [Usage](#usage)
- [Development](#development)
  - [Setting Up the Development Environment](#setting-up-the-development-environment)
  - [Running Locally](#running-locally)
  - [Adding a New Log Collector](#adding-a-new-log-collector)
  - [Testing](#testing)
  - [Troubleshooting](#troubleshooting)
- [Deployment](#deployment)
- [Contributing](#contributing)
- [Notes](#notes)
- [License](#license)

## Features

- Processes ECR scan events from AWS CloudWatch
- Retrieves detailed image metadata and scan findings from ECR
- Supports multiple log collectors for flexible data storage options
- Configurable logging levels for easy debugging
- AWS IAM role assumption for enhanced security
- Modular design for easy extension and maintenance

## Architecture

The project structure:

```
ecr-scan-collector/
├── cmd
│   └── lambda/         # Main entry point for the Lambda function
├── go.mod
├── go.sum
├── internal
│   ├── collector/      # Log collector implementations
│   ├── handler/        # Lambda event handler logic
│   ├── logger/         # Custom logger with configurable levels
│   └── types/          # Shared data types
└── pkg
    └── awsutils/       # AWS-related utility functions
scripts/                # Makefile scripts          
Makefile                # Build and development commands
```

## Prerequisites

- Go 1.23 or later
- Docker and Docker Compose
- AWS CLI configured with appropriate permissions
- AWS account with ECR and Lambda services enabled

## Getting Started

### Installation

1. Clone the repository:
   ```
   git clone https://github.com/iul1an/ecr-scan-collector.git
   cd ecr-scan-collector/
   ```

2. Build the Lambda function:
   ```
   make build
   ```

### Configuration

Configure the Lambda function using these environment variables:

- `SEVERITY_LEVELS`: Comma separated list of finding severities (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `INFORMATIONAL`)
- `LOG_LEVEL`: Logging level (`DEBUG`, `INFO`, `WARN`, `ERROR`)
- `STDOUT_COLLECTOR`: Enable stdout collector if set to "true"
- `OPENSEARCH_ENDPOINT`: OpenSearch endpoint URL. Set it to enable the collector.
- `OPENSEARCH_USE_AWS`: Use AWS authentication for OpenSearch if "true"
- `OPENSEARCH_USERNAME`: OpenSearch username (if not using AWS auth)
- `OPENSEARCH_PASSWORD`: OpenSearch password (if not using AWS auth)
- `OPENSEARCH_INSECURE`: Skip TLS verification if "true" (not recommended for production)
- `OPENSEARCH_ASSUME_ROLE_ARN`: ARN of IAM role to assume for OpenSearch access, required if the domain is deployed in a different AWS account than the Lambda
- `ECR_ASSUME_ROLE_ARN`: ARN of IAM role to assume for ECR access, required when the repositories are deployed in a different AWS account than the Lambda

### Usage

1. Set up an EventBridge rule to trigger the Lambda function on ECR scan completion events.
2. The function will process incoming events, retrieve detailed information, and store results using configured collectors.
3. Monitor the function's CloudWatch logs for execution details and errors.

## Development

### Setting Up the Development Environment

1. Ensure you have all [prerequisites](#prerequisites) installed.
2. Configure AWS access by exporting `AWS_REGION`, `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN` (if needed)

### Running Locally

Use `make dev` to set up and run the project locally. This command:

1. Optionally deploys OpenSearch and OpenSearch Dashboards as containers
2. Builds and deploys a Lambda function container that connects to the specified OpenSearch deployment

#### Basic Usage

```bash
make dev
```

#### Configuration Options

You can customize the local deployment using environment variables:

- **Local OpenSearch v2 Deployment**
  ```bash
  DEPLOY_LOCAL_OPENSEARCH=true make dev
  ```

- **Local OpenSearch Deployment with target version**
  ```bash
  DEPLOY_LOCAL_OPENSEARCH=true OPENSEARCH_VERSION=2.15.0 make dev
  ```

- **Remote OpenSearch Connection**
  ```bash
  export OPENSEARCH_ENDPOINT=https://foo.bar:9200
  export OPENSEARCH_USER=jimmy
  export OPENSEARCH_PASSWORD=soSecureMuchWow1337
  make dev
  ```

- **Set Log Level**
  ```bash
  LOG_LEVEL=debug make dev
  ```

- **Specify ECR Scan Severity Level Filter**
  ```bash
  SEVERITY_LEVELS=critical,high make dev
  ```

- **AWS OpenSearch with IAM Role**
  ```bash
  export OPENSEARCH_ASSUME_ROLE_ARN=arn:aws:iam::123456789012:role/ecr-scan-collector-opensearch-access
  export OPENSEARCH_ENDPOINT=https://vpc-os-domain-e63rzdhmm.eu-west-1.es.amazonaws.com
  export OPENSEARCH_USE_AWS=true
  export SEVERITY_LEVELS=critical,high
  make dev
  ```

#### Combining Options

You can combine multiple options:

```bash
LOG_LEVEL=debug SEVERITY_LEVELS=critical,high STDOUT_COLLECTOR=true make dev
```

#### Local Service Access

When using local OpenSearch deployment (`DEPLOY_LOCAL_OPENSEARCH=true`):

- OpenSearch: http://localhost:9200
- OpenSearch Dashboards: http://localhost:5601

#### Calling the Lambda

1. Use `make invoke-lambda`.
2. Check Lambda logs: `docker logs -f ecr-scan-collector`.
3. Check OpenSearch: `curl -XGET http://localhost:9200/_cat/indices`.
4. Check OpenSearch Dashboards:
   - Go to http://localhost:5601
   - Create an Index Pattern: Dashboards Management -> Index Patterns -> Create Index Pattern -> pattern name: `ecr-scan-collector-*` -> Time field: `ImageScanCompletedAt`
   - Head over to "Discover" to check the logs

### Adding a New Log Collector

1. Create a new file in `internal/collector/` (e.g., `new_collector.go`).
2. Implement the `LogCollector` interface:
   ```go
   type LogCollector interface {
         Index(ctx context.Context, jsonData []byte) error
   }
   ```
3. Add configuration options in `cmd/lambda/main.go`.

### Testing

Run the test suite:

```bash
make unit-tests
make integration-tests
```

### Security scanning

You can scan the code for security vulnerabilities using Trivy:
```
make scan
```

### Troubleshooting

If you encounter issues:
1. Ensure Docker is running with necessary permissions.
2. Verify AWS CLI configuration and ECR access.
3. Check Lambda function logs in AWS Console or CloudWatch.

To clean up resources and stop local services:

```bash
make clean
```

## Deployment

1. Push the Lambda container image to an ECR repository:
2. Deploy the Lambda function using AWS CLI or AWS Console.

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. `make unit-tests`, `make integration-tests` and `make lint`
4. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
5. Push to the branch (`git push origin feature/AmazingFeature`)
6. Open a Pull Request

Please ensure your code adheres to the project's coding standards and includes appropriate tests.

## Notes

### Using Colima on macOS for Integration Tests

When running integration tests, the `testcontainers` Go library assumes the default Docker socket path: `/var/run/docker.sock`.
However, Colima uses a different path for the Docker socket. To ensure that `testcontainers` works correctly with Colima, you need to set some environment variables.

Run these commands before executing your tests:

```bash
export TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock
export DOCKER_HOST="unix://${HOME}/.colima/default/docker.sock"
```

More information [here](https://java.testcontainers.org/supported_docker_environment/)

## License

This project is open-source software licensed under the MIT License.

### What this means:

- ✅ Free to use, modify, and distribute
- ✅ Can be used for commercial purposes
- ✅ No warranty provided
- ℹ️ License and copyright notice must be included with the software

For the full license text, see the [LICENSE](LICENSE) file in this repository.

Contributions to this project are welcome and will be licensed under the same terms.
