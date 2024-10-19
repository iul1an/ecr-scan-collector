#!/usr/bin/env bash

# Strict mode
set -euo pipefail
IFS=$'\n\t'

# Function to display usage
usage() {
    echo "Usage: $0 PROJECT_NAME"
    echo "Set DEPLOY_LOCAL_OPENSEARCH=true to deploy OpenSearch locally"
    exit 1
}

# Function to validate environment variables
validate_env_vars() {
    local var_names=("$@")
    local missing_vars=()
    for var_name in "${var_names[@]}"; do
        if [ -z "${!var_name:-}" ]; then
            missing_vars+=("$var_name")
        fi
    done
    if [ ${#missing_vars[@]} -ne 0 ]; then
        echo "Error: The following required environment variables are missing or empty:"
        printf "  - %s\n" "${missing_vars[@]}"
        exit 1
    fi
    echo "All required environment variables are set."
}

# Check if correct number of arguments are provided
if [[ $# -ne 1 ]]; then
    usage
fi

PROJECT_NAME="$1"
IMAGE_NAME="$PROJECT_NAME"
IMAGE_TAG=$(git log -1 --pretty=%h)

# Define and validate required environment variables
required_vars=(
    "AWS_REGION"
    "AWS_ACCESS_KEY_ID"
    "AWS_SECRET_ACCESS_KEY"
)
validate_env_vars "${required_vars[@]}"

# Create a temporary file for environment variables
ENV_FILE=$(mktemp)
trap 'rm -f "$ENV_FILE"' EXIT

docker network inspect "$PROJECT_NAME" &>/dev/null || docker network create "$PROJECT_NAME"

if [ "${DEPLOY_LOCAL_OPENSEARCH:-false}" = "true" ] && ! env | grep -q OPENSEARCH_ENDPOINT=; then
    OPENSEARCH_VERSION=${OPENSEARCH_VERSION:-2}
    echo -e "\nDeploying OpenSearch and OpenSearch Dashboards locally...\n"


    docker inspect "opensearch-${PROJECT_NAME}" &>/dev/null || {
        docker run -d --rm \
            -p 9200:9200 \
            --network="$PROJECT_NAME" \
            -e discovery.type=single-node \
            -e DISABLE_SECURITY_PLUGIN=true \
            -e DISABLE_INSTALL_DEMO_CONFIG=true \
            --name "opensearch-${PROJECT_NAME}" \
            opensearchproject/opensearch:"${OPENSEARCH_VERSION}"
    }

    docker inspect "opensearch-dashboards-${PROJECT_NAME}" &>/dev/null || \
        docker run -d --rm \
            -p 5601:5601 \
            --network="$PROJECT_NAME" \
            -e OPENSEARCH_HOSTS='["http://opensearch-'"${PROJECT_NAME}"':9200"]' \
            -e DISABLE_SECURITY_DASHBOARDS_PLUGIN=true \
            --name "opensearch-dashboards-${PROJECT_NAME}" \
            opensearchproject/opensearch-dashboards:"${OPENSEARCH_VERSION}"

    echo "OpenSearch: http://localhost:9200"
    echo "OpenSearch Dashboards: http://localhost:5601"
    echo
    echo "OPENSEARCH_ENDPOINT=http://opensearch-${PROJECT_NAME}:9200" >> "$ENV_FILE"
fi

# Enable stdout collector by default
if ! env | grep -q "STDOUT_COLLECTOR="; then
   echo STDOUT_COLLECTOR="true" >> "$ENV_FILE"
fi

# Populate environment file
env | grep -E "^(AWS_REGION=|AWS_ACCESS_KEY_ID=|AWS_SECRET_ACCESS_KEY=|AWS_SESSION_TOKEN=|LOG_LEVEL=|OPENSEARCH_|STDOUT_COLLECTOR=|SEVERITY_LEVELS=)" >> "$ENV_FILE"

# Remove existing container if it exists
if docker inspect "$PROJECT_NAME" &>/dev/null; then
    docker rm --force "$PROJECT_NAME"
fi

# Run the Docker container
echo "Starting Docker container for $PROJECT_NAME..."
if ! docker run --rm -d \
    -p 8080:8080 \
    --network="$PROJECT_NAME" \
    --name "$PROJECT_NAME" \
    --env-file "$ENV_FILE" \
    --entrypoint /app/aws-lambda-rie "${IMAGE_NAME}:${IMAGE_TAG}" \
    /app/lambda; then
    echo "Error: Failed to start Docker container"
    exit 1
fi

echo "Container started successfully. Lambda is running on http://localhost:8080/2015-03-31/functions/function/invocations"
