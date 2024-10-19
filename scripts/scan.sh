#!/usr/bin/env bash

# Strict mode
set -euo pipefail

# Function to display usage
usage() {
    echo "Usage: $0 SRCDIR LAMBDA_IMAGE"
    exit 1
}

# Check if correct number of arguments are provided
if [[ $# -ne 2 ]]; then
    usage
fi

# Main script execution starts here

SRCDIR="$1"
LAMBDA_IMAGE="$2"
TRIVY_IMAGE=aquasec/trivy:latest

docker volume inspect trivy &>/dev/null || docker volume create trivy

# Scan code
echo -e "\n#######\nScanning code..."
docker run --rm -v "$SRCDIR":/mnt -v trivy:/.cache "$TRIVY_IMAGE" \
    fs --cache-dir /.cache --severity HIGH,CRITICAL --ignore-unfixed /mnt

# Scan container image
if docker image inspect "$LAMBDA_IMAGE" &>/dev/null; then
    echo -e "\n#######\nScanning container image ${LAMBDA_IMAGE}..."
    docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy:/.cache/ "$TRIVY_IMAGE" \
        image --cache-dir /.cache --severity HIGH,CRITICAL --ignore-unfixed "$LAMBDA_IMAGE"
fi
