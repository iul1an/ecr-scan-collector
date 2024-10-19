#!/bin/bash

set -euo pipefail

if [[ $# -ne 1 ]]; then
	echo "Usage: $0 PROJECT_NAME"
	exit 1
fi

PROJECT_NAME=$1

echo "tearing down lambda containers..."
docker inspect "$PROJECT_NAME" &>/dev/null && docker rm --force "$PROJECT_NAME"
docker inspect "opensearch-${PROJECT_NAME}" &>/dev/null && docker rm --force "opensearch-${PROJECT_NAME}"
docker inspect "opensearch-dashboards-${PROJECT_NAME}" &>/dev/null && docker rm --force "opensearch-dashboards-${PROJECT_NAME}"
docker image prune -a --filter "label=app=${PROJECT_NAME}" --force
docker network inspect "$PROJECT_NAME" &>/dev/null && docker network rm "$PROJECT_NAME"
docker volume inspect trivy &>/dev/null && docker volume rm trivy

exit 0
