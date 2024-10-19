SHELL := /bin/bash
SRCDIR := $(CURDIR)
COMMIT_ID := $(shell git rev-parse --short HEAD)
GOLANGCI_LINT_VERSION := v1.61.0
PROJECT_NAME := ecr-scan-collector
GO := go

.PHONY: all test unit-tests integration-tests integration-tests-no-cache lint scan build dev invoke-lambda clean help

all: build

test: unit-tests integration-tests

unit-tests:
	$(GO) test -v ./...

integration-tests:
	$(GO) test -v -tags=integration ./...

integration-tests-no-cache:
	$(GO) test -v -tags=integration -count=1 ./...

lint:
	@if ! command -v golangci-lint &> /dev/null; then \
		echo "Installing golangci-lint..." && \
		$(GO) install github.com/golangci/golangci-lint/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION); \
	fi
	golangci-lint run -v --fix ./...

scan:
	@scripts/scan.sh $(SRCDIR) $(PROJECT_NAME):$(COMMIT_ID)

build: unit-tests
	docker build --build-arg INCLUDE_RIE=true -t "$(PROJECT_NAME):$(COMMIT_ID)" --label app="$(PROJECT_NAME)" ./

dev: build
	@scripts/dev.sh $(PROJECT_NAME)

invoke-lambda:
	curl --fail --url "http://localhost:8080/2015-03-31/functions/function/invocations" -d @testdata/ecr_scan_completed_event.json

clean:
	@scripts/clean.sh $(PROJECT_NAME)
	$(GO) clean -testcache

help:
	@echo "Available targets:"
	@echo "  all               - Run the build target (default)"
	@echo "  test              - Run both unit and integration tests"
	@echo "  unit-tests        - Run unit tests"
	@echo "  integration-tests - Run integration tests"
	@echo "  integration-tests-no-cache - Run integration tests without cache"
	@echo "  lint              - Run linter and fix issues"
	@echo "  scan              - Run security scan"
	@echo "  build             - Build the Docker image"
	@echo "  dev               - Run development environment"
	@echo "  invoke-lambda     - Invoke Lambda function locally"
	@echo "  clean             - Clean up resources"
	@echo "  help              - Show this help message"
