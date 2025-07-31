# Spotter - Universal Kubernetes Security Engine
# Minimal Makefile for building and releasing

.PHONY: help build test lint clean docker-build docker-push release

# Variables
APP_NAME := spotter
GO_VERSION := 1.24
DOCKER_REGISTRY := ghcr.io
DOCKER_IMAGE := $(DOCKER_REGISTRY)/madhuakula/$(APP_NAME)
VERSION := $(shell git describe --tags --always --dirty)
COMMIT := $(shell git rev-parse --short HEAD)
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -s -w \
	-X github.com/madhuakula/spotter/pkg/version.Version=$(VERSION) \
	-X github.com/madhuakula/spotter/pkg/version.Commit=$(COMMIT) \
	-X github.com/madhuakula/spotter/pkg/version.Date=$(DATE)

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

build: ## Build the binary
	@echo "Building $(APP_NAME)..."
	go build -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) .

test: ## Run tests
	@echo "Running tests..."
	go test -v ./...

lint: ## Run linter
	@echo "Running linter..."
	golangci-lint run

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/ dist/

docker-build: ## Build Docker image
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(VERSION) -t $(DOCKER_IMAGE):latest .

docker-push: docker-build ## Push Docker image
	@echo "Pushing Docker image..."
	docker push $(DOCKER_IMAGE):$(VERSION)
	docker push $(DOCKER_IMAGE):latest

release: ## Create release with goreleaser
	@echo "Creating release..."
	goreleaser release --clean

release-snapshot: ## Create snapshot release
	@echo "Creating snapshot release..."
	goreleaser release --snapshot --clean

.DEFAULT_GOAL := help