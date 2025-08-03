# Spotter - Kubernetes Security Scanner
# Simple OSS-standard Makefile

.DEFAULT_GOAL := help

# Variables
APP_NAME := spotter
REGISTRY := ghcr.io
NAMESPACE := madhuakula
IMAGE := $(REGISTRY)/$(NAMESPACE)/$(APP_NAME)

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build flags
LDFLAGS := -s -w \
	-X github.com/$(NAMESPACE)/$(APP_NAME)/pkg/version.Version=$(VERSION) \
	-X github.com/$(NAMESPACE)/$(APP_NAME)/pkg/version.Commit=$(COMMIT) \
	-X github.com/$(NAMESPACE)/$(APP_NAME)/pkg/version.Date=$(DATE)

# Build environment
CGO_ENABLED := 0
GOOS := linux
GOARCH := amd64

.PHONY: help build test clean lint fmt vet deps image push run install uninstall

help: ## Show this help message
	@echo "Spotter - Kubernetes Security Scanner"
	@echo ""
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the binary
	@echo "Building $(APP_NAME)..."
	CGO_ENABLED=$(CGO_ENABLED) GOOS=$(GOOS) GOARCH=$(GOARCH) \
		go build -ldflags="$(LDFLAGS)" -o bin/$(APP_NAME) .

test: ## Run tests
	@echo "Running tests..."
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests and show coverage
	@echo "Coverage report:"
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

clean: ## Clean build artifacts
	@echo "Cleaning..."
	rm -rf bin/ dist/ coverage.out coverage.html

lint: ## Run golangci-lint
	@echo "Running linter..."
	$(shell go env GOPATH)/bin/golangci-lint run ./...

fmt: ## Format code
	@echo "Formatting code..."
	go fmt ./...

vet: ## Run go vet
	@echo "Running go vet..."
	go vet ./...

deps: ## Download dependencies
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

image: ## Build container image
	@echo "Building container image $(IMAGE):$(VERSION)..."
	docker build \
		--build-arg ENABLE_VERSIONING=true \
		-t $(IMAGE):$(VERSION) \
		-t $(IMAGE):latest \
		.

push: image ## Build and push container image
	@echo "Pushing container image..."
	docker push $(IMAGE):$(VERSION)
	docker push $(IMAGE):latest

run: build ## Build and run the application
	@echo "Running $(APP_NAME)..."
	./bin/$(APP_NAME)

install: build ## Install binary to GOPATH/bin
	@echo "Installing $(APP_NAME)..."
	cp bin/$(APP_NAME) $(GOPATH)/bin/$(APP_NAME)

uninstall: ## Remove binary from GOPATH/bin
	@echo "Uninstalling $(APP_NAME)..."
	rm -f $(GOPATH)/bin/$(APP_NAME)

# Development targets
dev-setup: deps ## Setup development environment
	@echo "Setting up development environment..."
	@which golangci-lint >/dev/null || (echo "Installing golangci-lint..." && \
		curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(shell go env GOPATH)/bin)

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

release: check ## Run checks and build release artifacts
	@echo "Creating release..."
	goreleaser release --clean

release-snapshot: check ## Create snapshot release
	@echo "Creating snapshot release..."
	goreleaser release --snapshot --clean

# Local development with kind
kind-setup: ## Setup local kind cluster for testing
	@echo "Setting up kind cluster..."
	@if ! kind get clusters | grep -q spotter-test; then \
		kind create cluster --name spotter-test; \
	fi

kind-load: image ## Load image into kind cluster
	@echo "Loading image into kind cluster..."
	docker tag $(IMAGE):$(VERSION) spotter:latest
	docker save spotter:latest | kind load image-archive --name spotter-test /dev/stdin

kind-deploy: kind-load ## Deploy to kind cluster
	@echo "Deploying to kind cluster..."
	cd deployments/admission-controller && \
		./generate-local-certs.sh && \
		kubectl apply -f local-webhook.yaml && \
		kubectl apply -f local-deployment.yaml && \
		kubectl rollout restart deployment spotter-admission-controller -n spotter-system && \
		kubectl wait --for=condition=ready pod -l app=spotter-admission-controller -n spotter-system --timeout=15s


kind-test: kind-deploy ## Run tests in kind cluster
	@echo "Running tests in kind cluster..."
	kubectl create namespace test-spotter --dry-run=client -o yaml | kubectl apply -f -
	@echo "Testing complete. Check with: kubectl get pods -n test-spotter"

kind-clean: ## Clean up kind cluster
	@echo "Cleaning up kind cluster..."
	kind delete cluster --name spotter-test

# Print build info
info: ## Show build information
	@echo "Application: $(APP_NAME)"
	@echo "Version:     $(VERSION)"
	@echo "Commit:      $(COMMIT)"
	@echo "Date:        $(DATE)"
	@echo "Image:       $(IMAGE):$(VERSION)"
