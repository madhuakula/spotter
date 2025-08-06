---
title: CI/CD Integration
description: Integrate Spotter into your CI/CD pipelines for automated security scanning
---

Integrating Spotter into your CI/CD pipelines enables automated security scanning and policy enforcement throughout your development lifecycle. This guide covers integration patterns for popular CI/CD platforms and best practices for shift-left security.

## Overview

Spotter CI/CD integration provides:

- **Automated Security Scanning**: Scan manifests, Helm charts, and clusters
- **Policy Enforcement**: Block deployments that violate security policies
- **Security Reports**: Generate detailed security findings for review
- **Compliance Validation**: Ensure adherence to regulatory requirements
- **Developer Feedback**: Provide immediate feedback on security issues

## Integration Patterns

### 1. Pre-commit Hooks

Scan files before they're committed to version control:

```bash
#!/bin/bash
# .git/hooks/pre-commit

echo "Running Spotter security scan..."

# Get staged YAML files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM | grep -E '\.(yaml|yml)$')

if [ -n "$STAGED_FILES" ]; then
    # Scan staged files
    spotter scan manifests $STAGED_FILES \
        --min-severity medium \
        --fail-on-severity high \
        --output table
    
    if [ $? -ne 0 ]; then
        echo "❌ Security scan failed. Please fix the issues before committing."
        exit 1
    fi
    
    echo "✅ Security scan passed."
fi
```

### 2. Pull Request Validation

Scan changes in pull requests:

```yaml
# .github/workflows/pr-security-scan.yml
name: Security Scan

on:
  pull_request:
    paths:
      - '**/*.yaml'
      - '**/*.yml'
      - 'charts/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
      with:
        fetch-depth: 0
    
    - name: Get changed files
      id: changed-files
      uses: tj-actions/changed-files@v40
      with:
        files: |
          **/*.yaml
          **/*.yml
    
    - name: Install Spotter
      run: |
        wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-linux-amd64.tar.gz
        tar -xzf spotter-linux-amd64.tar.gz
        sudo mv spotter /usr/local/bin/
    
    - name: Scan changed files
      if: steps.changed-files.outputs.any_changed == 'true'
      run: |
        echo "Scanning files: ${{ steps.changed-files.outputs.all_changed_files }}"
        spotter scan manifests ${{ steps.changed-files.outputs.all_changed_files }} \
          --output sarif \
          --output-file security-results.sarif \
          --fail-on-severity high
    
    - name: Upload SARIF results
      if: always()
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: security-results.sarif
```

### 3. Build Pipeline Integration

Integrate into main build pipelines:

```yaml
# .github/workflows/build.yml
name: Build and Deploy

on:
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    outputs:
      scan-results: ${{ steps.scan.outputs.results }}
    steps:
    - uses: actions/checkout@v4
    
    - name: Security Scan
      id: scan
      run: |
        spotter scan manifests ./k8s/ \
          --output json \
          --output-file scan-results.json \
          --min-severity medium
        
        echo "results=$(cat scan-results.json | jq -c .)" >> $GITHUB_OUTPUT
    
    - name: Upload scan results
      uses: actions/upload-artifact@v3
      with:
        name: security-scan-results
        path: scan-results.json
  
  deploy:
    needs: security-scan
    runs-on: ubuntu-latest
    if: success()
    steps:
    - name: Deploy to staging
      run: |
        echo "Deploying to staging..."
        # Deployment logic here
```

## Platform-Specific Integrations

### GitHub Actions

#### Basic Integration

```yaml
name: Spotter Security Scan

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    
    steps:
    - name: Checkout code
      uses: actions/checkout@v4
    
    - name: Run Spotter Scan
      uses: madhuakula/spotter-action@v1
      with:
        scan-type: 'manifests'
        target: './k8s/'
        output-format: 'sarif'
        fail-on-severity: 'high'
        config-file: '.spotter.yaml'
    
    - name: Upload results to GitHub Security
      uses: github/codeql-action/upload-sarif@v2
      if: always()
      with:
        sarif_file: spotter-results.sarif
```

#### Advanced GitHub Action

```yaml
name: Advanced Security Pipeline

on:
  workflow_dispatch:
    inputs:
      environment:
        description: 'Target environment'
        required: true
        default: 'staging'
        type: choice
        options:
        - staging
        - production

jobs:
  security-scan:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        scan-type: [manifests, helm, cluster]
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Setup Kubernetes
      if: matrix.scan-type == 'cluster'
      uses: azure/setup-kubectl@v3
    
    - name: Configure kubeconfig
      if: matrix.scan-type == 'cluster'
      run: |
        echo "${{ secrets.KUBECONFIG }}" | base64 -d > $HOME/.kube/config
    
    - name: Scan ${{ matrix.scan-type }}
      run: |
        case "${{ matrix.scan-type }}" in
          "manifests")
            spotter scan manifests ./k8s/ --config .spotter-${{ github.event.inputs.environment }}.yaml
            ;;
          "helm")
            spotter scan helm ./charts/ --values values-${{ github.event.inputs.environment }}.yaml
            ;;
          "cluster")
            spotter scan cluster --namespace ${{ github.event.inputs.environment }}
            ;;
        esac
```

### GitLab CI

```yaml
# .gitlab-ci.yml
stages:
  - security-scan
  - build
  - deploy

variables:
  SPOTTER_VERSION: "latest"
  SPOTTER_CONFIG: ".spotter.yaml"

.spotter-scan: &spotter-scan
  image: alpine:latest
  before_script:
    - apk add --no-cache wget tar
    - wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-linux-amd64.tar.gz
    - tar -xzf spotter-linux-amd64.tar.gz
    - mv spotter /usr/local/bin/

security-scan-manifests:
  <<: *spotter-scan
  stage: security-scan
  script:
    - spotter scan manifests ./manifests/ 
        --config $SPOTTER_CONFIG 
        --output json 
        --output-file security-results.json 
        --fail-on-severity high
  artifacts:
    reports:
      junit: security-results.json
    expire_in: 1 week
  only:
    changes:
      - manifests/**/*
      - charts/**/*

security-scan-helm:
  <<: *spotter-scan
  stage: security-scan
  script:
    - |
      for chart in charts/*/; do
        echo "Scanning chart: $chart"
        spotter scan helm "$chart" 
          --values "$chart/values-${CI_ENVIRONMENT_NAME}.yaml" 
          --output json 
          --fail-on-severity medium
      done
  only:
    changes:
      - charts/**/*

deploy-staging:
  stage: deploy
  script:
    - echo "Deploying to staging..."
  environment:
    name: staging
  dependencies:
    - security-scan-manifests
    - security-scan-helm
  only:
    - develop

deploy-production:
  stage: deploy
  script:
    - echo "Deploying to production..."
  environment:
    name: production
  dependencies:
    - security-scan-manifests
    - security-scan-helm
  when: manual
  only:
    - main
```
