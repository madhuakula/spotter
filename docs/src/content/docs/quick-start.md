---
title: Quick Start
description: Get started with Spotter in minutes
---

This guide will help you get up and running with Spotter in just a few minutes. We'll cover the most common use cases and show you how to perform your first security scans.

## Prerequisites

Before starting, make sure you have:

- Spotter installed ([Installation Guide](/installation/))
- Access to a Kubernetes cluster (for cluster scanning)
- Some Kubernetes YAML files (for manifest scanning)

## Your First Scan

### 1. Scan a Simple Manifest

Let's start with a basic example. Create a file called `test-pod.yaml`:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
  namespace: default
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true
      runAsRoot: true
    env:
    - name: SECRET_KEY
      value: "super-secret-password"
```

Now scan it with Spotter:

```bash
spotter scan manifests test-pod.yaml
```

You should see several security findings, including:
- Container running in privileged mode
- Missing security context configurations
- Missing resouce limits configurations

### 2. Understanding the Output

Spotter's default table output shows:

```bash
❯ spotter scan manifests test-pod.yaml
🔍 Scanning resources [████████████████████████████████████████████████████████████████████████████████] 1/1 (100.0%) Completed in 0s
================================
  Spotter Security Scan Report
================================

Enhanced Scan Summary
════════════════════════════════════════════════════════════════════════════════
┌───────────────────────────┬───────────────────────────┐
│ Rules Evaluated           │ 142                       │
│ Total Evaluations         │ 87                        │
│ Failed Evaluations        │ 25                        │
│ Failure Rate              │ 28.7%                     │
│ Resources Scanned         │ 1                         │
│ Scan Duration             │ 21ms                      │
└───────────────────────────┴───────────────────────────┘

Category-wise Security Score
══════════════════════════════════════════════════════════════════════════════════════════
┌───────────────────────────────────────┬────────────────┬────────────────┬────────────────┬──────────────┐
│ Category                              │ Failed         │ Total          │ Score          │ Grade        │
├───────────────────────────────────────┼────────────────┼────────────────┼────────────────┼──────────────┤
│ Network & Traffic Security            │ 1              │ 1              │ 0.0%           │ F            │
│ Configuration & Resource Hygiene      │ 7              │ 8              │ 12.5%          │ F            │
│ Supply Chain & Image Security         │ 3              │ 4              │ 25.0%          │ F            │
│ Workload Security                     │ 9              │ 16             │ 43.8%          │ F            │
│ Access Control                        │ 4              │ 16             │ 75.0%          │ C+           │
│ Platform & Infrastructure Security    │ 1              │ 33             │ 97.0%          │ A+           │
│ Audit, Logging & Compliance           │ 0              │ 6              │ 100.0%         │ A+           │
│ Secrets & Data Protection             │ 0              │ 3              │ 100.0%         │ A+           │
└───────────────────────────────────────┴────────────────┴────────────────┴────────────────┴──────────────┘

Severity-wise Security Analysis
═════════════════════════════════════════════════════════════════════════════════════
┌───────────────────┬────────────────┬────────────────┬────────────────┐
│ Severity          │ Failed         │ Total          │ Failure %      │
├───────────────────┼────────────────┼────────────────┼────────────────┤
│ CRITICAL          │ 4              │ 30             │ 13.3%          │
│ HIGH              │ 6              │ 32             │ 18.8%          │
│ MEDIUM            │ 15             │ 24             │ 62.5%          │
│ LOW               │ 0              │ 1              │ 0.0%           │
└───────────────────┴────────────────┴────────────────┴────────────────┘

Resource Grouping Analysis
═══════════════════════════════════════════════════════════════════════════════════════════════
┌─────────────────────────────────────┬────────────────┬────────────────┬────────────────┬────────────────┐
│ Resource Type                       │ Failed         │ Total          │ Failure %      │ Risk Level     │
├─────────────────────────────────────┼────────────────┼────────────────┼────────────────┼────────────────┤
│ Pod                                 │ 25             │ 87             │ 28.7%          │ LOW            │
└─────────────────────────────────────┴────────────────┴────────────────┴────────────────┴────────────────┘

🔍 Top Security Findings
--------------------------------------------------------------------------------

🔴 CRITICAL (4 findings)
──────────────────────────────────────────────────
[1] [CRITICAL] Privilege Escalation Allowed
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Containers must not run with allowPrivilegeEscalation=true

[2] [CRITICAL] No Drop Capabilities for Containers
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Containers should explicitly drop all capabilities by default and only a...

[3] [CRITICAL] Container Is Privileged
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Containers should not run in privileged mode, as this grants all capabil...

  ... and 1 more rules

🟠 HIGH (6 findings)
──────────────────────────────────────────────────
[4] [HIGH] Pod Without Seccomp Profile
   Resource: Pod/insecure-pod
   Issue: Security rule violation: All pods must define seccompProfile

[5] [HIGH] NET_RAW Capabilities Not Being Dropped
   Resource: Pod/insecure-pod
   Issue: Security rule violation: NET_RAW capability must be dropped

[6] [HIGH] Image Without Digest
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Container images should be referenced by digest rather than by tag to en...

  ... and 3 more rules

🟡 MEDIUM (15 findings)
──────────────────────────────────────────────────
[7] [MEDIUM] Using Unrecommended Namespace
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Pods should not be deployed in the `default`, `kube-system`, or `kube-pu...

[8] [MEDIUM] Invalid Image Tag
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Container image tags should be specific and not use mutable tags like 'l...

[9] [MEDIUM] Memory Limits Not Defined
   Resource: Pod/insecure-pod
   Issue: Security rule violation: Containers should have memory limits defined to prevent excessive memory...

  ... and 12 more rules
... and 16 more security findings
Use --verbose flag to see all findings or filter by --min-severity

Useful Commands:
------------------------------------------------------------
   • Filter by severity: spotter scan cluster --min-severity=high
   • Export results: spotter scan cluster --output=json --output-file=results.json
   • Validate rules: spotter rules validate ./rules
   • Get help: spotter --help
```

### 3. Get Detailed Information

For more details about the findings, use JSON output:

```bash
spotter scan manifests test-pod.yaml --verbose
```

This provides complete information including:
- Rule descriptions
- Remediation steps
- CWE mappings
- Regulatory compliance mappings

## Common Scanning Scenarios

### Scan a Directory of Manifests

```bash
# Scan all YAML files in a directory
spotter scan manifests ./k8s-manifests/
```

### Scan a Live Kubernetes Cluster

```bash
# Scan the entire cluster
spotter scan cluster

# Scan specific namespace
spotter scan cluster --namespace production

# Scan specific resource types
spotter scan cluster --resource-types pods,services,deployments
```

### Scan Helm Charts

```bash
# Scan a Helm chart
spotter scan helm ./my-chart

# Scan with custom values
spotter scan helm ./my-chart --values values-prod.yaml

# Scan a specific release
spotter scan helm --release my-release --namespace production
```

## Filtering and Customization

### Filter by Severity

```bash
# Show only critical and high severity findings
spotter scan manifests test-pod.yaml --min-severity high

# Show only critical findings
spotter scan manifests test-pod.yaml --min-severity critical
```

### Filter by Categories

```bash
# Scan only workload security rules
spotter scan manifests test-pod.yaml --categories "Workload Security"

# Scan multiple categories
spotter scan manifests test-pod.yaml --categories "Workload Security,Access Control"
```

## Output Formats

### Table Output (Default)

```bash
spotter scan manifests test-pod.yaml
```

### JSON Output

```bash
spotter scan manifests test-pod.yaml --output json
```

### YAML Output

```bash
spotter scan manifests test-pod.yaml --output yaml
```

### SARIF Output (for CI/CD)

```bash
spotter scan manifests test-pod.yaml --output sarif
```

### Save to File

```bash
# Save results to file
spotter scan manifests test-pod.yaml --output json --output-file results.json

# Disable color for file output
spotter scan manifests test-pod.yaml --no-color --output-file results.txt
```

## CI/CD Integration

### GitHub Actions Example

Create `.github/workflows/security-scan.yml`:

```yaml
name: Security Scan

on:
  pull_request:
    paths:
      - 'k8s/**'
      - 'manifests/**'

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v4
    
    - name: Install Spotter
      run: |
        wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-linux-amd64.tar.gz
        tar -xzf spotter-linux-amd64.tar.gz
        sudo mv spotter /usr/local/bin/
    
    - name: Scan Kubernetes Manifests
      run: |
        spotter scan manifests ./k8s/ --output sarif --output-file results.sarif
    
    - name: Upload SARIF results
      uses: github/codeql-action/upload-sarif@v2
      with:
        sarif_file: results.sarif
```

### GitLab CI Example

Add to `.gitlab-ci.yml`:

```yaml
security-scan:
  stage: test
  image: alpine:latest
  before_script:
    - apk add --no-cache wget tar
    - wget https://github.com/madhuakula/spotter/releases/latest/download/spotter-linux-amd64.tar.gz
    - tar -xzf spotter-linux-amd64.tar.gz
    - mv spotter /usr/local/bin/
  script:
    - spotter scan manifests ./manifests/ --output json --output-file security-results.json
  artifacts:
    reports:
      junit: security-results.json
    expire_in: 1 week
  only:
    changes:
      - manifests/**/*
```

## Real-World Examples

### Example 1: Secure Pod Configuration

Here's how to fix the insecure pod from our first example:

```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: default
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 2000
  containers:
  - name: app
    image: nginx:1.21.6  # Specific version instead of latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
      capabilities:
        drop:
        - ALL
    env:
    - name: SECRET_KEY
      valueFrom:
        secretKeyRef:
          name: app-secrets
          key: secret-key
    resources:
      limits:
        memory: "128Mi"
        cpu: "100m"
      requests:
        memory: "64Mi"
        cpu: "50m"
```

### Example 2: Deployment with Security Best Practices

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-app
  namespace: production
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-app
  template:
    metadata:
      labels:
        app: secure-app
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: app
        image: myregistry.com/secure-app:v1.2.3
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          runAsUser: 1000
          capabilities:
            drop:
            - ALL
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 5
        resources:
          limits:
            memory: "512Mi"
            cpu: "500m"
          requests:
            memory: "256Mi"
            cpu: "250m"
```

## Next Steps

Now that you've completed the quick start:

1. **Explore Rules**: Learn about [Built-in Security Rules](/rules/builtin/)
2. **Custom Rules**: Create [Custom Security Rules](/rules/custom/)
3. **Deployment**: Set up [Admission Controller](/deployment/admission-controller/)
4. **CLI Reference**: Browse the complete [CLI Documentation](/cli/)

## Getting Help

If you encounter issues:

- Browse [GitHub Issues](https://github.com/madhuakula/spotter/issues)
- Join the community discussions
- Review the [FAQ](/faq/)

Happy scanning! 🔍