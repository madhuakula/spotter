---
title: Cluster Scanning
description: Scan live Kubernetes clusters for security vulnerabilities and misconfigurations
---

Spotter can scan live Kubernetes clusters to identify security vulnerabilities and misconfigurations in running workloads. This guide covers cluster scanning capabilities, setup, and best practices.

Cluster scanning provides:

- **Live Resource Analysis**: Scan running pods, services, and configurations
- **Runtime Security**: Identify security issues in active workloads
- **Compliance Monitoring**: Continuous compliance validation
- **Drift Detection**: Compare running state with desired configurations
- **Multi-Cluster Support**: Scan multiple clusters from a single command

## Prerequisites

### Kubernetes Access

```bash
# Verify cluster access
kubectl cluster-info
kubectl get nodes

# Check current context
kubectl config current-context

# List available contexts
kubectl config get-contexts
```

### RBAC Permissions

Spotter requires read access to cluster resources:

```yaml
# spotter-rbac.yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: spotter-scanner
  namespace: spotter-system
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: spotter-scanner
rules:
- apiGroups: [""]
  resources:
    - pods
    - services
    - configmaps
    - secrets
    - serviceaccounts
    - persistentvolumes
    - persistentvolumeclaims
    - nodes
  verbs: ["get", "list"]
- apiGroups: ["apps"]
  resources:
    - deployments
    - daemonsets
    - statefulsets
    - replicasets
  verbs: ["get", "list"]
- apiGroups: ["networking.k8s.io"]
  resources:
    - networkpolicies
    - ingresses
  verbs: ["get", "list"]
- apiGroups: ["policy"]
  resources:
    - podsecuritypolicies
  verbs: ["get", "list"]
- apiGroups: ["rbac.authorization.k8s.io"]
  resources:
    - roles
    - rolebindings
    - clusterroles
    - clusterrolebindings
  verbs: ["get", "list"]
- apiGroups: ["security.openshift.io"]
  resources:
    - securitycontextconstraints
  verbs: ["get", "list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: spotter-scanner
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: spotter-scanner
subjects:
- kind: ServiceAccount
  name: spotter-scanner
  namespace: spotter-system
```

```bash
# Apply RBAC configuration
kubectl create namespace spotter-system
kubectl apply -f spotter-rbac.yaml

# Get service account token (for older clusters)
kubectl create token spotter-scanner -n spotter-system
```

## Basic Cluster Scanning

### Scan Entire Cluster

```bash
# Scan all resources in the cluster
spotter scan cluster

# Scan with specific severity threshold
spotter scan cluster --min-severity medium

# Scan and output to file
spotter scan cluster --output json --output-file cluster-scan.json
```

### Namespace-Specific Scanning

```bash
# Scan specific namespace
spotter scan cluster --namespace production

# Scan multiple namespaces
spotter scan cluster --namespace production,staging,development

# Exclude system namespaces
spotter scan cluster --exclude-namespace kube-system,kube-public,kube-node-lease

# Scan all namespaces except excluded ones
spotter scan cluster --all-namespaces --exclude-namespace kube-system
```

### Resource Type Filtering

```bash
# Scan only pods
spotter scan cluster --resource-types pods

# Scan specific resource types
spotter scan cluster --resource-types pods,services,deployments

# Exclude specific resource types
spotter scan cluster --exclude-resource-types secrets,configmaps
```

## Advanced Scanning Options

### Label and Annotation Filtering

```bash
# Scan resources with specific labels
spotter scan cluster --label-selector app=nginx

# Scan resources with multiple label conditions
spotter scan cluster --label-selector "app=nginx,environment=production"

# Scan resources with annotation filters
spotter scan cluster --annotation-selector "security.scan=enabled"

# Combine label and annotation selectors
spotter scan cluster \
  --label-selector "app=nginx" \
  --annotation-selector "security.scan=enabled"
```

### Field Selectors

```bash
# Scan only running pods
spotter scan cluster --field-selector status.phase=Running

# Scan pods on specific nodes
spotter scan cluster --field-selector spec.nodeName=worker-node-1

# Combine multiple field selectors
spotter scan cluster --field-selector "status.phase=Running,spec.nodeName=worker-node-1"
```

### Time-Based Filtering

```bash
# Scan resources created in the last hour
spotter scan cluster --created-after 1h

# Scan resources created before a specific date
spotter scan cluster --created-before 2024-01-01

# Scan resources in a time range
spotter scan cluster --created-after 2024-01-01 --created-before 2024-01-31
```

## Output Formats and Analysis

### JSON Output Analysis

```bash
# Scan and analyze results
spotter scan cluster --output json --output-file cluster-scan.json

# Count findings by severity
jq '.summary' cluster-scan.json

# List critical findings
jq '.findings[] | select(.severity == "critical") | {rule_id, resource_name, namespace}' cluster-scan.json

# Group findings by namespace
jq 'group_by(.namespace) | map({namespace: .[0].namespace, count: length})' cluster-scan.json

# Find specific rule violations
jq '.findings[] | select(.rule_id == "workload-security-privileged-containers")' cluster-scan.json
```

### SARIF Output for Security Tools

```bash
# Generate SARIF output for security platforms
spotter scan cluster --output sarif --output-file cluster-scan.sarif

# Upload to GitHub Security tab
gh api repos/:owner/:repo/code-scanning/sarifs \
  --method POST \
  --field sarif=@cluster-scan.sarif \
  --field ref=refs/heads/main
```

## Troubleshooting

### Common Issues

#### Permission Denied

```bash
# Check current user permissions
kubectl auth can-i get pods --all-namespaces
kubectl auth can-i list deployments

# Check service account permissions
kubectl auth can-i get pods --as=system:serviceaccount:spotter-system:spotter-scanner

# Debug RBAC issues
kubectl describe clusterrolebinding spotter-scanner
```

#### Connection Issues

```bash
# Test cluster connectivity
kubectl cluster-info
kubectl get nodes

# Check kubeconfig
kubectl config view
kubectl config current-context

# Test with verbose output
spotter scan cluster --namespace default --verbose
```
