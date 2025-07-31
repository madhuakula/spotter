# Spotter Admission Controller - Local Testing Guide

Complete guide for testing Spotter admission controller with kind cluster in one go.

## Prerequisites
- Docker
- kind 
- kubectl

## One-Command Setup

```bash
# Complete setup script
bash -c '
set -e
echo "🚀 Setting up Spotter admission controller..."

# Create kind cluster
echo "📦 Creating kind cluster..."
kind create cluster --name spotter-test

# Build and load image  
echo "🔨 Building and loading image..."
docker build -f Dockerfile.admission -t spotter:latest .
docker save spotter:latest | kind load image-archive --name spotter-test /dev/stdin

# Generate certificates and deploy
echo "🔐 Deploying admission controller..."
cd deployments/admission-controller
./generate-local-certs.sh
kubectl apply -f local-deployment.yaml
kubectl apply -f local-webhook.yaml

# Wait for ready
echo "⏳ Waiting for ready..."
kubectl wait --for=condition=ready pod -l app=spotter-admission-controller -n spotter-system --timeout=60s

echo "✅ Setup complete! Run tests below."
'
```

## Quick Testing

### 1. Create test namespace
```bash
kubectl create namespace test-spotter
```

### 2. Test secure pod (should succeed)
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: test-spotter
spec:
  containers:
  - name: nginx
    image: nginx:1.20@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
    resources:
      requests:
        memory: "64Mi"
        cpu: "250m"
      limits:
        memory: "128Mi"
        cpu: "500m"
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
EOF
```

### 3. Test privileged pod (should be rejected)
```bash
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: test-spotter
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
EOF
```

### 4. Check results
```bash
# Check pods
kubectl get pods -n test-spotter

# Check logs for violations
kubectl logs -l app=spotter-admission-controller -n spotter-system --tail=20

# Check events for rejections
kubectl get events -n test-spotter --sort-by='.lastTimestamp'
```

## Expected Results

**Secure pod**: ✅ Created successfully  
**Privileged pod**: ❌ Rejected with security violations

**Log output shows**:
```
level=INFO msg="Resource passed security evaluation" kind=Pod name=secure-pod
level=ERROR msg="Security violations detected" kind=Pod name=privileged-pod total_violations=15 critical=3
```

## Manual Setup Steps (if needed)

### 1. Create cluster
```bash
kind create cluster --name spotter-test
```

### 2. Build image
```bash
docker build -f Dockerfile.admission -t spotter:latest .
docker save spotter:latest | kind load image-archive --name spotter-test /dev/stdin
```

### 3. Deploy
```bash
cd deployments/admission-controller
./generate-local-certs.sh
kubectl apply -f local-deployment.yaml
kubectl apply -f local-webhook.yaml
```

### 4. Verify
```bash
kubectl wait --for=condition=ready pod -l app=spotter-admission-controller -n spotter-system --timeout=60s
kubectl logs -l app=spotter-admission-controller -n spotter-system
```

## All-in-One Test Script

Save as `test-spotter.sh` and run with `bash test-spotter.sh`:

```bash
#!/bin/bash
set -e

echo "🧪 Testing Spotter admission controller..."

# Test namespace
kubectl create namespace test-spotter --dry-run=client -o yaml | kubectl apply -f -

# Test 1: Secure pod (should pass)
echo "✅ Testing secure pod..."
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
  namespace: test-spotter
spec:
  containers:
  - name: nginx
    image: nginx:1.20@sha256:10f14ffa93f8dedf1057897b745e5ac72ac5655c299dade0aa434c71557697ea
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
EOF

# Test 2: Privileged pod (should fail)
echo "❌ Testing privileged pod..."
kubectl apply -f - <<EOF || echo "Pod correctly rejected by admission controller"
apiVersion: v1
kind: Pod
metadata:
  name: privileged-pod
  namespace: test-spotter
spec:
  containers:
  - name: nginx
    image: nginx:latest
    securityContext:
      privileged: true
      runAsUser: 0
EOF

echo ""
echo "📊 Results:"
kubectl get pods -n test-spotter
echo ""
echo "🔍 Recent logs:"
kubectl logs -l app=spotter-admission-controller -n spotter-system --tail=10
```

## Monitoring

```bash
# Check status
kubectl get pods -n spotter-system

# View logs
kubectl logs -f -l app=spotter-admission-controller -n spotter-system

# Check webhook config
kubectl get validatingadmissionwebhook spotter-validating-webhook

# Health check
kubectl exec -n spotter-system deployment/spotter-admission-controller -- wget -qO- http://localhost:8080/health
```

## Troubleshooting

**Pod not starting**:
```bash
kubectl describe pod -n spotter-system -l app=spotter-admission-controller
```

**Image not found**:
```bash
docker save spotter:latest | kind load image-archive --name spotter-test /dev/stdin
```

**Certificate issues**:
```bash
cd deployments/admission-controller && ./generate-local-certs.sh
kubectl apply -f local-webhook.yaml
```

**Webhook not working**:
```bash
kubectl logs -l app=spotter-admission-controller -n spotter-system | grep "admission request"
```

## Cleanup

```bash
kubectl delete namespace test-spotter
kubectl delete -f local-webhook.yaml -f local-deployment.yaml
kind delete cluster --name spotter-test
```

## Key Features

- **165 security rules** loaded automatically
- **Validates**: pods, deployments, services, jobs, etc.
- **Excludes**: system namespaces (kube-system, etc.)
- **Mode**: CREATE operations only (not updates)
- **Logging**: Severity-based summaries with violation details
- **Failure policy**: Ignore (lenient for testing)

This guide provides everything needed to test the Spotter admission controller locally with kind cluster in a straightforward manner.
