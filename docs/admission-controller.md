# Spotter Admission Controller

The Spotter Admission Controller is a Kubernetes ValidatingAdmissionWebhook and MutatingAdmissionWebhook that enforces security policies in real-time as resources are created or updated in your cluster.

## Features

- 🛡️ **Real-time Security Validation**: Validates resources against built-in security rules as they're created/updated
- 🔍 **Two Operation Modes**: 
  - `validating`: Blocks non-compliant resources
  - `evaluating`: Logs violations but allows resources (audit mode)
- 📦 **Embedded Rules**: Uses built-in security rules embedded in the binary
- 🎯 **Selective Monitoring**: Configure specific namespaces and resource types to monitor
- 🔧 **Severity Filtering**: Set minimum severity levels for enforcement
- 📊 **Comprehensive Logging**: Detailed structured logging for all evaluations
- 🚀 **Production Ready**: Health checks, metrics, graceful shutdown

## Quick Start

### 1. Prerequisites

- Kubernetes cluster v1.16+
- Docker for building images
- kubectl configured
- OpenSSL for certificate generation

### 2. Build and Deploy

```bash
# Clone and enter the repository
cd spotter/

# Generate TLS certificates
make -f Makefile.admission generate-certs

# Build Docker image
make -f Makefile.admission build

# Push to your registry (update REGISTRY variable)
make -f Makefile.admission push REGISTRY=your-registry.com/your-org

# Deploy admission controller
make -f Makefile.admission deploy

# Deploy webhook configuration
make -f Makefile.admission deploy-webhook
```

### 3. Test the Admission Controller

```bash
# Test with a non-compliant pod (should be rejected)
make -f Makefile.admission test-validating

# Test with a compliant pod (should be accepted)
make -f Makefile.admission test-compliant

# Check admission controller logs
make -f Makefile.admission logs
```

## Configuration

### Server Modes

#### Validating Mode (Default)
```bash
spotter server --mode=validating
```
- Blocks resources that violate security rules
- Returns admission errors with violation details
- Recommended for production environments

#### Evaluating Mode
```bash
spotter server --mode=evaluating
```
- Allows all resources but logs violations
- Useful for monitoring and gradual rollout
- Good for understanding current compliance state

### Configuration Options

| Flag | Default | Description |
|------|---------|-------------|
| `--mode` | `validating` | Server mode: `validating` or `evaluating` |
| `--port` | `8443` | HTTPS server port |
| `--tls-cert-file` | `/etc/certs/tls.crt` | TLS certificate file path |
| `--tls-key-file` | `/etc/certs/tls.key` | TLS private key file path |
| `--namespaces` | `[]` | Namespaces to monitor (empty = all) |
| `--resource-types` | `[]` | Resource types to monitor (empty = all supported) |
| `--min-severity` | `medium` | Minimum severity level (`low`, `medium`, `high`, `critical`) |

### Namespace Filtering

Monitor specific namespaces:
```bash
spotter server --namespaces=production,staging,default
```

### Resource Type Filtering

Monitor specific resource types:
```bash
spotter server --resource-types=Pod,Deployment,Service
```

### Severity Filtering

Set minimum severity level:
```bash
spotter server --min-severity=high
```

## Supported Resources

The admission controller monitors these Kubernetes resources:

- **Core/v1**: Pods, Services, ServiceAccounts, ConfigMaps, Secrets
- **apps/v1**: Deployments, ReplicaSets, DaemonSets, StatefulSets
- **batch/v1**: Jobs, CronJobs
- **networking.k8s.io/v1**: NetworkPolicies, Ingresses
- **rbac.authorization.k8s.io/v1**: Roles, RoleBindings, ClusterRoles, ClusterRoleBindings

## Built-in Security Rules

The admission controller includes comprehensive built-in rules covering:

- **Access Control**: RBAC, service accounts, authentication
- **Workload Security**: Container security contexts, capabilities, privilege escalation
- **Network Security**: Network policies, service mesh configuration
- **Supply Chain**: Image security, registries, signatures
- **Configuration**: Resource limits, probes, best practices
- **Secrets Management**: Secret handling, encryption
- **Platform Security**: Node security, admission controllers

## Examples

### Example 1: Block Privileged Containers

```yaml
# This pod will be REJECTED
apiVersion: v1
kind: Pod
metadata:
  name: insecure-pod
spec:
  containers:
  - name: app
    image: nginx:latest
    securityContext:
      privileged: true  # ❌ Violation
      runAsUser: 0      # ❌ Violation
```

### Example 2: Compliant Pod

```yaml
# This pod will be ACCEPTED
apiVersion: v1
kind: Pod
metadata:
  name: secure-pod
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1001
    runAsGroup: 1001
  containers:
  - name: app
    image: nginx:1.21.6@sha256:abc123...  # ✅ Pinned by digest
    securityContext:
      allowPrivilegeEscalation: false    # ✅ Secure
      readOnlyRootFilesystem: true       # ✅ Secure
      runAsNonRoot: true                 # ✅ Secure
      capabilities:
        drop: ["ALL"]                    # ✅ Secure
    livenessProbe:                       # ✅ Health checks
      httpGet:
        path: /health
        port: 8080
    readinessProbe:                      # ✅ Health checks
      httpGet:
        path: /ready
        port: 8080
```

## Monitoring and Troubleshooting

### Health Checks

- **Liveness**: `GET /healthz`
- **Readiness**: `GET /readyz`
- **Metrics**: `GET /metrics` (Prometheus format)

### Logging

The admission controller provides structured JSON logging:

```json
{
  "level": "info",
  "msg": "Security violation detected",
  "kind": "Pod",
  "namespace": "default",
  "name": "insecure-pod",
  "rule_id": "container-running-as-root",
  "severity": "critical",
  "message": "Containers must not run as UID 0",
  "category": "workload-security"
}
```

### Status Commands

```bash
# Check admission controller status
make -f Makefile.admission status

# View logs
make -f Makefile.admission logs

# Test webhook
make -f Makefile.admission test-validating
```

## Deployment Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   kubectl       │───▶│  API Server      │───▶│ Spotter         │
│   apply pod.yaml│    │                  │    │ Admission       │
└─────────────────┘    │ 1. Receives      │    │ Controller      │
                       │    request       │    │                 │
                       │ 2. Calls webhook │    │ 1. Evaluates    │
                       │ 3. Gets response │    │    rules        │
                       │ 4. Allows/Denies │    │ 2. Returns      │
                       │    resource      │    │    decision     │
                       └──────────────────┘    └─────────────────┘
```

## Security Considerations

1. **TLS Certificates**: Always use valid TLS certificates in production
2. **RBAC**: Apply principle of least privilege to service account
3. **Resource Limits**: Set appropriate CPU/memory limits
4. **Namespace Isolation**: Deploy in dedicated namespace
5. **Failure Policy**: Configure appropriate failure policies
6. **Monitoring**: Monitor admission controller health and performance

## Advanced Configuration

### Using cert-manager

```yaml
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: spotter-admission-controller-cert
  namespace: spotter-system
spec:
  secretName: spotter-admission-controller-certs
  issuerRef:
    name: ca-issuer
    kind: ClusterIssuer
  dnsNames:
  - spotter-admission-controller.spotter-system.svc
  - spotter-admission-controller.spotter-system.svc.cluster.local
```

### Custom Configuration File

```yaml
# config.yaml
server:
  mode: validating
  port: 8443
  min-severity: high
  namespaces: ["production", "staging"]
  resource-types: ["Pod", "Deployment"]

log-level: info
log-format: json
```

### Prometheus Monitoring

The admission controller exposes metrics for monitoring:

- `spotter_admission_requests_total`: Total admission requests
- `spotter_admission_duration_seconds`: Request processing duration
- `spotter_violations_total`: Total violations detected
- `spotter_allowed_requests_total`: Total allowed requests
- `spotter_denied_requests_total`: Total denied requests

## Troubleshooting

### Common Issues

1. **Certificate Issues**
   ```bash
   # Regenerate certificates
   make -f Makefile.admission generate-certs
   ```

2. **Webhook Not Called**
   ```bash
   # Check webhook configuration
   kubectl describe validatingadmissionwebhooks spotter-validating-webhook
   ```

3. **Pod Startup Issues**
   ```bash
   # Check logs
   kubectl logs -l app.kubernetes.io/name=spotter -n spotter-system
   ```

4. **Permission Denied**
   ```bash
   # Check RBAC
   kubectl auth can-i create events --as=system:serviceaccount:spotter-system:spotter-admission-controller
   ```

### Debug Mode

Enable debug logging:
```bash
kubectl set env deployment/spotter-admission-controller SPOTTER_LOG_LEVEL=debug -n spotter-system
```

## Contributing

See the main project README for contribution guidelines.

## License

See the main project LICENSE file.
