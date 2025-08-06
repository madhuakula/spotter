---
title: Built-in Security Rules
description: Comprehensive guide to Spotter's built-in security rules
---

Spotter comes with 140+ built-in security rules covering all major Kubernetes security domains. These rules are based on industry best practices, security benchmarks, and real-world attack patterns.

These rules are based on KICS Kubernetes Queries [https://github.com/Checkmarx/kics/tree/master/docs/queries/kubernetes-queries](https://github.com/Checkmarx/kics/tree/master/docs/queries/kubernetes-queries)

## Rule Categories

Spotter organizes security rules into 10 comprehensive categories:

### 1. Workload Security

**Focus**: Container and pod-level security configurations

**Key Areas**:
- Container privilege escalation
- Security contexts and capabilities
- Resource limits and requests
- Health checks and probes
- Image security policies

### 2. Access Control

**Focus**: Authentication, authorization, and RBAC policies

**Key Areas**:
- RBAC roles and bindings
- Service account security
- Pod security policies
- Admission controllers
- User and group permissions

### 3. Network & Traffic Security

**Focus**: Network policies, service exposure, and traffic control

**Key Areas**:
- Network policy enforcement
- Service exposure methods
- Ingress and egress controls
- Load balancer configurations
- DNS security

### 4. Secrets & Data Protection

**Focus**: Secret management, encryption, and data security

**Key Areas**:
- Secret storage and access
- Environment variable security
- Volume mount security
- Encryption at rest and in transit
- Data classification

### 5. Configuration & Resource Hygiene

**Focus**: Resource management, configuration best practices

**Key Areas**:
- Resource quotas and limits
- Deprecated API usage
- Label and annotation standards
- Configuration validation
- Resource lifecycle management

### 6. Supply Chain & Image Security

**Focus**: Container image security and supply chain integrity

**Key Areas**:
- Image vulnerability scanning
- Image registry security
- Image signing and verification
- Base image policies
- Dependency management

### 7. CI/CD & GitOps Security

**Focus**: Pipeline security and deployment practices

**Key Areas**:
- Pipeline security controls
- Deployment automation
- Code review processes
- Artifact integrity
- Environment promotion

### 8. Runtime Threat Detection

**Focus**: Runtime security monitoring and anomaly detection

**Key Areas**:
- Behavioral analysis
- Anomaly detection
- Runtime policy enforcement
- Threat intelligence
- Incident response

### 9. Audit, Logging & Compliance

**Focus**: Audit trails, logging, and regulatory compliance

**Key Areas**:
- Audit log configuration
- Compliance frameworks (CIS, NIST, SOC2)
- Log retention policies
- Monitoring and alerting
- Governance controls

### 10. Platform & Infrastructure Security

**Focus**: Cluster-level and infrastructure security

**Key Areas**:
- Node security configuration
- Control plane hardening
- etcd security
- API server configuration
- Cluster networking

## Rule Structure

Each built-in rule follows a standardized structure:

```yaml
apiVersion: rules.spotter.run/v1
kind: SecurityRule
metadata:
  name: container-is-privileged
  labels:
    category: "Workload Security"
    severity: critical
spec:
  id: SPOTTER-WORKLOAD-SECURITY-105
  name: "Container Is Privileged"
  version: "1.0.0"
  description: "Containers should not run in privileged mode, as this grants all capabilities to the container and removes all security restrictions."
  severity:
    level: CRITICAL
    score: 9.8
  category: "Workload Security"
  subcategory: "Pod Security Context"
  cwe: "CWE-269"
  regulatoryStandards:
    - name: "CIS Kubernetes Benchmark v1.8.0"
      reference: "https://www.cisecurity.org/benchmark/kubernetes"
      section: "5.2.1"
  match:
    resources:
      kubernetes:
        apiGroups:
          - ""
          - "apps"
        versions:
          - "v1"
        kinds:
          - Pod
          - Deployment
          - StatefulSet
          - DaemonSet
        namespaces:
          include: ["*"]
          exclude: ["kube-system", "kube-public"]
  cel: |
    (object.kind == 'Pod' && (
      (has(object.spec.containers) && object.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)) ||
      (has(object.spec.initContainers) && object.spec.initContainers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true))
    )) || (object.kind != 'Pod' && (
      (has(object.spec.template.spec.containers) && object.spec.template.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)) ||
      (has(object.spec.template.spec.initContainers) && object.spec.template.spec.initContainers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true))
    ))
  remediation:
    manual: "Set `privileged: false` in the container's security context."
  references:
    - title: "Kubernetes Pod Security Standards (Restricted)"
      url: "https://kubernetes.io/docs/concepts/security/pod-security-standards/#restricted"
  metadata:
    author: "Spotter Security Team"
    created: "2025-07-29"
```

## Severity Levels

Spotter uses a 4-level severity system:

### Critical (Score: 9.0-10.0)
- **Impact**: Immediate security risk, potential for system compromise
- **Examples**: Privileged containers, cluster-admin access, exposed secrets
- **Action**: Fix immediately

### High (Score: 7.0-8.9)
- **Impact**: Significant security risk, potential for privilege escalation
- **Examples**: Missing network policies, weak RBAC, insecure configurations
- **Action**: Fix within 24-48 hours

### Medium (Score: 4.0-6.9)
- **Impact**: Moderate security risk, potential for information disclosure
- **Examples**: Missing resource limits, deprecated APIs, weak encryption
- **Action**: Fix within 1 week

### Low (Score: 1.0-3.9)
- **Impact**: Minor security risk, potential for denial of service
- **Examples**: Missing labels, suboptimal configurations, minor policy violations
- **Action**: Fix during next maintenance window

## Compliance Mappings

Built-in rules are mapped to major compliance frameworks:

### CIS Kubernetes Benchmark
- **Coverage**: 95% of CIS controls
- **Sections**: All major sections (Control Plane, Worker Nodes, Policies)
- **Updates**: Regular updates with new CIS releases

### NIST Cybersecurity Framework
- **Functions**: Identify, Protect, Detect, Respond, Recover
- **Categories**: Asset Management, Access Control, Data Security
- **Subcategories**: Detailed mappings for each control

### SOC 2 Type II
- **Trust Criteria**: Security, Availability, Confidentiality
- **Controls**: Technical and operational controls
- **Evidence**: Automated evidence collection

### PCI DSS
- **Requirements**: Data protection, access control, monitoring
- **Scope**: Applicable to payment processing workloads
- **Validation**: Continuous compliance monitoring

### HIPAA
- **Safeguards**: Administrative, physical, technical
- **Requirements**: Healthcare data protection
- **Controls**: Access control, audit trails, encryption

## Rule Management

### Listing Rules

```bash
# List all built-in rules
spotter rules list

# List by category
spotter rules list --category "Workload Security"

# List by severity
spotter rules list --severity critical
```

### Rule Information

```bash
# Show detailed rule information
spotter rules info SPOTTER-WORKLOAD-SECURITY-100

# Export rule definition
spotter rules info SPOTTER-WORKLOAD-SECURITY-100 --output yaml
```

### Filtering Rules

```bash
# Include specific rules
spotter scan cluster --include-rules "SPOTTER-WORKLOAD-SECURITY-100,SPOTTER-WORKLOAD-SECURITY-101"

# Filter by category
spotter scan cluster --categories "Workload Security,Access Control"

# Filter by severity
spotter scan cluster --min-severity medium
```
