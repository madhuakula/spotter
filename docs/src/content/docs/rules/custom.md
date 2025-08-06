---
title: Custom Security Rules
description: Create and manage custom security rules for Spotter
---

Spotter allows you to create custom security rules tailored to your organization's specific security policies and requirements. Custom rules use the same CEL (Common Expression Language) engine as built-in rules, providing powerful and flexible security checks.

## Rule Structure

Custom rules follow the same structure as built-in rules:

```yaml
apiVersion: rules.spotter.run/v1
kind: SecurityRule
metadata:
  name: unique-name
  labels:
    category: "Workload Security"
    severity: high

spec:
  id: SPOTTER-<CATEGORY>-<NNN>
  name: "Readable Rule Name"
  version: "1.0.0"
  description: "Human readable explanation of what this rule checks"

  severity:
    level: "HIGH"                  # LOW | MEDIUM | HIGH | CRITICAL
    score: 8.7                     # 0.0 - 10.0, like CVSS

  category: "Workload Security"   # See SecurityCategory constants for all available categories
  subcategory: "Privilege Escalation"
  cwe: "CWE-269"                   # Optional CWE or MITRE ref

  regulatoryStandards:
    - name: "CIS Kubernetes 5.2.5"
      reference: "https://cisecurity.org/..."
    - name: "NIST SP 800-53 AC-6"
      reference: "https://csrc.nist.gov/..."

  match:
    resources:
      kubernetes:
        apiGroups:
          - ""
          - apps
        versions:
          - v1
        kinds:
          - Pod
          - Deployment
          - StatefulSet
          - Job
        namespaces:
          include: ["*"]
          exclude: ["kube-system", "kube-public"]
        labels:
          include:
            environment: ["production", "staging"]
          exclude:
            security.spotter.dev/ignore: ["true"]

  cel: |
    object.kind in ["Pod", "Deployment", "StatefulSet", "Job"] &&
    (
      (object.kind == "Pod" &&
       has(object.spec.containers) &&
       object.spec.containers.exists(container,
         has(container.securityContext) &&
         container.securityContext.allowPrivilegeEscalation == true
       )) ||
      (has(object.spec.template.spec.containers) &&
       object.spec.template.spec.containers.exists(container,
         has(container.securityContext) &&
         container.securityContext.allowPrivilegeEscalation == true
       ))
    )

  remediation:
    manual: |
      Update securityContext to disable allowPrivilegeEscalation...

  references:
    - title: "Kubernetes Security Context"
      url: "https://kubernetes.io/docs/tasks/configure-pod-container/security-context/"

  metadata:
    author: "Spotter Security Team"
    created: "2024-01-01"
```

## Required Fields

### Metadata Section

```yaml
metadata:
  name: "unique-rule-name"        # Must be unique across all rules
  labels:
    category: "Category Name"      # Rule category
    severity: "medium"             # Severity level
```

### Spec Section

```yaml
spec:
  id: "CUSTOM-001"                 # Unique rule identifier
  name: "Human Readable Name"      # Display name
  version: "1.0.0"                 # Semantic version
  description: "Rule description"  # What the rule checks
  severity:
    level: "medium"                # info, low, medium, high, critical
    score: 5.0                     # Numeric score (0.0-10.0)
  category: "Category Name"        # Primary category
  match:                           # Resource matching criteria
    kubernetes:
      resources: [...]             # Kubernetes resources to match
  cel: |                          # CEL expression
    # Expression that returns true when rule is violated
  remediation:
    description: "Fix description" # How to remediate
    steps: [...]                  # Remediation steps
```
