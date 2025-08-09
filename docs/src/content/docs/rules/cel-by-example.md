---
title: CEL by Example
description: Quick, example-heavy guide for writing CEL queries and setting match.resources
---
## Overview

This guide shows how to write a complete Spotter rule end-to-end:
- Start with a full rule template 
- Then scope your rule with match.resources
- Finally, write the CEL query to detect your condition

## Complete rule template 

```yaml
# apiVersion and kind identify this document as a Spotter security rule
apiVersion: rules.spotter.run/v1   # Always rules.spotter.run/v1
kind: SecurityRule                 # Always SecurityRule

metadata:                          # Kubernetes-style metadata for this rule object
  name: example-rule               # Machine-friendly unique name for the rule
  labels:                          # Optional: free-form labels (useful for grouping/searching)
    category: "Workload Security"
    severity: high

spec:                               # The rule’s specification
  id: SPOTTER-EXAMPLE-001           # Stable, unique ID (used in results and tooling)
  name: "Example Rule"              # Human-readable rule title
  version: "1.0.0"                 # Rule version (bump when logic/wording changes)
  description: >-                    # What the rule checks and why it matters
    Concise description of the risk and what is being validated.

  severity:                         # Severity used in outputs and reports
    level: HIGH                     # One of: LOW, MEDIUM, HIGH, CRITICAL
    score: 7.5                      # Numeric score (e.g., CVSS-like)

  category: "Workload Security"     # One primary category from the catalog
  subcategory: "Pod Security"       # Optional: narrower grouping within a category

  cwe: "CWE-000"                    # Optional: CWE identifier if applicable

  regulatoryStandards:              # Optional: map to compliance controls/benchmarks
    - name: "CIS Kubernetes Benchmark v1.8.0"
      reference: "https://www.cisecurity.org/benchmark/kubernetes"
      # section: "5.2.1"            # Optional: if you track specific sections

  match:                            # What resources are in scope for this rule
    resources:
      kubernetes:
        apiGroups: ["", apps]       # core API group is ""
        versions: [v1]
        kinds: [Pod, Deployment]    # Keep this tight for performance
        # namespaces:                # Optional include/exclude by namespace
        #   include: ["*"]
        #   exclude: ["kube-system", "kube-public"]
        # labels:                    # Optional include/exclude by labels
        #   include:
        #     environment: ["production"]
        #   exclude:
        #     security.spotter.dev/ignore: ["true"]

  cel: |                             # The CEL expression (true = finding)
    object.kind == 'Pod' && has(object.spec)   # Replace with your logic

  remediation:                      # Optional: how to fix the issue
    manual: "Clear, actionable steps to remediate the finding."

  references:                       # Optional: further reading and context
    - title: "Relevant Documentation"
      url: "https://kubernetes.io/"
      description: "Why this matters and best practices."

  metadata:                         # Optional: rule authoring metadata
    author: "Your Name or Team"
    created: "2025-01-01"
```

## Scope resources with match.resources

Use `match.resources.kubernetes` to scope which objects the rule evaluates. Wildcards are allowed.

```yaml
match:
  resources:
    kubernetes:
      apiGroups: ["", apps, batch]   # core API group is ""
      versions: [v1]
      kinds: [Pod, Deployment, StatefulSet, DaemonSet, Job, CronJob]
      namespaces:
        include: ["*"]               # all namespaces
        exclude: ["kube-system", "kube-public"]
      labels:
        include:
          environment: ["production", "staging"]
        exclude:
          security.spotter.dev/ignore: ["true"]
```

### Quick scopes

```yaml
# Only Pods in all namespaces
match:
  resources:
    kubernetes:
      apiGroups: [""]
      versions: [v1]
      kinds: [Pod]

# Only Deployments in apps/v1 within team-a namespaces
match:
  resources:
    kubernetes:
      apiGroups: [apps]
      versions: [v1]
      kinds: [Deployment]
      namespaces:
        include: ["team-a-*"]

# Exclude CI namespaces and ignored workloads by label
match:
  resources:
    kubernetes:
      apiGroups: ["", apps, batch]
      versions: [v1]
      kinds: [Pod, Deployment, StatefulSet, Job]
      namespaces:
        include: ["*"]
        exclude: ["ci-*", "kube-*"]
      labels:
        exclude:
          security.spotter.dev/ignore: ["true"]
```

### Tips
- Keep `apiGroups` and `kinds` as tight as possible for performance.
- Use `namespaces.include/exclude` and `labels.include/exclude` to focus rules without extra CEL logic.

## Write CEL for your rule

Focus on navigating the resource shape and expressing your check simply. `object` is the root of the live resource (the full Kubernetes object you’re evaluating).

### Concepts and references

For operators, macros, and standard library, see the CEL docs: [Language](https://cel.dev/docs/language/), [Macros (e.g., `has`, `exists`, `all`)](https://cel.dev/docs/macros/), and [Standard definitions](https://cel.dev/docs/standard-definitions/). Keep this page as a practical guide to writing Spotter rules, not CEL language internals.

### Example 1: Check the resource kind

Start by matching on the `kind` field to narrow the resource type.

```cel
object.kind == 'Service'
```

### Example 2: Match a Service of type NodePort

Combine kind matching with a specific spec field.

```cel
object.kind == 'Service' && has(object.spec.type) && object.spec.type == 'NodePort'
```

### Example 3: Ensure an Ingress has no TLS configured

Use presence and size checks for lists/maps.

```cel
object.kind == 'Ingress' && (!has(object.spec.tls) || size(object.spec.tls) == 0)
```

### Example 4: Match Pods whose name starts with a prefix

String helpers are useful for naming conventions.

```cel
object.kind == 'Pod' && has(object.metadata.name) && object.metadata.name.startsWith("demo-")
```

### Example 5: Require a Pod label to be set

Verify that a label key exists and is non-empty.

```cel
object.kind == 'Pod' && has(object.metadata.labels) && object.metadata.labels['team'] != ''
```

### Example 6: Require a Service annotation to be present

Annotations can be used for ownership or metadata tracking.

```cel
object.kind == 'Service' && has(object.metadata.annotations) && object.metadata.annotations['owner'] != ''
```

### Example 7: Deny privileged containers across Pods and controllers

Branch on `Pod` vs controller objects to traverse to container lists.

```cel
(object.kind == 'Pod'
  ? (
      (has(object.spec.containers) && object.spec.containers.exists(c,
        has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true
      )) ||
      (has(object.spec.initContainers) && object.spec.initContainers.exists(c,
        has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true
      ))
    )
  : (
      (has(object.spec.template.spec.containers) && object.spec.template.spec.containers.exists(c,
        has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true
      )) ||
      (has(object.spec.template.spec.initContainers) && object.spec.template.spec.initContainers.exists(c,
        has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true
      ))
    )
)
```

### Example 8: Require memory limits for all containers

Ensure each container declares `resources.limits.memory`.

```cel
(object.kind == 'Pod'
  ? (
      has(object.spec.containers) && object.spec.containers.exists(c,
        !has(c.resources) || !has(c.resources.limits) || !has(c.resources.limits.memory)
      )
    )
  : (
      has(object.spec.template.spec.containers) && object.spec.template.spec.containers.exists(c,
        !has(c.resources) || !has(c.resources.limits) || !has(c.resources.limits.memory)
      )
    )
)
```

### Example 9: Flag host networking wherever it is set

Detect `hostNetwork: true` at the Pod or template level.

```cel
(object.kind == 'Pod'
  ? (has(object.spec.hostNetwork) && object.spec.hostNetwork == true)
  : (has(object.spec.template.spec.hostNetwork) && object.spec.template.spec.hostNetwork == true)
)
```

### Example 10: Detect any hostPort assignment on containers

Scan container ports for a non-zero `hostPort`.

```cel
(object.kind == 'Pod'
  ? (
      has(object.spec.containers) && object.spec.containers.exists(c,
        has(c.ports) && c.ports.exists(p, has(p.hostPort) && p.hostPort > 0)
      )
    )
  : (
      has(object.spec.template.spec.containers) && object.spec.template.spec.containers.exists(c,
        has(c.ports) && c.ports.exists(p, has(p.hostPort) && p.hostPort > 0)
      )
    )
)
```

### Authoring tips

Keep scopes tight with `match.resources`, start with the narrowest condition you need, and add container/Pod branching only when necessary.


