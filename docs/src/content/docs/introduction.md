---
title: Introduction
description: Learn about Spotter, the Universal Kubernetes Security Engine
---

**Spotter** is a comprehensive Kubernetes security scanner that helps identify security misconfigurations, vulnerabilities, and compliance issues in your Kubernetes clusters and manifests. Built with extensibility and performance in mind, Spotter uses the Common Expression Language (CEL) for flexible and powerful security rule evaluation.

## What is Spotter?

Spotter is designed to be your universal Kubernetes security engine, providing:

- **Comprehensive Security Scanning**: Analyze live clusters, YAML manifests, and Helm charts
- **140+ Built-in Rules**: Covering all major Kubernetes security domains
- **High Performance**: Concurrent scanning with intelligent resource matching
- **Flexible Deployment**: CLI tool, admission controller, or CI/CD integration
- **Extensible Rules**: Create custom security rules using CEL expressions

## Key Features

### 🔍 Multiple Scan Targets

- **Live Clusters**: Scan running Kubernetes clusters in real-time
- **Manifest Files**: Analyze YAML/JSON files before deployment
- **Helm Charts**: Scan Helm templates and rendered manifests
- **CI/CD Integration**: Integrate into your development pipeline

### 🛡️ Comprehensive Security Coverage

Spotter organizes security rules into 10 major categories:

1. **Workload Security** - Container privileges, security contexts, capabilities
2. **Access Control** - RBAC, service accounts, authorization policies
3. **Network & Traffic Security** - Network policies, service exposure
4. **Secrets & Data Protection** - Secret management, encryption at rest/transit
5. **Configuration & Resource Hygiene** - Resource limits, probes, deprecated APIs
6. **Supply Chain & Image Security** - Image scanning, registries, signatures
7. **CI/CD & GitOps Security** - Pipeline security, shift-left policies
8. **Runtime Threat Detection** - Anomaly detection, policy violations
9. **Audit, Logging & Compliance** - CIS benchmarks, governance frameworks
10. **Platform & Infrastructure Security** - Node security, control plane hardening

### ⚡ High Performance Architecture

- **Concurrent Processing**: Configurable worker pools for parallel scanning
- **Intelligent Matching**: Efficient resource filtering and rule matching
- **CEL Engine**: Fast expression evaluation with caching
- **Memory Efficient**: Optimized for large-scale cluster scanning

### 📊 Flexible Output Formats

- **Table**: Human-readable console output
- **JSON**: Machine-readable structured data
- **YAML**: Configuration-friendly format
- **SARIF**: Static Analysis Results Interchange Format for CI/CD

## How Spotter Works

1. **Resource Discovery**: Spotter discovers Kubernetes resources from clusters or files
2. **Rule Matching**: Each resource is matched against applicable security rules
3. **CEL Evaluation**: Security rules written in CEL are evaluated against resources
4. **Result Aggregation**: Findings are collected and categorized by severity
5. **Report Generation**: Results are formatted and output in the desired format

## Use Cases

### Development & Testing
- Scan manifests during development to catch security issues early
- Validate security risks before deployment
- Integrate into local development workflows

### CI/CD Pipelines
- Automated security scanning in build pipelines
- Gate deployments based on security findings
- Generate security reports for compliance

### Production Monitoring
- Regular cluster security assessments
- Compliance auditing and reporting
- Runtime security policy enforcement via admission controller

### Security Teams
- Centralized security rule management
- Custom rule development for organization-specific policies
- Security posture monitoring and trending

## Architecture Overview

Spotter follows a modular architecture:

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   CLI Layer     │    │   Config Layer  │    │  Output Layer   │
│                 │    │                 │    │                 │
│ • Commands      │    │ • YAML Config   │    │ • Table         │
│ • Flags         │    │ • Validation    │    │ • JSON          │
│ • Help          │    │ • Defaults      │    │ • SARIF         │
└─────────────────┘    └─────────────────┘    └─────────────────┘
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                │
┌───────────────────────────────┼───────────────────────────────────┐
│                        Core Engine                                │
│                                                                   │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │
│  │   Scanner   │  │    Rules    │  │     CEL     │  │ Reporter  │ │
│  │             │  │   Engine    │  │   Engine    │  │           │ │
│  │ • K8s API   │  │             │  │             │  │ • Format  │ │
│  │ • Files     │  │ • Matching  │  │ • Evaluate  │  │ • Output  │ │
│  │ • Helm      │  │ • Loading   │  │ • Cache     │  │ • Filter  │ │
│  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │
└───────────────────────────────────────────────────────────────────┘
```

## Getting Started

Ready to start using Spotter? Check out our [Installation Guide](/installation/) to get up and running quickly, or jump to the [Quick Start](/quick-start/) for a hands-on introduction.

## Community & Support

- **GitHub Repository**: [madhuakula/spotter](https://github.com/madhuakula/spotter)
- **Issue Tracker**: Report bugs and request features
- **Discussions**: Community support and questions
- **Documentation**: Comprehensive guides and references

Spotter is open source and licensed under the Apache License 2.0. We welcome contributions from the community!
