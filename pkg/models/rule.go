package models

import (
	"time"
)

// SecurityRule represents the main security rule structure
type SecurityRule struct {
	APIVersion string       `yaml:"apiVersion" json:"apiVersion"`
	Kind       string       `yaml:"kind" json:"kind"`
	Metadata   RuleMetadata `yaml:"metadata" json:"metadata"`
	Spec       RuleSpec     `yaml:"spec" json:"spec"`
}

// RuleMetadata contains metadata for the security rule
type RuleMetadata struct {
	Name   string            `yaml:"name" json:"name"`
	Labels map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// RuleSpec contains the specification of the security rule
type RuleSpec struct {
	ID                  string                  `yaml:"id" json:"id"`
	Name                string                  `yaml:"name" json:"name"`
	Version             string                  `yaml:"version" json:"version"`
	Description         string                  `yaml:"description" json:"description"`
	Severity            Severity                `yaml:"severity" json:"severity"`
	Category            string                  `yaml:"category" json:"category"`
	Subcategory         string                  `yaml:"subcategory,omitempty" json:"subcategory,omitempty"`
	CWE                 string                  `yaml:"cwe,omitempty" json:"cwe,omitempty"`
	RegulatoryStandards []RegulatoryStandard    `yaml:"regulatoryStandards,omitempty" json:"regulatoryStandards,omitempty"`
	Match               MatchCriteria           `yaml:"match" json:"match"`
	CEL                 string                  `yaml:"cel" json:"cel"`
	Remediation         *Remediation            `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	References          []Reference             `yaml:"references,omitempty" json:"references,omitempty"`
	Metadata            *RuleAdditionalMetadata `yaml:"metadata,omitempty" json:"metadata,omitempty"`
}

// Severity represents the severity level and risk score
type Severity struct {
	Level SeverityLevel `yaml:"level" json:"level"`
	Score float64       `yaml:"score" json:"score"`
}

// SeverityLevel represents the severity levels
type SeverityLevel string

const (
	SeverityLow      SeverityLevel = "LOW"
	SeverityMedium   SeverityLevel = "MEDIUM"
	SeverityHigh     SeverityLevel = "HIGH"
	SeverityCritical SeverityLevel = "CRITICAL"
)

// SecurityCategory represents the security rule categories
// These 10 abstracted categories provide comprehensive coverage of Kubernetes and cloud security domains
type SecurityCategory string

const (
	// WorkloadSecurity covers hardening of Pods, Deployments, containers, and their runtime behavior.
	// Includes securityContext, privilege escalation, image pulls, etc.
	WorkloadSecurity SecurityCategory = "Workload Security"

	// AccessControl covers RBAC, service accounts, impersonation, IAM bindings,
	// and overprivileged identities across both K8s and cloud.
	AccessControl SecurityCategory = "Access Control"

	// NetworkTrafficSecurity covers NetworkPolicies, ingress/egress controls, service exposure,
	// DNS policies, and cloud networking (e.g., public IPs).
	NetworkTrafficSecurity SecurityCategory = "Network & Traffic Security"

	// SecretsDataProtection covers secrets in envs, volumes, Vault integration,
	// encryption (at rest/transit), configmaps with sensitive data.
	SecretsDataProtection SecurityCategory = "Secrets & Data Protection"

	// ConfigurationResourceHygiene covers resource limits, liveness/readiness probes,
	// deprecated APIs, misconfigs, annotations/labels, etc.
	ConfigurationResourceHygiene SecurityCategory = "Configuration & Resource Hygiene"

	// SupplyChainImageSecurity covers image signing, scanning, SBOM, base image hygiene,
	// provenance, untrusted registries.
	SupplyChainImageSecurity SecurityCategory = "Supply Chain & Image Security"

	// CICDGitOpsSecurity covers pipeline security, GitHub Actions/Tekton/Argo safety,
	// Git repo access, shift-left policies.
	CICDGitOpsSecurity SecurityCategory = "CI/CD & GitOps Security"

	// RuntimeThreatDetection covers anomaly detection, eBPF, runtime policy violations,
	// malware detection, process/file/network monitoring.
	RuntimeThreatDetection SecurityCategory = "Runtime Threat Detection"

	// AuditLoggingCompliance covers logging, audit events, governance,
	// CIS/NIST/PCI benchmarks, custom compliance controls.
	AuditLoggingCompliance SecurityCategory = "Audit, Logging & Compliance"

	// PlatformInfrastructureSecurity covers node-level risks (hostPath, hostPID),
	// control plane exposure, metadata servers, cloud infra misconfigs (S3, IMDS, etc.).
	PlatformInfrastructureSecurity SecurityCategory = "Platform & Infrastructure Security"
)

// RegulatoryStandard represents a regulatory compliance standard
type RegulatoryStandard struct {
	Name      string `yaml:"name" json:"name"`
	Reference string `yaml:"reference" json:"reference"`
}

// MatchCriteria defines what resources this rule should be applied to
type MatchCriteria struct {
	Resources ResourceCriteria `yaml:"resources" json:"resources"`
}

// ResourceCriteria defines the resource matching criteria
type ResourceCriteria struct {
	Kubernetes KubernetesResourceCriteria `yaml:"kubernetes" json:"kubernetes"`
}

// KubernetesResourceCriteria defines Kubernetes-specific matching criteria
type KubernetesResourceCriteria struct {
	APIGroups  []string           `yaml:"apiGroups" json:"apiGroups"`
	Versions   []string           `yaml:"versions" json:"versions"`
	Kinds      []string           `yaml:"kinds" json:"kinds"`
	Namespaces *NamespaceSelector `yaml:"namespaces,omitempty" json:"namespaces,omitempty"`
	Labels     *LabelSelector     `yaml:"labels,omitempty" json:"labels,omitempty"`
}

// NamespaceSelector defines namespace inclusion/exclusion criteria
type NamespaceSelector struct {
	Include []string `yaml:"include,omitempty" json:"include,omitempty"`
	Exclude []string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// LabelSelector defines label-based selection criteria
type LabelSelector struct {
	Include map[string][]string `yaml:"include,omitempty" json:"include,omitempty"`
	Exclude map[string][]string `yaml:"exclude,omitempty" json:"exclude,omitempty"`
}

// Remediation contains remediation instructions
type Remediation struct {
	Manual string `yaml:"manual,omitempty" json:"manual,omitempty"`
}

// Reference represents an external reference
type Reference struct {
	Title       string `yaml:"title" json:"title"`
	URL         string `yaml:"url" json:"url"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

// RuleAdditionalMetadata contains additional metadata about the rule
type RuleAdditionalMetadata struct {
	Author  string `yaml:"author,omitempty" json:"author,omitempty"`
	Created string `yaml:"created,omitempty" json:"created,omitempty"`
}

// ValidationResult represents the result of applying a rule to a resource
type ValidationResult struct {
	RuleID      string                 `json:"ruleId"`
	RuleName    string                 `json:"ruleName"`
	Resource    map[string]interface{} `json:"resource"`
	Passed      bool                   `json:"passed"`
	Message     string                 `json:"message,omitempty"`
	Severity    SeverityLevel          `json:"severity"`
	Category    string                 `json:"category"`
	Remediation string                 `json:"remediation,omitempty"`
	Timestamp   time.Time              `json:"timestamp"`
}

// ScanResult represents the overall scan results
type ScanResult struct {
	TotalResources    int                `json:"totalResources"`
	TotalRules        int                `json:"totalRules"`
	Passed            int                `json:"passed"`
	Failed            int                `json:"failed"`
	Results           []ValidationResult `json:"results"`
	SeverityBreakdown map[string]int     `json:"severityBreakdown"`
	CategoryBreakdown map[string]int     `json:"categoryBreakdown"`
	AIRecommendations interface{}        `json:"aiRecommendations,omitempty"`
	Timestamp         time.Time          `json:"timestamp"`
	Duration          time.Duration      `json:"duration"`
}

// ScanSummary represents a summary of scan results
type ScanSummary struct {
	TotalResources     int              `json:"totalResources"`
	ScannedResources   int              `json:"scannedResources"`
	TotalRules         int              `json:"totalRules"`
	ExecutedRules      int              `json:"executedRules"`
	TotalFindings      int              `json:"totalFindings"`
	FindingsBySeverity map[Severity]int `json:"findingsBySeverity"`
	FindingsByCategory map[string]int   `json:"findingsByCategory"`
	ResourceTypes      map[string]int   `json:"resourceTypes"`
	Namespaces         map[string]int   `json:"namespaces"`
	HighestSeverity    Severity         `json:"highestSeverity"`
	ScanDuration       time.Duration    `json:"scanDuration"`
	Timestamp          time.Time        `json:"timestamp"`
	Status             ScanStatus       `json:"status"`
}

// ScanStatus represents the status of a scan
type ScanStatus string

const (
	ScanStatusSuccess    ScanStatus = "SUCCESS"
	ScanStatusFailed     ScanStatus = "FAILED"
	ScanStatusPartial    ScanStatus = "PARTIAL"
	ScanStatusError      ScanStatus = "ERROR"
	ScanStatusInProgress ScanStatus = "IN_PROGRESS"
)

// RuleTestCase represents a single test case for rule validation
type RuleTestCase struct {
	Name  string `yaml:"name" json:"name"`
	Pass  bool   `yaml:"pass" json:"pass"`
	Input string `yaml:"input" json:"input"`
}

// RuleTestSuite represents a collection of test cases for a rule
type RuleTestSuite []RuleTestCase
