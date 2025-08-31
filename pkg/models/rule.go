package models

import (
	"time"
)

// SpotterRule represents the main security rule structure (renamed from SecurityRule)
type SpotterRule struct {
	APIVersion string       `yaml:"apiVersion" json:"apiVersion"`
	Kind       string       `yaml:"kind" json:"kind"`
	Metadata   RuleMetadata `yaml:"metadata" json:"metadata"`
	Spec       RuleSpec     `yaml:"spec" json:"spec"`
}

// SpotterRulePack represents a collection of security rules
type SpotterRulePack struct {
	APIVersion string       `yaml:"apiVersion" json:"apiVersion"`
	Kind       string       `yaml:"kind" json:"kind"`
	Metadata   RuleMetadata `yaml:"metadata" json:"metadata"`
	Spec       RulePackSpec `yaml:"spec" json:"spec"`
}

// SecurityRule is an alias for backward compatibility
type SecurityRule = SpotterRule

// RuleMetadata contains metadata for the security rule
type RuleMetadata struct {
	Name        string            `yaml:"name" json:"name"`
	Labels      map[string]string `yaml:"labels,omitempty" json:"labels,omitempty"`
	Annotations map[string]string `yaml:"annotations,omitempty" json:"annotations,omitempty"`
}

// RuleSpec contains the specification of the security rule (simplified to match external API)
type RuleSpec struct {
	Match       MatchCriteria `yaml:"match" json:"match"`
	CEL         string        `yaml:"cel" json:"cel"`
	Remediation *Remediation  `yaml:"remediation,omitempty" json:"remediation,omitempty"`
	References  []Reference   `yaml:"references,omitempty" json:"references,omitempty"`
}

// RulePackSpec contains the specification of a rule pack
type RulePackSpec struct {
	Rules      []string    `yaml:"rules" json:"rules"`
	References []Reference `yaml:"references,omitempty" json:"references,omitempty"`
}

// Helper methods for SpotterRule to extract metadata from annotations and labels

// GetID returns the rule ID from metadata name
func (r *SpotterRule) GetID() string {
	return r.Metadata.Name
}

// GetTitle returns the rule title from annotations
func (r *SpotterRule) GetTitle() string {
	if r.Metadata.Annotations != nil {
		return r.Metadata.Annotations["rules.spotter.dev/title"]
	}
	return ""
}

// GetVersion returns the rule version from annotations
func (r *SpotterRule) GetVersion() string {
	if r.Metadata.Annotations != nil {
		return r.Metadata.Annotations["rules.spotter.dev/version"]
	}
	return ""
}

// GetDescription returns the rule description from annotations
func (r *SpotterRule) GetDescription() string {
	if r.Metadata.Annotations != nil {
		return r.Metadata.Annotations["rules.spotter.dev/description"]
	}
	return ""
}

// GetCWE returns the CWE identifier from annotations
func (r *SpotterRule) GetCWE() string {
	if r.Metadata.Annotations != nil {
		return r.Metadata.Annotations["rules.spotter.dev/cwe"]
	}
	return ""
}

// GetSeverity returns the severity from labels
func (r *SpotterRule) GetSeverity() string {
	if r.Metadata.Labels != nil {
		return r.Metadata.Labels["rules.spotter.dev/severity"]
	}
	return ""
}

// GetCategory returns the category from labels
func (r *SpotterRule) GetCategory() string {
	if r.Metadata.Labels != nil {
		return r.Metadata.Labels["rules.spotter.dev/category"]
	}
	return ""
}

// GetSeverityLevel returns the severity as SeverityLevel type
func (r *SpotterRule) GetSeverityLevel() SeverityLevel {
	severityStr := r.GetSeverity()
	return SeverityLevel(severityStr)
}

// GetRemediation returns the manual remediation text
func (r *SpotterRule) GetRemediation() string {
	if r.Spec.Remediation != nil {
		return r.Spec.Remediation.Manual
	}
	return ""
}

// GetCELExpression returns the CEL expression
func (r *SpotterRule) GetCELExpression() string {
	return r.Spec.CEL
}

// Helper methods for SpotterRulePack to extract metadata from annotations

// GetID returns the rule pack ID from metadata name
func (rp *SpotterRulePack) GetID() string {
	return rp.Metadata.Name
}

// GetTitle returns the rule pack title from annotations
func (rp *SpotterRulePack) GetTitle() string {
	if rp.Metadata.Annotations != nil {
		return rp.Metadata.Annotations["rules.spotter.dev/title"]
	}
	return ""
}

// GetVersion returns the rule pack version from annotations
func (rp *SpotterRulePack) GetVersion() string {
	if rp.Metadata.Annotations != nil {
		return rp.Metadata.Annotations["rules.spotter.dev/version"]
	}
	return ""
}

// GetDescription returns the rule pack description from annotations
func (rp *SpotterRulePack) GetDescription() string {
	if rp.Metadata.Annotations != nil {
		return rp.Metadata.Annotations["rules.spotter.dev/description"]
	}
	return ""
}

// GetAuthor returns the rule pack author from annotations
func (rp *SpotterRulePack) GetAuthor() string {
	if rp.Metadata.Annotations != nil {
		return rp.Metadata.Annotations["rules.spotter.dev/author"]
	}
	return ""
}

// GetRules returns the list of rule IDs in the pack
func (rp *SpotterRulePack) GetRules() []string {
	return rp.Spec.Rules
}

type SeverityLevel string

const (
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

// String returns the string representation of the severity level
func (s SeverityLevel) String() string {
	return string(s)
}

// IsValid checks if the severity level is valid
func (s SeverityLevel) IsValid() bool {
	switch s {
	case SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// GetScore returns the numeric score for the severity level
func (s SeverityLevel) GetScore() float64 {
	switch s {
	case SeverityLow:
		return 3.0
	case SeverityMedium:
		return 5.0
	case SeverityHigh:
		return 7.0
	case SeverityCritical:
		return 9.0
	default:
		return 0.0
	}
}

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

	// AuditLoggingCompliance covers logging, audit events, governance,
	// CIS/NIST/PCI benchmarks, custom compliance controls.
	AuditLoggingCompliance SecurityCategory = "Audit, Logging & Compliance"

	// PlatformInfrastructureSecurity covers node-level risks (hostPath, hostPID),
	// control plane exposure, metadata servers, cloud infra misconfigs (S3, IMDS, etc.).
	PlatformInfrastructureSecurity SecurityCategory = "Platform & Infrastructure Security"
)

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
	Timestamp         time.Time          `json:"timestamp"`
	Duration          time.Duration      `json:"duration"`
}

// ScanSummary represents a summary of scan results
type ScanSummary struct {
	TotalResources     int                   `json:"totalResources"`
	ScannedResources   int                   `json:"scannedResources"`
	TotalRules         int                   `json:"totalRules"`
	ExecutedRules      int                   `json:"executedRules"`
	TotalFindings      int                   `json:"totalFindings"`
	FindingsBySeverity map[SeverityLevel]int `json:"findingsBySeverity"`
	FindingsByCategory map[string]int        `json:"findingsByCategory"`
	ResourceTypes      map[string]int        `json:"resourceTypes"`
	Namespaces         map[string]int        `json:"namespaces"`
	HighestSeverity    SeverityLevel         `json:"highestSeverity"`
	ScanDuration       time.Duration         `json:"scanDuration"`
	Timestamp          time.Time             `json:"timestamp"`
	Status             ScanStatus            `json:"status"`
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
