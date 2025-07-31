package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
)

// SARIFReporter implements the Reporter interface for SARIF output
type SARIFReporter struct{}

// NewSARIFReporter creates a new SARIF reporter
func NewSARIFReporter() Reporter {
	return &SARIFReporter{}
}

// GenerateReport generates a SARIF report from scan results
func (r *SARIFReporter) GenerateReport(ctx context.Context, results *models.ScanResult) ([]byte, error) {
	sarifReport := r.buildSARIFReport(results)

	data, err := json.MarshalIndent(sarifReport, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal SARIF report: %w", err)
	}

	return data, nil
}

// WriteReport writes the SARIF report to the configured writer
func (r *SARIFReporter) WriteReport(ctx context.Context, results *models.ScanResult, writer io.Writer) error {
	data, err := r.GenerateReport(ctx, results)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write SARIF report: %w", err)
	}

	return nil
}

// SARIF format structures
type SARIFReport struct {
	Version string     `json:"version"`
	Schema  string     `json:"$schema"`
	Runs    []SARIFRun `json:"runs"`
}

type SARIFRun struct {
	Tool        SARIFTool              `json:"tool"`
	Results     []SARIFResult          `json:"results"`
	Artifacts   []SARIFArtifact        `json:"artifacts,omitempty"`
	Invocations []SARIFInvocation      `json:"invocations,omitempty"`
	Properties  map[string]interface{} `json:"properties,omitempty"`
}

type SARIFTool struct {
	Driver SARIFDriver `json:"driver"`
}

type SARIFDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version"`
	InformationUri string      `json:"informationUri,omitempty"`
	Rules          []SARIFRule `json:"rules"`
}

type SARIFRule struct {
	ID                   string                 `json:"id"`
	Name                 string                 `json:"name,omitempty"`
	ShortDescription     SARIFMessage           `json:"shortDescription"`
	FullDescription      SARIFMessage           `json:"fullDescription,omitempty"`
	Help                 SARIFMessage           `json:"help,omitempty"`
	Properties           map[string]interface{} `json:"properties,omitempty"`
	DefaultConfiguration SARIFConfiguration     `json:"defaultConfiguration,omitempty"`
}

type SARIFConfiguration struct {
	Level string `json:"level"`
}

type SARIFMessage struct {
	Text string `json:"text"`
}

type SARIFResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    SARIFMessage           `json:"message"`
	Locations  []SARIFLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type SARIFLocation struct {
	PhysicalLocation SARIFPhysicalLocation  `json:"physicalLocation"`
	LogicalLocations []SARIFLogicalLocation `json:"logicalLocations,omitempty"`
}

type SARIFPhysicalLocation struct {
	ArtifactLocation SARIFArtifactLocation `json:"artifactLocation"`
	Region           SARIFRegion           `json:"region,omitempty"`
}

type SARIFArtifactLocation struct {
	URI string `json:"uri"`
}

type SARIFRegion struct {
	StartLine   int `json:"startLine,omitempty"`
	StartColumn int `json:"startColumn,omitempty"`
	EndLine     int `json:"endLine,omitempty"`
	EndColumn   int `json:"endColumn,omitempty"`
}

type SARIFLogicalLocation struct {
	Name               string `json:"name"`
	Kind               string `json:"kind,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
}

type SARIFArtifact struct {
	Location SARIFArtifactLocation `json:"location"`
}

type SARIFInvocation struct {
	ExecutionSuccessful bool   `json:"executionSuccessful"`
	ExitCode            int    `json:"exitCode,omitempty"`
	StartTimeUtc        string `json:"startTimeUtc,omitempty"`
	EndTimeUtc          string `json:"endTimeUtc,omitempty"`
}

// GetFormat returns the format name
func (r *SARIFReporter) GetFormat() string {
	return "sarif"
}

// GetFileExtension returns the file extension
func (r *SARIFReporter) GetFileExtension() string {
	return ".sarif"
}

// buildSARIFReport constructs the SARIF report structure
func (r *SARIFReporter) buildSARIFReport(results *models.ScanResult) *SARIFReport {
	// Calculate comprehensive statistics
	categoryStats := r.calculateCategoryStats(results.Results)
	severityStats := r.calculateSeverityStats(results.Results)
	resourceStats := r.calculateResourceGroupingStats(results.Results)

	// Calculate overall metrics
	totalEvaluations := len(results.Results)
	passedEvaluations := results.Passed
	failedEvaluations := results.Failed
	successRate := 0.0
	if totalEvaluations > 0 {
		successRate = float64(passedEvaluations) / float64(totalEvaluations) * 100
	}
	overallGrade := r.calculateOverallGrade(successRate)
	overallRiskScore := r.calculateOverallRiskScore(results.Results)

	// Collect unique rules
	rulesMap := make(map[string]*models.ValidationResult)
	for i := range results.Results {
		result := &results.Results[i]
		if _, exists := rulesMap[result.RuleID]; !exists {
			rulesMap[result.RuleID] = result
		}
	}

	// Build SARIF rules
	sarifRules := make([]SARIFRule, 0, len(rulesMap))
	ruleIndexMap := make(map[string]int)
	index := 0
	for ruleID, result := range rulesMap {
		sarifRule := SARIFRule{
			ID:   ruleID,
			Name: result.RuleName,
			ShortDescription: SARIFMessage{
				Text: result.RuleName,
			},
			DefaultConfiguration: SARIFConfiguration{
				Level: r.severityToSARIFLevel(result.Severity),
			},
			Properties: map[string]interface{}{
				"category": result.Category,
				"severity": string(result.Severity),
			},
		}

		if result.Remediation != "" {
			sarifRule.Help = SARIFMessage{
				Text: result.Remediation,
			}
		}

		sarifRules = append(sarifRules, sarifRule)
		ruleIndexMap[ruleID] = index
		index++
	}

	// Build SARIF results
	sarifResults := make([]SARIFResult, 0, len(results.Results))
	for _, result := range results.Results {
		if result.Passed {
			continue // Only include failed results in SARIF
		}

		sarifResult := SARIFResult{
			RuleID:    result.RuleID,
			RuleIndex: ruleIndexMap[result.RuleID],
			Level:     r.severityToSARIFLevel(result.Severity),
			Message: SARIFMessage{
				Text: result.Message,
			},
			Locations: []SARIFLocation{
				{
					PhysicalLocation: SARIFPhysicalLocation{
						ArtifactLocation: SARIFArtifactLocation{
							URI: r.buildResourceURI(result.Resource),
						},
					},
					LogicalLocations: []SARIFLogicalLocation{
						{
							Name:               r.getResourceName(result.Resource),
							Kind:               "resource",
							FullyQualifiedName: r.getResourceFQN(result.Resource),
						},
					},
				},
			},
			Properties: map[string]interface{}{
				"timestamp": result.Timestamp.Format("2006-01-02T15:04:05Z"),
				"category":  result.Category,
			},
		}

		sarifResults = append(sarifResults, sarifResult)
	}

	// Build enhanced invocation with comprehensive statistics
	invocation := SARIFInvocation{
		ExecutionSuccessful: results.Failed == 0,
		StartTimeUtc:        results.Timestamp.Format("2006-01-02T15:04:05Z"),
		EndTimeUtc:          results.Timestamp.Add(results.Duration).Format("2006-01-02T15:04:05Z"),
	}

	return &SARIFReport{
		Version: "2.1.0",
		Schema:  "https://json.schemastore.org/sarif-2.1.0.json",
		Runs: []SARIFRun{
			{
				Tool: SARIFTool{
					Driver: SARIFDriver{
						Name:           "Spotter",
						Version:        "1.0.0",
						InformationUri: "https://github.com/madhuakula/spotter",
						Rules:          sarifRules,
					},
				},
				Results:     sarifResults,
				Invocations: []SARIFInvocation{invocation},
				Properties: map[string]interface{}{
					"summary": map[string]interface{}{
						"total_evaluations":  totalEvaluations,
						"passed_evaluations": passedEvaluations,
						"failed_evaluations": failedEvaluations,
						"success_rate":       successRate,
						"overall_grade":      overallGrade,
						"overall_risk_score": overallRiskScore,
					},
					"category_scoring":  categoryStats,
					"severity_analysis": severityStats,
					"resource_grouping": resourceStats,
				},
			},
		},
	}
}

// severityToSARIFLevel converts severity level to SARIF level
func (r *SARIFReporter) severityToSARIFLevel(severity models.SeverityLevel) string {
	switch severity {
	case models.SeverityLow:
		return "note"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityHigh:
		return "error"
	case models.SeverityCritical:
		return "error"
	default:
		return "warning"
	}
}

// buildResourceURI creates a URI for the resource
func (r *SARIFReporter) buildResourceURI(resource map[string]interface{}) string {
	var parts []string

	if kind, ok := resource["kind"].(string); ok {
		parts = append(parts, strings.ToLower(kind))
	}

	if metadata, ok := resource["metadata"].(map[string]interface{}); ok {
		if namespace, ok := metadata["namespace"].(string); ok && namespace != "" {
			parts = append(parts, namespace)
		}
		if name, ok := metadata["name"].(string); ok {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return "unknown-resource"
	}

	return strings.Join(parts, "/")
}

// Helper methods for SARIF reporter

func (r *SARIFReporter) calculateOverallGrade(successRate float64) string {
	if successRate >= 95 {
		return "A+"
	} else if successRate >= 90 {
		return "A"
	} else if successRate >= 85 {
		return "B+"
	} else if successRate >= 80 {
		return "B"
	} else if successRate >= 75 {
		return "C+"
	} else if successRate >= 70 {
		return "C"
	} else if successRate >= 65 {
		return "D+"
	} else if successRate >= 60 {
		return "D"
	}
	return "F"
}

func (r *SARIFReporter) calculateOverallRiskScore(results []models.ValidationResult) float64 {
	if len(results) == 0 {
		return 0.0
	}

	totalRisk := 0.0
	count := 0

	for _, result := range results {
		if !result.Passed {
			severityMultiplier := map[models.SeverityLevel]float64{
				models.SeverityCritical: 4.0,
				models.SeverityHigh:     3.0,
				models.SeverityMedium:   2.0,
				models.SeverityLow:      1.0,
			}
			if multiplier, exists := severityMultiplier[result.Severity]; exists {
				totalRisk += multiplier
				count++
			}
		}
	}

	if count == 0 {
		return 0.0
	}

	return totalRisk / float64(count)
}

func (r *SARIFReporter) calculateCategoryStats(results []models.ValidationResult) map[string]CategoryStat {
	categoryStats := make(map[string]CategoryStat)

	for _, result := range results {
		category := result.Category
		if category == "" {
			category = "Uncategorized"
		}

		stat := categoryStats[category]
		stat.Category = category
		stat.Total++
		if !result.Passed {
			stat.Failed++
		}
		categoryStats[category] = stat
	}

	// Calculate derived metrics
	for category, stat := range categoryStats {
		if stat.Total > 0 {
			stat.FailureRate = float64(stat.Failed) / float64(stat.Total) * 100
			stat.Score = 100 - stat.FailureRate
			stat.Grade = r.calculateGrade(stat.Score)
		}
		categoryStats[category] = stat
	}

	return categoryStats
}

func (r *SARIFReporter) calculateSeverityStats(results []models.ValidationResult) map[string]SeverityStat {
	severityStats := make(map[string]SeverityStat)

	for _, result := range results {
		severity := string(result.Severity)
		if severity == "" {
			severity = "UNKNOWN"
		}

		stat := severityStats[severity]
		stat.Severity = severity
		stat.Total++
		if !result.Passed {
			stat.Failed++
		}
		severityStats[severity] = stat
	}

	// Calculate derived metrics
	for severity, stat := range severityStats {
		if stat.Total > 0 {
			stat.FailureRate = float64(stat.Failed) / float64(stat.Total) * 100
			stat.RiskScore = r.calculateRiskScore(models.SeverityLevel(severity), stat.FailureRate)
			stat.Impact = r.calculateImpact(stat.RiskScore)
		}
		severityStats[severity] = stat
	}

	return severityStats
}

func (r *SARIFReporter) calculateResourceGroupingStats(results []models.ValidationResult) map[string]ResourceStat {
	resourceStats := make(map[string]ResourceStat)

	for _, result := range results {
		// Extract resource type and namespace from resource metadata
		resourceType := "Unknown"
		namespace := "default"

		if result.Resource != nil {
			if kind, ok := result.Resource["kind"].(string); ok {
				resourceType = kind
			}
			if metadata, ok := result.Resource["metadata"].(map[string]interface{}); ok {
				if ns, ok := metadata["namespace"].(string); ok && ns != "" {
					namespace = ns
				}
			}
		}

		key := fmt.Sprintf("%s/%s", resourceType, namespace)
		stat := resourceStats[key]
		stat.ResourceType = resourceType
		stat.Namespace = namespace
		stat.TotalCount++
		if !result.Passed {
			stat.FailedCount++
		}
		resourceStats[key] = stat
	}

	// Calculate derived metrics
	for key, stat := range resourceStats {
		if stat.TotalCount > 0 {
			stat.FailureRate = float64(stat.FailedCount) / float64(stat.TotalCount) * 100
			stat.RiskLevel = r.calculateResourceRiskLevel(stat.FailureRate, stat.FailedCount)
		}
		resourceStats[key] = stat
	}

	return resourceStats
}

func (r *SARIFReporter) calculateGrade(score float64) string {
	if score >= 95 {
		return "A+"
	} else if score >= 90 {
		return "A"
	} else if score >= 85 {
		return "B+"
	} else if score >= 80 {
		return "B"
	} else if score >= 75 {
		return "C+"
	} else if score >= 70 {
		return "C"
	} else if score >= 65 {
		return "D+"
	} else if score >= 60 {
		return "D"
	}
	return "F"
}

func (r *SARIFReporter) calculateRiskScore(severity models.SeverityLevel, failureRate float64) float64 {
	severityMultiplier := map[models.SeverityLevel]float64{
		models.SeverityCritical: 4.0,
		models.SeverityHigh:     3.0,
		models.SeverityMedium:   2.0,
		models.SeverityLow:      1.0,
	}

	multiplier, exists := severityMultiplier[severity]
	if !exists {
		multiplier = 1.0
	}

	return (failureRate / 100.0) * multiplier * 10.0
}

func (r *SARIFReporter) calculateImpact(riskScore float64) string {
	if riskScore >= 8.0 {
		return "CRITICAL"
	} else if riskScore >= 6.0 {
		return "HIGH"
	} else if riskScore >= 4.0 {
		return "MEDIUM"
	} else if riskScore >= 2.0 {
		return "LOW"
	}
	return "MINIMAL"
}

func (r *SARIFReporter) calculateResourceRiskLevel(failureRate float64, failedCount int) string {
	if failureRate >= 80 && failedCount >= 5 {
		return "CRITICAL"
	} else if failureRate >= 60 && failedCount >= 3 {
		return "HIGH"
	} else if failureRate >= 40 && failedCount >= 2 {
		return "MEDIUM"
	} else if failureRate >= 20 || failedCount >= 1 {
		return "LOW"
	}
	return "MINIMAL"
}

// getResourceName extracts the resource name
func (r *SARIFReporter) getResourceName(resource map[string]interface{}) string {
	if metadata, ok := resource["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			return name
		}
	}
	return "unknown"
}

// getResourceFQN creates a fully qualified name for the resource
func (r *SARIFReporter) getResourceFQN(resource map[string]interface{}) string {
	var parts []string

	if apiVersion, ok := resource["apiVersion"].(string); ok {
		parts = append(parts, apiVersion)
	}

	if kind, ok := resource["kind"].(string); ok {
		parts = append(parts, kind)
	}

	if metadata, ok := resource["metadata"].(map[string]interface{}); ok {
		if namespace, ok := metadata["namespace"].(string); ok && namespace != "" {
			parts = append(parts, namespace)
		}
		if name, ok := metadata["name"].(string); ok {
			parts = append(parts, name)
		}
	}

	if len(parts) == 0 {
		return "unknown"
	}

	return strings.Join(parts, "/")
}
