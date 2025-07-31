package reporter

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/madhuakula/spotter/pkg/models"
	"gopkg.in/yaml.v3"
)

// YAMLReporter implements the Reporter interface for YAML output
type YAMLReporter struct{}

// NewYAMLReporter creates a new YAML reporter
func NewYAMLReporter() Reporter {
	return &YAMLReporter{}
}

// GetFormat returns the format name
func (r *YAMLReporter) GetFormat() string {
	return "yaml"
}

// GetFileExtension returns the file extension
func (r *YAMLReporter) GetFileExtension() string {
	return ".yaml"
}

// GenerateReport generates a YAML report from scan results
func (r *YAMLReporter) GenerateReport(ctx context.Context, results *models.ScanResult) ([]byte, error) {
	yamlReport := r.buildYAMLReport(results)

	data, err := yaml.Marshal(yamlReport)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal YAML report: %w", err)
	}

	return data, nil
}

// WriteReport writes the YAML report to the configured writer
func (r *YAMLReporter) WriteReport(ctx context.Context, results *models.ScanResult, writer io.Writer) error {
	data, err := r.GenerateReport(ctx, results)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write YAML report: %w", err)
	}

	return nil
}

// YAML report structures
type YAMLReport struct {
	Metadata         YAMLMetadata            `yaml:"metadata"`
	Summary          YAMLSummary             `yaml:"summary"`
	CategoryScoring  map[string]CategoryStat `yaml:"category_scoring"`
	SeverityAnalysis map[string]SeverityStat `yaml:"severity_analysis"`
	ResourceGrouping map[string]ResourceStat `yaml:"resource_grouping"`
	Results          []YAMLResult            `yaml:"results"`
}

type YAMLMetadata struct {
	Tool      string    `yaml:"tool"`
	Version   string    `yaml:"version"`
	Timestamp time.Time `yaml:"timestamp"`
	Duration  string    `yaml:"duration"`
}

type YAMLSummary struct {
	TotalResources    int            `yaml:"total_resources"`
	TotalRules        int            `yaml:"total_rules"`
	TotalEvaluations  int            `yaml:"total_evaluations"`
	PassedEvaluations int            `yaml:"passed_evaluations"`
	FailedEvaluations int            `yaml:"failed_evaluations"`
	SuccessRate       float64        `yaml:"success_rate"`
	OverallGrade      string         `yaml:"overall_grade"`
	RiskScore         float64        `yaml:"risk_score"`
	SeverityBreakdown map[string]int `yaml:"severity_breakdown"`
	CategoryBreakdown map[string]int `yaml:"category_breakdown"`
}

type YAMLResult struct {
	RuleID      string       `yaml:"rule_id"`
	RuleName    string       `yaml:"rule_name"`
	Category    string       `yaml:"category"`
	Severity    string       `yaml:"severity"`
	Passed      bool         `yaml:"passed"`
	Message     string       `yaml:"message"`
	Remediation string       `yaml:"remediation,omitempty"`
	Resource    YAMLResource `yaml:"resource"`
	Timestamp   time.Time    `yaml:"timestamp"`
}

type YAMLResource struct {
	Kind      string `yaml:"kind"`
	Name      string `yaml:"name"`
	Namespace string `yaml:"namespace,omitempty"`
}

// buildYAMLReport constructs the YAML report structure
func (r *YAMLReporter) buildYAMLReport(results *models.ScanResult) *YAMLReport {
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

	// Build severity and category breakdowns
	severityBreakdown := make(map[string]int)
	categoryBreakdown := make(map[string]int)

	for _, result := range results.Results {
		if !result.Passed {
			severityBreakdown[string(result.Severity)]++
			categoryBreakdown[result.Category]++
		}
	}

	// Build YAML results
	yamlResults := make([]YAMLResult, 0, len(results.Results))
	for _, result := range results.Results {
		yamlResult := YAMLResult{
			RuleID:      result.RuleID,
			RuleName:    result.RuleName,
			Category:    result.Category,
			Severity:    string(result.Severity),
			Passed:      result.Passed,
			Message:     result.Message,
			Remediation: result.Remediation,
			Resource:    r.extractYAMLResource(result.Resource),
			Timestamp:   result.Timestamp,
		}
		yamlResults = append(yamlResults, yamlResult)
	}

	return &YAMLReport{
		Metadata: YAMLMetadata{
			Tool:      "Spotter",
			Version:   "1.0.0",
			Timestamp: results.Timestamp,
			Duration:  results.Duration.String(),
		},
		Summary: YAMLSummary{
			TotalResources:    results.TotalResources,
			TotalRules:        results.TotalRules,
			TotalEvaluations:  totalEvaluations,
			PassedEvaluations: passedEvaluations,
			FailedEvaluations: failedEvaluations,
			SuccessRate:       successRate,
			OverallGrade:      overallGrade,
			RiskScore:         overallRiskScore,
			SeverityBreakdown: severityBreakdown,
			CategoryBreakdown: categoryBreakdown,
		},
		CategoryScoring:  categoryStats,
		SeverityAnalysis: severityStats,
		ResourceGrouping: resourceStats,
		Results:          yamlResults,
	}
}

// extractYAMLResource extracts resource information for YAML output
func (r *YAMLReporter) extractYAMLResource(resource map[string]interface{}) YAMLResource {
	yamlResource := YAMLResource{
		Kind:      "Unknown",
		Name:      "Unknown",
		Namespace: "",
	}

	if resource != nil {
		if kind, ok := resource["kind"].(string); ok {
			yamlResource.Kind = kind
		}

		if metadata, ok := resource["metadata"].(map[string]interface{}); ok {
			if name, ok := metadata["name"].(string); ok {
				yamlResource.Name = name
			}
			if namespace, ok := metadata["namespace"].(string); ok {
				yamlResource.Namespace = namespace
			}
		}
	}

	return yamlResource
}

// Helper methods for YAML reporter

func (r *YAMLReporter) calculateOverallGrade(successRate float64) string {
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

func (r *YAMLReporter) calculateOverallRiskScore(results []models.ValidationResult) float64 {
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

func (r *YAMLReporter) calculateCategoryStats(results []models.ValidationResult) map[string]CategoryStat {
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

func (r *YAMLReporter) calculateSeverityStats(results []models.ValidationResult) map[string]SeverityStat {
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

func (r *YAMLReporter) calculateResourceGroupingStats(results []models.ValidationResult) map[string]ResourceStat {
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

func (r *YAMLReporter) calculateGrade(score float64) string {
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

func (r *YAMLReporter) calculateRiskScore(severity models.SeverityLevel, failureRate float64) float64 {
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

func (r *YAMLReporter) calculateImpact(riskScore float64) string {
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

func (r *YAMLReporter) calculateResourceRiskLevel(failureRate float64, failedCount int) string {
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
