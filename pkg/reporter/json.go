package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/version"
)

// ResourceStat represents resource statistics for JSON output
type ResourceStat struct {
	ResourceType string  `json:"resource_type"`
	Namespace    string  `json:"namespace"`
	FailedCount  int     `json:"failed_count"`
	TotalCount   int     `json:"total_count"`
	FailureRate  float64 `json:"failure_rate"`
	RiskLevel    string  `json:"risk_level"`
}

// JSONReporter implements the Reporter interface for JSON output
type JSONReporter struct{}

// NewJSONReporter creates a new JSON reporter
func NewJSONReporter() Reporter {
	return &JSONReporter{}
}

// GenerateReport generates a JSON report from scan results
func (r *JSONReporter) GenerateReport(ctx context.Context, results *models.ScanResult) ([]byte, error) {
	report := r.buildJSONReport(results)

	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal JSON report: %w", err)
	}

	return data, nil
}

// WriteReport writes the JSON report to the configured writer
func (r *JSONReporter) WriteReport(ctx context.Context, results *models.ScanResult, writer io.Writer) error {
	data, err := r.GenerateReport(ctx, results)
	if err != nil {
		return err
	}

	_, err = writer.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write JSON report: %w", err)
	}

	return nil
}

// JSONReport represents the structure of the JSON output
type JSONReport struct {
	Metadata         JSONMetadata            `json:"metadata"`
	Summary          JSONSummary             `json:"summary"`
	CategoryScoring  map[string]CategoryStat `json:"category_scoring"`
	SeverityAnalysis map[string]SeverityStat `json:"severity_analysis"`
	ResourceGrouping map[string]ResourceStat `json:"resource_grouping"`
	Results          []JSONResult            `json:"results"`
}

// JSONMetadata contains metadata about the scan
type JSONMetadata struct {
	Timestamp time.Time `json:"timestamp"`
	Version   string    `json:"version"`
	Duration  string    `json:"duration"`
}

// JSONSummary contains summary statistics
type JSONSummary struct {
	TotalResources    int            `json:"total_resources"`
	TotalRules        int            `json:"total_rules"`
	Passed            int            `json:"passed"`
	Failed            int            `json:"failed"`
	SuccessRate       float64        `json:"success_rate"`
	OverallGrade      string         `json:"overall_grade"`
	RiskScore         float64        `json:"risk_score"`
	SeverityBreakdown map[string]int `json:"severity_breakdown"`
	CategoryBreakdown map[string]int `json:"category_breakdown"`
}

// JSONResult represents a single validation result
type JSONResult struct {
	RuleID      string               `json:"rule_id"`
	RuleName    string               `json:"rule_name"`
	Severity    models.SeverityLevel `json:"severity"`
	Category    string               `json:"category"`
	Passed      bool                 `json:"passed"`
	Message     string               `json:"message"`
	Remediation string               `json:"remediation,omitempty"`
	Resource    JSONResource         `json:"resource"`
	Timestamp   time.Time            `json:"timestamp"`
}

// JSONResource represents the resource information
type JSONResource struct {
	APIVersion string                 `json:"api_version"`
	Kind       string                 `json:"kind"`
	Namespace  string                 `json:"namespace,omitempty"`
	Name       string                 `json:"name"`
	Labels     map[string]interface{} `json:"labels,omitempty"`
}

// extractResourceInfo extracts resource information from the resource map
func (r *JSONReporter) extractResourceInfo(resource map[string]interface{}) JSONResource {
	jsonResource := JSONResource{}

	if apiVersion, ok := resource["apiVersion"].(string); ok {
		jsonResource.APIVersion = apiVersion
	}
	if kind, ok := resource["kind"].(string); ok {
		jsonResource.Kind = kind
	}

	// Extract metadata
	if metadata, ok := resource["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			jsonResource.Name = name
		}
		if namespace, ok := metadata["namespace"].(string); ok {
			jsonResource.Namespace = namespace
		}
		if labels, ok := metadata["labels"].(map[string]interface{}); ok {
			jsonResource.Labels = labels
		}
	}

	return jsonResource
}

// GetFormat returns the format name
func (r *JSONReporter) GetFormat() string {
	return "json"
}

// GetFileExtension returns the file extension
func (r *JSONReporter) GetFileExtension() string {
	return ".json"
}

// buildJSONReport constructs the JSON report structure
func (r *JSONReporter) buildJSONReport(results *models.ScanResult) *JSONReport {
	// Calculate enhanced metrics
	totalEvaluations := results.Passed + results.Failed
	successRate := float64(0)
	if totalEvaluations > 0 {
		successRate = float64(results.Passed) / float64(totalEvaluations) * 100
	}

	// Calculate overall grade and risk score
	overallGrade := r.calculateOverallGrade(successRate)
	riskScore := r.calculateOverallRiskScore(results.Results)

	report := &JSONReport{
		Metadata: JSONMetadata{
			Timestamp: results.Timestamp,
			Version:   version.GetVersion(),
			Duration:  results.Duration.String(),
		},
		Summary: JSONSummary{
			TotalResources:    results.TotalResources,
			TotalRules:        results.TotalRules,
			Passed:            results.Passed,
			Failed:            results.Failed,
			SuccessRate:       successRate,
			OverallGrade:      overallGrade,
			RiskScore:         riskScore,
			SeverityBreakdown: results.SeverityBreakdown,
			CategoryBreakdown: results.CategoryBreakdown,
		},
		CategoryScoring:  r.calculateCategoryStats(results.Results),
		SeverityAnalysis: r.calculateSeverityStats(results.Results),
		ResourceGrouping: r.calculateResourceGroupingStats(results.Results),
		Results:          make([]JSONResult, 0, len(results.Results)),
	}

	// Convert validation results
	for _, result := range results.Results {
		jsonResult := JSONResult{
			RuleID:      result.RuleID,
			RuleName:    result.RuleName,
			Severity:    result.Severity,
			Category:    result.Category,
			Passed:      result.Passed,
			Message:     result.Message,
			Remediation: result.Remediation,
			Timestamp:   result.Timestamp,
			Resource:    r.extractResourceInfo(result.Resource),
		}
		report.Results = append(report.Results, jsonResult)
	}

	return report
}

// Helper methods for JSON reporter

func (r *JSONReporter) calculateOverallGrade(successRate float64) string {
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

func (r *JSONReporter) calculateOverallRiskScore(results []models.ValidationResult) float64 {
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

func (r *JSONReporter) calculateCategoryStats(results []models.ValidationResult) map[string]CategoryStat {
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

func (r *JSONReporter) calculateSeverityStats(results []models.ValidationResult) map[string]SeverityStat {
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

func (r *JSONReporter) calculateResourceGroupingStats(results []models.ValidationResult) map[string]ResourceStat {
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

func (r *JSONReporter) calculateGrade(score float64) string {
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

func (r *JSONReporter) calculateRiskScore(severity models.SeverityLevel, failureRate float64) float64 {
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

func (r *JSONReporter) calculateImpact(riskScore float64) string {
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

func (r *JSONReporter) calculateResourceRiskLevel(failureRate float64, failedCount int) string {
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
