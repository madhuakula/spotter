package reporter

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/madhuakula/spotter/pkg/models"
)

// CategoryStat represents statistics for a security category
type CategoryStat struct {
	Category    string
	Failed      int
	Total       int
	Score       float64
	FailureRate float64
	Grade       string
}

// SeverityStat represents statistics for a severity level
type SeverityStat struct {
	Severity    string
	Failed      int
	Total       int
	FailureRate float64
	RiskScore   float64
	Impact      string
}

// ResourceGroupStat represents statistics for resource grouping
type ResourceGroupStat struct {
	ResourceType string
	Namespace    string
	FailedCount  int
	TotalCount   int
	FailureRate  float64
	RiskLevel    string
}

// TableReporter generates reports in table format for console output
type TableReporter struct {
	noColor     bool
	verbose     bool
	quiet       bool
	summaryOnly bool
}

// NewTableReporter creates a new table reporter
func NewTableReporter(noColor, verbose bool) Reporter {
	return &TableReporter{
		noColor:     noColor,
		verbose:     verbose,
		quiet:       false,
		summaryOnly: false,
	}
}

// SetQuiet sets the quiet mode for the table reporter
func (r *TableReporter) SetQuiet(quiet bool) {
	r.quiet = quiet
}

// SetSummaryOnly sets the summary-only mode for the table reporter
func (r *TableReporter) SetSummaryOnly(summaryOnly bool) {
	r.summaryOnly = summaryOnly
}

// GenerateReport generates a table format report
func (r *TableReporter) GenerateReport(ctx context.Context, results *models.ScanResult) ([]byte, error) {
	var output strings.Builder

	// If quiet mode, only show basic summary
	if r.quiet {
		output.WriteString(fmt.Sprintf("Scan completed: %d violations found in %d resources\n", results.Failed, results.TotalResources))
		return []byte(output.String()), nil
	}

	// Header (unless summary-only)
	if !r.summaryOnly {
		output.WriteString(r.formatHeader("Spotter Security Scan Report"))
		output.WriteString("\n")
	}

	// Enhanced Summary with scoring (always shown)
	output.WriteString(r.formatEnhancedSummary(results))
	output.WriteString("\n")

	// If summary-only mode, stop here
	if r.summaryOnly {
		return []byte(output.String()), nil
	}

	// Category-wise scoring table (always shown)
	output.WriteString(r.formatCategoryScoreTable(results))
	output.WriteString("\n")

	// Severity-wise scoring table (always shown)
	output.WriteString(r.formatSeverityScoreTable(results))
	output.WriteString("\n")

	// Resource grouping analysis (always shown)
	output.WriteString(r.formatResourceGroupingTable(results))
	output.WriteString("\n")

	// Findings
	if len(results.Results) > 0 {
		output.WriteString(r.formatFindings(results.Results))
		output.WriteString("\n")

		// AI Recommendations (if available)
		if results.AIRecommendations != nil {
			output.WriteString(r.formatAIRecommendations(results.AIRecommendations))
			output.WriteString("\n")
		}

		// Add actionable summary (always shown)
		output.WriteString(r.formatActionableSummary(results))
	} else {
		output.WriteString(r.colorize("✓ No security issues found!\n", "green"))
	}

	return []byte(output.String()), nil
}

// WriteReport writes the report to the specified writer
func (r *TableReporter) WriteReport(ctx context.Context, results *models.ScanResult, writer io.Writer) error {
	report, err := r.GenerateReport(ctx, results)
	if err != nil {
		return err
	}

	_, err = writer.Write(report)
	return err
}

// GetFormat returns the format name
func (r *TableReporter) GetFormat() string {
	return "table"
}

// GetFileExtension returns the file extension
func (r *TableReporter) GetFileExtension() string {
	return ".txt"
}

// Helper methods

func (r *TableReporter) formatHeader(title string) string {
	line := strings.Repeat("=", len(title)+4)
	return fmt.Sprintf("%s\n  %s  \n%s\n", line, title, line)
}

func (r *TableReporter) formatFindings(results []models.ValidationResult) string {
	var output strings.Builder

	// Categorize findings
	celErrors, securityFindings := r.categorizeFindingsByType(results)

	// Display CEL errors
	if len(celErrors) > 0 {
		output.WriteString(r.colorize("CEL Evaluation Issues\n", "yellow"))
		output.WriteString(strings.Repeat("-", 80) + "\n")

		if r.verbose {
			// Show all CEL errors in verbose mode
			for i, result := range celErrors {
				output.WriteString(r.formatCELError(&result, i+1))
				output.WriteString("\n")
			}
		} else {
			// Show only first 3 CEL errors to avoid overwhelming output
			maxCELErrors := 3
			showCount := len(celErrors)
			if showCount > maxCELErrors {
				showCount = maxCELErrors
			}

			for i := 0; i < showCount; i++ {
				output.WriteString(r.formatCELErrorBrief(&celErrors[i], i+1))
				output.WriteString("\n")
			}

			if len(celErrors) > maxCELErrors {
				output.WriteString(r.colorize(fmt.Sprintf("... and %d more CEL evaluation issues\n", len(celErrors)-maxCELErrors), "yellow"))
				output.WriteString(r.colorize("Use --verbose flag to see all CEL errors\n", "cyan"))
			}
		}
		output.WriteString("\n")
	}

	// Display security findings
	if len(securityFindings) > 0 {
		// Sort results by severity (critical first)
		sortedResults := make([]models.ValidationResult, len(securityFindings))
		copy(sortedResults, securityFindings)
		sort.Slice(sortedResults, func(i, j int) bool {
			return r.severityWeight(sortedResults[i].Severity) > r.severityWeight(sortedResults[j].Severity)
		})

		if r.verbose {
			// Show hierarchical security findings in verbose mode
			output.WriteString(r.formatHierarchicalSecurityFindings(sortedResults))
		} else {
			// Show concise hierarchical security findings in non-verbose mode
			output.WriteString(r.formatConciseHierarchicalSecurityFindings(sortedResults))
		}
	}

	return output.String()
}

func (r *TableReporter) formatCELErrorBrief(result *models.ValidationResult, index int) string {
	var output strings.Builder

	// Brief format for CEL errors
	output.WriteString(fmt.Sprintf("WARNING %d. %s\n",
		index,
		r.colorize(result.RuleID, "yellow")))

	// Resource info
	resourceKind := "unknown"
	resourceName := "unknown"
	if kind, ok := result.Resource["kind"].(string); ok {
		resourceKind = kind
	}
	if metadata, ok := result.Resource["metadata"].(map[string]interface{}); ok {
		if name, ok := metadata["name"].(string); ok {
			resourceName = name
		}
	}

	output.WriteString(fmt.Sprintf("   Resource: %s/%s\n", resourceKind, resourceName))
	output.WriteString(fmt.Sprintf("   Error: %s\n", r.colorize(result.Message, "red")))

	return output.String()
}

func (r *TableReporter) formatCELError(result *models.ValidationResult, index int) string {
	var finding strings.Builder

	// Header for CEL error
	finding.WriteString(fmt.Sprintf("WARNING [%d] %s\n",
		index,
		r.colorize("CEL Evaluation Issue", "yellow")))

	// Rule details
	finding.WriteString(fmt.Sprintf("    Rule ID: %s\n", result.RuleID))
	if result.RuleName != "" {
		finding.WriteString(fmt.Sprintf("    Rule Name: %s\n", result.RuleName))
	}

	// Resource info
	if resourceKind, ok := result.Resource["kind"].(string); ok {
		resourceName := "unknown"
		if metadata, ok := result.Resource["metadata"].(map[string]interface{}); ok {
			if name, ok := metadata["name"].(string); ok {
				resourceName = name
			}
			if namespace, ok := metadata["namespace"].(string); ok && namespace != "" {
				finding.WriteString(fmt.Sprintf("    Namespace: %s\n", namespace))
			}
		}
		finding.WriteString(fmt.Sprintf("    Resource: %s/%s\n", resourceKind, resourceName))
	}

	// Error message
	if result.Message != "" {
		finding.WriteString(fmt.Sprintf("    Error: %s\n", result.Message))
	}

	// Actionable guidance for CEL errors
	finding.WriteString(r.colorize("    Suggested Actions:\n", "cyan"))
	if strings.Contains(result.Message, "no such key") {
		finding.WriteString("       • Check if the resource has the expected structure\n")
		finding.WriteString("       • Verify the CEL expression references correct field names\n")
		finding.WriteString("       • Consider adding null checks in the rule expression\n")
	} else if strings.Contains(result.Message, "type") {
		finding.WriteString("       • Verify data types in the CEL expression\n")
		finding.WriteString("       • Check for type conversion issues\n")
	} else {
		finding.WriteString("       • Review the rule's CEL expression syntax\n")
		finding.WriteString("       • Check rule documentation for proper usage\n")
	}

	return finding.String()
}

// formatHierarchicalSecurityFindings creates a hierarchical view of security findings
// organized by category > severity > rule with concise, actionable data
// formatConciseHierarchicalSecurityFindings creates a concise hierarchical view for non-verbose mode
func (r *TableReporter) formatConciseHierarchicalSecurityFindings(results []models.ValidationResult) string {
	var output strings.Builder

	output.WriteString(r.colorize("🔍 Top Security Findings\n", "red"))
	output.WriteString(strings.Repeat("-", 80) + "\n")

	// Group findings by severity -> rule
	severityMap := make(map[models.SeverityLevel]map[string][]models.ValidationResult)

	for _, result := range results {
		if severityMap[result.Severity] == nil {
			severityMap[result.Severity] = make(map[string][]models.ValidationResult)
		}
		if severityMap[result.Severity][result.RuleName] == nil {
			severityMap[result.Severity][result.RuleName] = []models.ValidationResult{}
		}
		severityMap[result.Severity][result.RuleName] = append(
			severityMap[result.Severity][result.RuleName], result)
	}

	// Sort severities by weight (critical first)
	var severities []models.SeverityLevel
	for severity := range severityMap {
		severities = append(severities, severity)
	}
	sort.Slice(severities, func(i, j int) bool {
		return r.severityWeight(severities[i]) > r.severityWeight(severities[j])
	})

	// Track displayed findings to limit output
	displayedFindings := 0
	maxFindings := 10

	for _, severity := range severities {
		if displayedFindings >= maxFindings {
			break
		}

		ruleMap := severityMap[severity]
		severityColor := r.getSeverityColor(severity)

		// Count total findings for this severity
		severityCount := 0
		for _, findings := range ruleMap {
			severityCount += len(findings)
		}

		// Severity header
		severityEmoji := r.getSeverityEmoji(severity)
		output.WriteString(fmt.Sprintf("\n%s %s (%d findings)\n",
			severityEmoji,
			r.colorize(string(severity), severityColor),
			severityCount))
		output.WriteString(strings.Repeat("─", 50) + "\n")

		// Sort rules by finding count
		type ruleInfo struct {
			name  string
			count int
		}
		var rules []ruleInfo
		for ruleName, findings := range ruleMap {
			rules = append(rules, ruleInfo{name: ruleName, count: len(findings)})
		}
		sort.Slice(rules, func(i, j int) bool {
			return rules[i].count > rules[j].count
		})

		// Show top rules for this severity
		maxRulesPerSeverity := 3
		for i, ruleInfo := range rules {
			if i >= maxRulesPerSeverity || displayedFindings >= maxFindings {
				if len(rules) > maxRulesPerSeverity {
					output.WriteString(fmt.Sprintf("  %s\n",
						r.colorize(fmt.Sprintf("... and %d more rules", len(rules)-maxRulesPerSeverity), "yellow")))
				}
				break
			}

			ruleName := ruleInfo.name
			findings := ruleMap[ruleName]

			// Rule header with count
			output.WriteString(fmt.Sprintf("[%d] [%s] %s\n",
				displayedFindings+1,
				r.colorize(string(severity), severityColor),
				ruleName))

			// Show first affected resource
			if len(findings) > 0 {
				finding := findings[0]
				resourceKind := "unknown"
				resourceName := "unknown"

				if kind, ok := finding.Resource["kind"].(string); ok {
					resourceKind = kind
				}
				if metadata, ok := finding.Resource["metadata"].(map[string]interface{}); ok {
					if name, ok := metadata["name"].(string); ok {
						resourceName = name
					}
				}

				output.WriteString(fmt.Sprintf("   Resource: %s/%s\n", resourceKind, resourceName))

				// Show unique issue message (truncated)
				if finding.Message != "" {
					message := finding.Message
					if len(message) > 100 {
						message = message[:97] + "..."
					}
					output.WriteString(fmt.Sprintf("   Issue: %s\n", message))
				}

				// Show count if multiple resources affected
				uniqueResourceCount := r.getUniqueResourceCount(findings)
				if uniqueResourceCount > 1 {
					output.WriteString(fmt.Sprintf("   %s\n",
						r.colorize(fmt.Sprintf("Affects %d resources total", uniqueResourceCount), "yellow")))
				}
			}

			output.WriteString("\n")
			displayedFindings++
		}
	}

	// Show summary if there are more findings
	totalFindings := len(results)
	if displayedFindings < totalFindings {
		output.WriteString(r.colorize(fmt.Sprintf("... and %d more security findings\n", totalFindings-displayedFindings), "red"))
		output.WriteString(r.colorize("Use --verbose flag to see all findings or filter by --min-severity\n", "cyan"))
	}

	return output.String()
}

func (r *TableReporter) formatHierarchicalSecurityFindings(results []models.ValidationResult) string {
	var output strings.Builder

	output.WriteString(r.colorize("Security Findings (Hierarchical View)\n", "red"))
	output.WriteString(strings.Repeat("═", 80) + "\n")

	// Group findings by category -> severity -> rule
	categoryMap := make(map[string]map[models.SeverityLevel]map[string][]models.ValidationResult)

	for _, result := range results {
		category := result.Category
		if category == "" {
			category = "Uncategorized"
		}

		if categoryMap[category] == nil {
			categoryMap[category] = make(map[models.SeverityLevel]map[string][]models.ValidationResult)
		}
		if categoryMap[category][result.Severity] == nil {
			categoryMap[category][result.Severity] = make(map[string][]models.ValidationResult)
		}
		if categoryMap[category][result.Severity][result.RuleName] == nil {
			categoryMap[category][result.Severity][result.RuleName] = []models.ValidationResult{}
		}
		categoryMap[category][result.Severity][result.RuleName] = append(
			categoryMap[category][result.Severity][result.RuleName], result)
	}

	// Sort categories by total failure count
	type categoryInfo struct {
		name  string
		count int
	}
	var categories []categoryInfo
	for category, severityMap := range categoryMap {
		totalCount := 0
		for _, ruleMap := range severityMap {
			for _, findings := range ruleMap {
				totalCount += len(findings)
			}
		}
		categories = append(categories, categoryInfo{name: category, count: totalCount})
	}
	sort.Slice(categories, func(i, j int) bool {
		return categories[i].count > categories[j].count
	})

	// Display hierarchical findings
	for _, catInfo := range categories {
		category := catInfo.name
		severityMap := categoryMap[category]

		// Category header
		categoryEmoji := r.getCategoryEmoji(category)
		output.WriteString(fmt.Sprintf("\n%s [%s] (%d findings)\n",
			categoryEmoji,
			r.colorize(category, "cyan"), catInfo.count))
		output.WriteString(strings.Repeat("─", 60) + "\n")

		// Sort severities by weight (critical first)
		var severities []models.SeverityLevel
		for severity := range severityMap {
			severities = append(severities, severity)
		}
		sort.Slice(severities, func(i, j int) bool {
			return r.severityWeight(severities[i]) > r.severityWeight(severities[j])
		})

		for _, severity := range severities {
			ruleMap := severityMap[severity]
			severityColor := r.getSeverityColor(severity)

			// Count total findings for this severity
			severityCount := 0
			for _, findings := range ruleMap {
				severityCount += len(findings)
			}

			// Severity header
			severityEmoji := r.getSeverityEmoji(severity)
			output.WriteString(fmt.Sprintf("  %s %s (%d findings)\n",
				severityEmoji,
				r.colorize(string(severity), severityColor),
				severityCount))

			// Sort rules by finding count
			type ruleInfo struct {
				name  string
				count int
			}
			var rules []ruleInfo
			for ruleName, findings := range ruleMap {
				rules = append(rules, ruleInfo{name: ruleName, count: len(findings)})
			}
			sort.Slice(rules, func(i, j int) bool {
				return rules[i].count > rules[j].count
			})

			for _, ruleInfo := range rules {
				ruleName := ruleInfo.name
				findings := ruleMap[ruleName]

				// Rule header
				output.WriteString(fmt.Sprintf("    🔧 [FIX] %s (%d resources)\n",
					r.colorize(ruleName, "white"), len(findings)))

				// Show affected resources (limit to 5 per rule for conciseness)
				maxResources := 5
				uniqueResourceCount := r.getUniqueResourceCount(findings)
				for i, finding := range findings {
					if i >= maxResources {
						remainingResources := uniqueResourceCount - maxResources
						if remainingResources > 0 {
							output.WriteString(fmt.Sprintf("      %s\n",
								r.colorize(fmt.Sprintf("... and %d more resources", remainingResources), "yellow")))
						}
						break
					}

					// Extract resource info
					resourceKind := "unknown"
					resourceName := "unknown"
					namespace := ""

					if kind, ok := finding.Resource["kind"].(string); ok {
						resourceKind = kind
					}
					if metadata, ok := finding.Resource["metadata"].(map[string]interface{}); ok {
						if name, ok := metadata["name"].(string); ok {
							resourceName = name
						}
						if ns, ok := metadata["namespace"].(string); ok && ns != "" {
							namespace = ns
						}
					}

					// Format resource line
					resourceInfo := fmt.Sprintf("%s/%s", resourceKind, resourceName)
					if namespace != "" {
						resourceInfo += fmt.Sprintf(" (ns: %s)", namespace)
					}

					output.WriteString(fmt.Sprintf("      📋 %s\n", resourceInfo))
				}

				// Show unique issue messages once per rule to avoid repetition
				uniqueMessages := r.getUniqueMessages(findings)
				for _, message := range uniqueMessages {
					if len(message) > 80 {
						message = message[:77] + "..."
					}
					output.WriteString(fmt.Sprintf("        %s\n",
						r.colorize(message, "yellow")))
				}

				// Show remediation if available
				if len(findings) > 0 && findings[0].Remediation != "" {
					remediation := findings[0].Remediation
					if len(remediation) > 100 {
						remediation = remediation[:97] + "..."
					}
					output.WriteString(fmt.Sprintf("      ✅ %s %s\n",
						r.colorize("Fix:", "green"), remediation))
				}
				output.WriteString("\n")
			}
		}
	}

	return output.String()
}

// categorizeFindingsByType separates CEL errors from actual security findings
func (r *TableReporter) categorizeFindingsByType(results []models.ValidationResult) ([]models.ValidationResult, []models.ValidationResult) {
	var celErrors []models.ValidationResult
	var securityFindings []models.ValidationResult

	for _, result := range results {
		if !result.Passed {
			if strings.Contains(result.Message, "CEL evaluation error") {
				celErrors = append(celErrors, result)
			} else {
				securityFindings = append(securityFindings, result)
			}
		}
	}

	return celErrors, securityFindings
}

func (r *TableReporter) getSeverityColor(severity models.SeverityLevel) string {
	switch severity {
	case models.SeverityCritical:
		return "red"
	case models.SeverityHigh:
		return "orange"
	case models.SeverityMedium:
		return "yellow"
	case models.SeverityLow:
		return "blue"
	default:
		return "white"
	}
}

func (r *TableReporter) getSeverityEmoji(severity models.SeverityLevel) string {
	switch severity {
	case models.SeverityCritical:
		return "🔴"
	case models.SeverityHigh:
		return "🟠"
	case models.SeverityMedium:
		return "🟡"
	case models.SeverityLow:
		return "🔵"
	default:
		return "⚪"
	}
}

func (r *TableReporter) severityWeight(severity models.SeverityLevel) int {
	switch severity {
	case models.SeverityCritical:
		return 5
	case models.SeverityHigh:
		return 4
	case models.SeverityMedium:
		return 3
	case models.SeverityLow:
		return 2
	default:
		return 0
	}
}

func (r *TableReporter) formatActionableSummary(results *models.ScanResult) string {
	var summary strings.Builder

	// Categorize findings
	_, securityFindings := r.categorizeFindingsByType(results.Results)

	// Command suggestions only
	summary.WriteString(r.colorize("Useful Commands:\n", "green"))
	summary.WriteString(strings.Repeat("-", 60) + "\n")
	if len(securityFindings) > 0 {
		summary.WriteString("   • Filter by severity: spotter scan cluster --min-severity=high\n")
		summary.WriteString("   • Export results: spotter scan cluster --output=json --output-file=results.json\n")
	}
	summary.WriteString("   • Validate rules: spotter rules validate ./rules\n")
	summary.WriteString("   • Get help: spotter --help\n")

	return summary.String()
}

// formatEnhancedSummary creates an enhanced summary with better visual formatting
func (r *TableReporter) formatEnhancedSummary(results *models.ScanResult) string {
	var summary strings.Builder

	summary.WriteString(r.colorize("Enhanced Scan Summary", "cyan"))
	summary.WriteString("\n")
	summary.WriteString(strings.Repeat("═", 80) + "\n")

	// Calculate enhanced metrics
	totalEvaluations := results.Passed + results.Failed
	failureRate := float64(0)
	if totalEvaluations > 0 {
		failureRate = float64(results.Failed) / float64(totalEvaluations) * 100
	}

	// Enhanced summary table with better formatting (2 columns only)
	type summaryRow struct {
		label string
		value string
	}

	rows := []summaryRow{
		{"Rules Evaluated", fmt.Sprintf("%d", results.TotalRules)},
		{"Total Evaluations", fmt.Sprintf("%d", totalEvaluations)},
		{"Failed Evaluations", fmt.Sprintf("%d", results.Failed)},
		{"Failure Rate", fmt.Sprintf("%.1f%%", failureRate)},
		{"Resources Scanned", fmt.Sprintf("%d", results.TotalResources)},
		{"Scan Duration", results.Duration.Round(time.Millisecond).String()},
	}

	// Format enhanced table with proper alignment (2 columns)
	for i, row := range rows {
		if i == 0 {
			summary.WriteString(fmt.Sprintf("┌─%-25s─┬─%-25s─┐\n", strings.Repeat("─", 25), strings.Repeat("─", 25)))
		}

		// Color the values appropriately
		value := row.value
		if row.label == "Failed Evaluations" && results.Failed > 0 {
			value = r.colorize(value, "red")
		} else if row.label == "Failure Rate" {
			if failureRate > 50 {
				value = r.colorize(value, "red")
			} else if failureRate > 20 {
				value = r.colorize(value, "yellow")
			} else {
				value = r.colorize(value, "green")
			}
		} else if row.label == "Rules Evaluated" || row.label == "Resources Scanned" || row.label == "Total Evaluations" {
			value = r.colorize(value, "cyan")
		}

		summary.WriteString(fmt.Sprintf("│ %s │ %s │\n",
			r.padToWidth(row.label, 25),
			r.padToWidth(value, 25)))
		if i == len(rows)-1 {
			summary.WriteString(fmt.Sprintf("└─%-25s─┴─%-25s─┘\n", strings.Repeat("─", 25), strings.Repeat("─", 25)))
		}
	}

	return summary.String()
}

// formatCategoryScoreTable creates a category-wise scoring table
func (r *TableReporter) formatCategoryScoreTable(results *models.ScanResult) string {
	var table strings.Builder

	table.WriteString(r.colorize("Category-wise Security Score", "cyan"))
	table.WriteString("\n")
	table.WriteString(strings.Repeat("═", 90) + "\n")

	// Group results by category
	categoryStats := r.calculateCategoryStats(results.Results)

	if len(categoryStats) == 0 {
		table.WriteString(r.colorize("No categorized findings available\n", "yellow"))
		return table.String()
	}

	// Sort categories by failure rate (worst first)
	var sortedCategories []CategoryStat
	for _, stat := range categoryStats {
		sortedCategories = append(sortedCategories, stat)
	}
	sort.Slice(sortedCategories, func(i, j int) bool {
		return sortedCategories[i].FailureRate > sortedCategories[j].FailureRate
	})

	// Table header
	table.WriteString(fmt.Sprintf("┌─%-37s─┬─%-14s─┬─%-14s─┬─%-14s─┬─%-12s─┐\n", strings.Repeat("─", 37), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 12)))
	table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │\n",
		r.padToWidth(r.colorize("Category", "bold"), 37),
		r.padToWidth(r.colorize("Failed", "bold"), 14),
		r.padToWidth(r.colorize("Total", "bold"), 14),
		r.padToWidth(r.colorize("Score", "bold"), 14),
		r.padToWidth(r.colorize("Grade", "bold"), 12)))
	table.WriteString(fmt.Sprintf("├─%-37s─┼─%-14s─┼─%-14s─┼─%-14s─┼─%-12s─┤\n", strings.Repeat("─", 37), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 12)))

	// Table rows
	for _, stat := range sortedCategories {
		scoreColor := r.getScoreColor(stat.Score)
		gradeColor := r.getGradeColor(stat.Grade)
		table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │\n",
			r.padToWidth(r.truncateString(stat.Category, 37), 37),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.Failed), "red"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.Total), "cyan"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%.1f%%", stat.Score), scoreColor), 14),
			r.padToWidth(r.colorize(stat.Grade, gradeColor), 12)))
	}

	table.WriteString(fmt.Sprintf("└─%-37s─┴─%-14s─┴─%-14s─┴─%-14s─┴─%-12s─┘\n", strings.Repeat("─", 37), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 12)))

	return table.String()
}

// formatSeverityScoreTable creates a severity-wise scoring table
func (r *TableReporter) formatSeverityScoreTable(results *models.ScanResult) string {
	var table strings.Builder

	table.WriteString(r.colorize("Severity-wise Security Analysis", "cyan"))
	table.WriteString("\n")
	table.WriteString(strings.Repeat("═", 85) + "\n")

	// Calculate severity stats
	severityStats := r.calculateSeverityStats(results.Results)

	if len(severityStats) == 0 {
		table.WriteString(r.colorize("No severity data available\n", "yellow"))
		return table.String()
	}

	// Sort by severity weight (critical first)
	var sortedSeverities []SeverityStat
	for _, stat := range severityStats {
		sortedSeverities = append(sortedSeverities, stat)
	}
	sort.Slice(sortedSeverities, func(i, j int) bool {
		return r.severityWeight(models.SeverityLevel(sortedSeverities[i].Severity)) > r.severityWeight(models.SeverityLevel(sortedSeverities[j].Severity))
	})

	// Table header (removed Impact and Risk Score columns)
	table.WriteString(fmt.Sprintf("┌─%-17s─┬─%-14s─┬─%-14s─┬─%-14s─┐\n", strings.Repeat("─", 17), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))
	table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │\n",
		r.padToWidth(r.colorize("Severity", "bold"), 17),
		r.padToWidth(r.colorize("Failed", "bold"), 14),
		r.padToWidth(r.colorize("Total", "bold"), 14),
		r.padToWidth(r.colorize("Failure %", "bold"), 14)))
	table.WriteString(fmt.Sprintf("├─%-17s─┼─%-14s─┼─%-14s─┼─%-14s─┤\n", strings.Repeat("─", 17), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))

	// Table rows
	for _, stat := range sortedSeverities {
		severityColor := r.getSeverityColor(models.SeverityLevel(stat.Severity))
		table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │\n",
			r.padToWidth(r.colorize(stat.Severity, severityColor), 17),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.Failed), "red"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.Total), "cyan"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%.1f%%", stat.FailureRate), severityColor), 14)))
	}

	table.WriteString(fmt.Sprintf("└─%-17s─┴─%-14s─┴─%-14s─┴─%-14s─┘\n", strings.Repeat("─", 17), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))

	return table.String()
}

// formatResourceGroupingTable creates a resource grouping analysis table
func (r *TableReporter) formatResourceGroupingTable(results *models.ScanResult) string {
	var table strings.Builder

	table.WriteString(r.colorize("Resource Grouping Analysis", "cyan"))
	table.WriteString("\n")
	table.WriteString(strings.Repeat("═", 95) + "\n")

	// Calculate resource grouping stats
	resourceStats := r.calculateResourceGroupingStats(results.Results)

	if len(resourceStats) == 0 {
		table.WriteString(r.colorize("No resource data available\n", "yellow"))
		return table.String()
	}

	// Sort by failure count (highest first)
	var sortedResources []ResourceGroupStat
	for _, stat := range resourceStats {
		sortedResources = append(sortedResources, stat)
	}
	sort.Slice(sortedResources, func(i, j int) bool {
		return sortedResources[i].FailedCount > sortedResources[j].FailedCount
	})

	// Table header (removed Namespace column)
	table.WriteString(fmt.Sprintf("┌─%-35s─┬─%-14s─┬─%-14s─┬─%-14s─┬─%-14s─┐\n", strings.Repeat("─", 35), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))
	table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │\n",
		r.padToWidth(r.colorize("Resource Type", "bold"), 35),
		r.padToWidth(r.colorize("Failed", "bold"), 14),
		r.padToWidth(r.colorize("Total", "bold"), 14),
		r.padToWidth(r.colorize("Failure %", "bold"), 14),
		r.padToWidth(r.colorize("Risk Level", "bold"), 14)))
	table.WriteString(fmt.Sprintf("├─%-35s─┼─%-14s─┼─%-14s─┼─%-14s─┼─%-14s─┤\n", strings.Repeat("─", 35), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))

	// Table rows (limit to top 10 for readability)
	maxRows := 10
	if len(sortedResources) < maxRows {
		maxRows = len(sortedResources)
	}

	for i := 0; i < maxRows; i++ {
		stat := sortedResources[i]
		riskColor := r.getRiskLevelColor(stat.RiskLevel)
		table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │\n",
			r.padToWidth(r.truncateString(stat.ResourceType, 35), 35),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.FailedCount), "red"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%d", stat.TotalCount), "cyan"), 14),
			r.padToWidth(r.colorize(fmt.Sprintf("%.1f%%", stat.FailureRate), "yellow"), 14),
			r.padToWidth(r.colorize(stat.RiskLevel, riskColor), 14)))
	}

	if len(sortedResources) > maxRows {
		table.WriteString(fmt.Sprintf("│ %s │ %s │ %s │ %s │ %s │\n",
			r.padToWidth(r.colorize("... and more", "yellow"), 35),
			r.padToWidth("", 14),
			r.padToWidth("", 14),
			r.padToWidth("", 14),
			r.padToWidth("", 14)))
	}

	table.WriteString(fmt.Sprintf("└─%-35s─┴─%-14s─┴─%-14s─┴─%-14s─┴─%-14s─┘\n", strings.Repeat("─", 35), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14), strings.Repeat("─", 14)))

	return table.String()
}

// Helper methods for enhanced table formatting

func (r *TableReporter) getScoreColor(score float64) string {
	if score >= 90 {
		return "green"
	} else if score >= 70 {
		return "yellow"
	}
	return "red"
}

func (r *TableReporter) getGradeColor(grade string) string {
	switch grade {
	case "A", "A+":
		return "green"
	case "B", "B+":
		return "yellow"
	case "C", "C+":
		return "yellow"
	default:
		return "red"
	}
}

func (r *TableReporter) getRiskLevelColor(riskLevel string) string {
	switch strings.ToLower(riskLevel) {
	case "critical", "high":
		return "red"
	case "medium":
		return "yellow"
	case "low":
		return "green"
	default:
		return "cyan"
	}
}

func (r *TableReporter) truncateString(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// displayWidth calculates the actual display width of a string, ignoring ANSI color codes
func (r *TableReporter) displayWidth(s string) int {
	// Remove ANSI escape sequences to get actual display width
	width := 0
	inEscape := false
	for _, char := range s {
		if char == '\033' { // Start of ANSI escape sequence
			inEscape = true
			continue
		}
		if inEscape {
			if char == 'm' { // End of ANSI escape sequence
				inEscape = false
			}
			continue
		}
		// Handle Unicode characters and emojis properly
		// Most emojis and special Unicode chars take 2 display positions
		if char > 0x1F600 && char < 0x1F64F || // Emoticons
			char > 0x1F300 && char < 0x1F5FF || // Misc Symbols
			char > 0x1F680 && char < 0x1F6FF || // Transport and Map
			char > 0x2600 && char < 0x26FF || // Misc symbols
			char > 0x2700 && char < 0x27BF || // Dingbats
			char > 0xFE00 && char < 0xFE0F { // Variation selectors
			width += 2
		} else {
			width++
		}
	}
	return width
}

// padToWidth pads a string to a specific display width, accounting for color codes
func (r *TableReporter) padToWidth(s string, width int) string {
	displayW := r.displayWidth(s)
	if displayW >= width {
		return s
	}
	return s + strings.Repeat(" ", width-displayW)
}

func (r *TableReporter) calculateCategoryStats(results []models.ValidationResult) map[string]CategoryStat {
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

func (r *TableReporter) calculateSeverityStats(results []models.ValidationResult) map[string]SeverityStat {
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

func (r *TableReporter) calculateResourceGroupingStats(results []models.ValidationResult) map[string]ResourceGroupStat {
	resourceStats := make(map[string]ResourceGroupStat)

	for _, result := range results {
		// Extract resource type from resource metadata
		resourceType := "Unknown"

		if result.Resource != nil {
			if kind, ok := result.Resource["kind"].(string); ok {
				resourceType = kind
			}
		}

		// Group by resource type only (no namespace)
		key := resourceType
		stat := resourceStats[key]
		stat.ResourceType = resourceType
		stat.Namespace = "" // Not used for aggregated view
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

func (r *TableReporter) calculateGrade(score float64) string {
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

func (r *TableReporter) calculateRiskScore(severity models.SeverityLevel, failureRate float64) float64 {
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

func (r *TableReporter) calculateImpact(riskScore float64) string {
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

func (r *TableReporter) calculateResourceRiskLevel(failureRate float64, failedCount int) string {
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

// getUniqueMessages extracts unique messages from findings to avoid repetition
func (r *TableReporter) getUniqueMessages(findings []models.ValidationResult) []string {
	messageSet := make(map[string]bool)
	var uniqueMessages []string

	for _, finding := range findings {
		if finding.Message != "" && !messageSet[finding.Message] {
			messageSet[finding.Message] = true
			uniqueMessages = append(uniqueMessages, finding.Message)
			// Limit to 3 unique messages to avoid overwhelming output
			if len(uniqueMessages) >= 3 {
				break
			}
		}
	}

	return uniqueMessages
}

// getUniqueResourceCount counts the number of unique resources in a slice of findings
func (r *TableReporter) getUniqueResourceCount(findings []models.ValidationResult) int {
	resourceSet := make(map[string]bool)

	for _, finding := range findings {
		// Create a unique identifier for each resource
		resourceKind := "unknown"
		resourceName := "unknown"
		namespace := ""

		if kind, ok := finding.Resource["kind"].(string); ok {
			resourceKind = kind
		}

		if metadata, ok := finding.Resource["metadata"].(map[string]interface{}); ok {
			if name, ok := metadata["name"].(string); ok {
				resourceName = name
			}
			if ns, ok := metadata["namespace"].(string); ok {
				namespace = ns
			}
		}

		// Create unique key: kind/namespace/name
		resourceKey := fmt.Sprintf("%s/%s/%s", resourceKind, namespace, resourceName)
		resourceSet[resourceKey] = true
	}

	return len(resourceSet)
}

func (r *TableReporter) colorize(text, color string) string {
	if r.noColor {
		return text
	}

	colorCodes := map[string]string{
		"red":     "\033[31m",
		"green":   "\033[32m",
		"yellow":  "\033[33m",
		"blue":    "\033[34m",
		"magenta": "\033[35m",
		"cyan":    "\033[36m",
		"white":   "\033[37m",
		"orange":  "\033[38;5;208m", // Add orange color for HIGH severity
		"bold":    "\033[1m",
		"reset":   "\033[0m",
	}

	if code, exists := colorCodes[color]; exists {
		return fmt.Sprintf("%s%s%s", code, text, colorCodes["reset"])
	}

	return text
}

func (r *TableReporter) getCategoryEmoji(category string) string {
	switch strings.ToLower(category) {
	case "access control":
		return "🔐"
	case "configuration & resource hygiene", "configuration":
		return "⚙️"
	case "supply chain & image security", "supply chain":
		return "📦"
	case "workload security":
		return "🛡️"
	case "platform & infrastructure security", "platform":
		return "🏗️"
	case "secrets & data protection", "secrets":
		return "🔒"
	case "network traffic security", "network":
		return "🌐"
	case "audit logging compliance", "audit":
		return "📋"
	case "runtime threat detection", "runtime":
		return "⚡"
	default:
		return "📁"
	}
}

// formatAIRecommendations formats AI recommendations in a clean table format
func (r *TableReporter) formatAIRecommendations(aiRecommendations interface{}) string {
	var output strings.Builder

	if aiRecommendations == nil {
		return ""
	}

	// Convert to JSON and back to handle any struct type
	jsonBytes, err := json.Marshal(aiRecommendations)
	if err != nil {
		return ""
	}

	var recOutput map[string]interface{}
	if err := json.Unmarshal(jsonBytes, &recOutput); err != nil {
		return ""
	}

	// Check for error in the output first
	errorMsg, hasError := recOutput["error"].(string)

	recommendations, exists := recOutput["recommendations"]
	if !exists && !hasError {
		return ""
	}

	var recsList []interface{}
	if exists && recommendations != nil {
		var ok bool
		recsList, ok = recommendations.([]interface{})
		if !ok {
			recsList = []interface{}{} // Empty list if can't parse
		}
	}

	// Header
	output.WriteString(r.colorize("🤖 AI Security Recommendations\n", "cyan"))
	output.WriteString(strings.Repeat("─", 80) + "\n")

	// If there's an error, show it and return
	if hasError && errorMsg != "" {
		output.WriteString(fmt.Sprintf("%s %s\n",
			r.colorize("⚠️  Error:", "red"),
			errorMsg))
		output.WriteString(fmt.Sprintf("   %s\n",
			r.colorize("Tip: Ensure your AI model (Ollama) is running and accessible", "yellow")))
		output.WriteString("\n")
		return output.String()
	}

	if len(recsList) == 0 {
		output.WriteString(fmt.Sprintf("%s %s\n",
			r.colorize("ℹ️  Info:", "blue"),
			"No AI recommendations generated"))
		output.WriteString("\n")
		return output.String()
	}

	// Display each recommendation
	for _, rec := range recsList {
		recMap, ok := rec.(map[string]interface{})
		if !ok {
			continue
		}

		title, _ := recMap["title"].(string)
		priority, _ := recMap["priority"].(float64) // JSON numbers come as float64
		actionsInterface, _ := recMap["actions"].([]interface{})
		relatedRulesInterface, _ := recMap["related_rules"].([]interface{})

		// Convert actions from []interface{} to []string
		var actions []string
		for _, action := range actionsInterface {
			if actionStr, ok := action.(string); ok {
				actions = append(actions, actionStr)
			}
		}

		// Convert related rules from []interface{} to []string
		var relatedRules []string
		for _, rule := range relatedRulesInterface {
			if ruleStr, ok := rule.(string); ok {
				relatedRules = append(relatedRules, ruleStr)
			}
		}

		// Format priority and title
		output.WriteString(fmt.Sprintf("%s %s %d: %s\n",
			r.colorize("►", "blue"),
			r.colorize("Priority", "yellow"),
			int(priority),
			r.colorize(title, "white")))

		// Format actions
		if len(actions) > 0 {
			for _, action := range actions {
				output.WriteString(fmt.Sprintf("   %s %s\n",
					r.colorize("Actions:", "green"),
					action))
			}
		}

		// Format related rules (compact)
		if len(relatedRules) > 0 {
			rulesStr := strings.Join(relatedRules, ", ")
			output.WriteString(fmt.Sprintf("   %s %s\n",
				r.colorize("Related:", "gray"),
				rulesStr))
		}

		output.WriteString("\n")
	}

	return output.String()
}
