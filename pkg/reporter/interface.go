package reporter

import (
	"context"
	"io"

	"github.com/madhuakula/spotter/pkg/models"
)

// Reporter defines the interface for generating scan reports
type Reporter interface {
	// GenerateReport generates a report from scan results
	GenerateReport(ctx context.Context, results *models.ScanResult) ([]byte, error)

	// WriteReport writes a report to the specified writer
	WriteReport(ctx context.Context, results *models.ScanResult, writer io.Writer) error

	// GetFormat returns the format name of this reporter
	GetFormat() string

	// GetFileExtension returns the recommended file extension
	GetFileExtension() string
}

// ReporterFactory creates reporters for different output formats
type ReporterFactory interface {
	// CreateReporter creates a reporter for the specified format
	CreateReporter(format string) (Reporter, error)

	// GetSupportedFormats returns a list of supported output formats
	GetSupportedFormats() []string
}

// ReportOptions defines options for report generation
type ReportOptions struct {
	// Format specifies the output format (table, json, yaml, sarif)
	Format string

	// OutputFile specifies the output file path
	OutputFile string

	// NoColor disables colored output for table format
	NoColor bool

	// Verbose enables verbose output
	Verbose bool

	// IncludePassedRules includes rules that passed in the report
	IncludePassedRules bool

	// MinSeverity filters results by minimum severity level
	MinSeverity string

	// GroupBy specifies how to group results (resource, rule, severity, category)
	GroupBy string

	// SortBy specifies how to sort results (severity, resource, rule)
	SortBy string

	// Template specifies a custom template file for report generation
	Template string
}

// SummaryReporter generates summary statistics from scan results
type SummaryReporter interface {
	// GenerateSummary generates a summary of scan results
	GenerateSummary(ctx context.Context, results *models.ScanResult) (*models.ScanSummary, error)

	// GenerateComplianceReport generates a compliance report
	GenerateComplianceReport(ctx context.Context, results *models.ScanResult, standards []string) (*ComplianceReport, error)
}

// ComplianceReport represents a compliance report
type ComplianceReport struct {
	Standard     string              `json:"standard"`
	Version      string              `json:"version"`
	Score        float64             `json:"score"`
	TotalChecks  int                 `json:"totalChecks"`
	PassedChecks int                 `json:"passedChecks"`
	FailedChecks int                 `json:"failedChecks"`
	Controls     []ComplianceControl `json:"controls"`
	Summary      *models.ScanSummary `json:"summary"`
	Timestamp    string              `json:"timestamp"`
}

// ComplianceControl represents a compliance control
type ComplianceControl struct {
	ID          string                     `json:"id"`
	Title       string                     `json:"title"`
	Description string                     `json:"description"`
	Status      ComplianceStatus           `json:"status"`
	Findings    []*models.ValidationResult `json:"findings"`
	Score       float64                    `json:"score"`
}

// ComplianceStatus represents the status of a compliance control
type ComplianceStatus string

const (
	ComplianceStatusPassed  ComplianceStatus = "PASSED"
	ComplianceStatusFailed  ComplianceStatus = "FAILED"
	ComplianceStatusSkipped ComplianceStatus = "SKIPPED"
	ComplianceStatusError   ComplianceStatus = "ERROR"
)

// MetricsReporter generates metrics from scan results
type MetricsReporter interface {
	// GenerateMetrics generates metrics from scan results
	GenerateMetrics(ctx context.Context, results *models.ScanResult) (*ScanMetrics, error)

	// ExportPrometheusMetrics exports metrics in Prometheus format
	ExportPrometheusMetrics(ctx context.Context, metrics *ScanMetrics) ([]byte, error)
}

// ScanMetrics represents scan metrics
type ScanMetrics struct {
	TotalResources     int            `json:"totalResources"`
	ScannedResources   int            `json:"scannedResources"`
	TotalRules         int            `json:"totalRules"`
	ExecutedRules      int            `json:"executedRules"`
	TotalFindings      int            `json:"totalFindings"`
	FindingsBySeverity map[string]int `json:"findingsBySeverity"`
	FindingsByCategory map[string]int `json:"findingsByCategory"`
	ResourceTypes      map[string]int `json:"resourceTypes"`
	Namespaces         map[string]int `json:"namespaces"`
	ScanDuration       string         `json:"scanDuration"`
	Timestamp          string         `json:"timestamp"`
}
