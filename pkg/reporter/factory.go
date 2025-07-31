package reporter

import (
	"fmt"
	"os"
	"strings"
)

// ReporterType represents the type of reporter
type ReporterType string

const (
	ReporterTypeTable ReporterType = "table"
	ReporterTypeJSON  ReporterType = "json"
	ReporterTypeYAML  ReporterType = "yaml"
	ReporterTypeSARIF ReporterType = "sarif"
)

// Factory implements the ReporterFactory interface
type Factory struct{}

// NewFactory creates a new reporter factory
func NewFactory() *Factory {
	return &Factory{}
}

// CreateReporter creates a reporter based on the specified type
func (f *Factory) CreateReporter(format string) (Reporter, error) {
	reporterType, err := ParseReporterType(format)
	if err != nil {
		return nil, err
	}

	switch reporterType {
	case ReporterTypeTable:
		return NewTableReporter(false, false), nil
	case ReporterTypeJSON:
		return NewJSONReporter(), nil
	case ReporterTypeYAML:
		return NewYAMLReporter(), nil
	case ReporterTypeSARIF:
		return NewSARIFReporter(), nil
	default:
		return nil, fmt.Errorf("unsupported reporter type: %s", reporterType)
	}
}

// CreateReporterWithOptions creates a reporter with specific options
func (f *Factory) CreateReporterWithOptions(format string, noColor, verbose bool) (Reporter, error) {
	reporterType, err := ParseReporterType(format)
	if err != nil {
		return nil, err
	}

	switch reporterType {
	case ReporterTypeTable:
		return NewTableReporter(noColor, verbose), nil
	case ReporterTypeJSON:
		return NewJSONReporter(), nil
	case ReporterTypeYAML:
		return NewYAMLReporter(), nil
	case ReporterTypeSARIF:
		return NewSARIFReporter(), nil
	default:
		return nil, fmt.Errorf("unsupported reporter type: %s", reporterType)
	}
}

// GetSupportedFormats returns a list of supported reporter formats
func (f *Factory) GetSupportedFormats() []string {
	return []string{
		string(ReporterTypeTable),
		string(ReporterTypeJSON),
		string(ReporterTypeYAML),
		string(ReporterTypeSARIF),
	}
}

// ParseReporterType parses a string into a ReporterType
func ParseReporterType(s string) (ReporterType, error) {
	switch strings.ToLower(s) {
	case "table", "console":
		return ReporterTypeTable, nil
	case "json":
		return ReporterTypeJSON, nil
	case "yaml", "yml":
		return ReporterTypeYAML, nil
	case "sarif":
		return ReporterTypeSARIF, nil
	default:
		return "", fmt.Errorf("unsupported reporter type: %s", s)
	}
}

// getWriter creates the appropriate writer based on options


// ValidateReportOptions validates the report options
func ValidateReportOptions(options *ReportOptions) error {
	if options == nil {
		return fmt.Errorf("report options cannot be nil")
	}

	// Validate output file path if specified
	if options.OutputFile != "" {
		// Check if the directory exists
		dir := strings.TrimSuffix(options.OutputFile, "/"+getFileName(options.OutputFile))
		if dir != "" && dir != "." {
			if _, err := os.Stat(dir); os.IsNotExist(err) {
				return fmt.Errorf("output directory does not exist: %s", dir)
			}
		}
	}

	return nil
}

// getFileName extracts the filename from a path
func getFileName(path string) string {
	parts := strings.Split(path, "/")
	if len(parts) == 0 {
		return path
	}
	return parts[len(parts)-1]
}

// GetRecommendedFileExtension returns the recommended file extension for a reporter type
func GetRecommendedFileExtension(reporterType ReporterType) string {
	switch reporterType {
	case ReporterTypeJSON:
		return ".json"
	case ReporterTypeYAML:
		return ".yaml"
	case ReporterTypeSARIF:
		return ".sarif"
	case ReporterTypeTable:
		return ".txt"
	default:
		return ".txt"
	}
}

// SuggestOutputFileName suggests an output filename based on the reporter type and target
func SuggestOutputFileName(reporterType ReporterType, target string) string {
	base := "spotter-report"
	if target != "" {
		// Sanitize target name for filename
		sanitized := strings.ReplaceAll(target, "/", "-")
		sanitized = strings.ReplaceAll(sanitized, ":", "-")
		sanitized = strings.ReplaceAll(sanitized, " ", "-")
		base = fmt.Sprintf("spotter-%s", sanitized)
	}

	return base + GetRecommendedFileExtension(reporterType)
}