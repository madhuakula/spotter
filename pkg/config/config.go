package config

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// LoggingConfig represents logging configuration
type LoggingConfig struct {
	Level  string `yaml:"level" json:"level"`
	Format string `yaml:"format" json:"format"`
}

// ScannerConfig represents scanner configuration
// Note: Most fields are not yet implemented in the codebase
type ScannerConfig struct {
	// TODO: Implement these scanner configuration options
	// Workers                 int           `yaml:"workers" json:"workers"`
	// MaxConcurrency          int           `yaml:"max_concurrency" json:"max_concurrency"`
	// Timeout                 time.Duration `yaml:"timeout" json:"timeout"`
	// BatchSize               int           `yaml:"batch_size" json:"batch_size"`
	// StreamingMode           bool          `yaml:"streaming_mode" json:"streaming_mode"`
	// MemoryLimit             string        `yaml:"memory_limit" json:"memory_limit"`
	// ResourcePoolSize        int           `yaml:"resource_pool_size" json:"resource_pool_size"`
	// IncludeNamespaces       []string      `yaml:"include_namespaces" json:"include_namespaces"`
	// ExcludeNamespaces       []string      `yaml:"exclude_namespaces" json:"exclude_namespaces"`
	// ExcludeSystemNamespaces bool          `yaml:"exclude_system_namespaces" json:"exclude_system_namespaces"`
	// ResourceTypes           []string      `yaml:"resource_types" json:"resource_types"`
	// IncludeClusterResources bool          `yaml:"include_cluster_resources" json:"include_cluster_resources"`
	// Recursive               bool          `yaml:"recursive" json:"recursive"`
	// FileExtensions          []string      `yaml:"file_extensions" json:"file_extensions"`
	// Parallelism             int           `yaml:"parallelism" json:"parallelism"`
	// FailOnViolations        bool          `yaml:"fail_on_violations" json:"fail_on_violations"`
	// MaxViolations           int           `yaml:"max_violations" json:"max_violations"`
	// IncludePassed           bool          `yaml:"include_passed" json:"include_passed"`
}

// RulesConfig represents rules configuration
type RulesConfig struct {
	CustomPaths    []string          `yaml:"custom_paths" json:"custom_paths"`
	SeverityFilter []string          `yaml:"severity_filter" json:"severity_filter"`
	MinSeverity    string            `yaml:"min_severity" json:"min_severity"`
	IncludeRules   []string          `yaml:"include_rules" json:"include_rules"`
	ExcludeRules   []string          `yaml:"exclude_rules" json:"exclude_rules"`
	Categories     []string          `yaml:"categories" json:"categories"`
	CustomFilters  map[string]string `yaml:"custom_filters" json:"custom_filters"`
	DefaultPacks   []string          `yaml:"default_packs" json:"default_packs"`
}

// OutputConfig represents output configuration
type OutputConfig struct {
	Format  string `yaml:"format" json:"format"`
	Verbose bool   `yaml:"verbose" json:"verbose"`
	File    string `yaml:"file" json:"file"`
	Pretty  bool   `yaml:"pretty" json:"pretty"`
}

// KubernetesConfig represents Kubernetes configuration
type KubernetesConfig struct {
	Kubeconfig string        `yaml:"kubeconfig" json:"kubeconfig"`
	Context    string        `yaml:"context" json:"context"`
	Timeout    time.Duration `yaml:"timeout" json:"timeout"`
	Namespace  string        `yaml:"namespace" json:"namespace"`
}

// HelmConfig represents Helm configuration
type HelmConfig struct {
	ReleaseName        string   `yaml:"release_name" json:"release_name"`
	Namespace          string   `yaml:"namespace" json:"namespace"`
	KubeVersion        string   `yaml:"kube_version" json:"kube_version"`
	ValuesFiles        []string `yaml:"values_files" json:"values_files"`
	SetValues          []string `yaml:"set_values" json:"set_values"`
	SetStringValues    []string `yaml:"set_string_values" json:"set_string_values"`
	SkipCRDs           bool     `yaml:"skip_crds" json:"skip_crds"`
	SkipTests          bool     `yaml:"skip_tests" json:"skip_tests"`
	ValidateSchema     bool     `yaml:"validate_schema" json:"validate_schema"`
	IncludeCRDs        bool     `yaml:"include_crds" json:"include_crds"`
	UpdateDependencies bool     `yaml:"update_dependencies" json:"update_dependencies"`
	ChartRepo          string   `yaml:"chart_repo" json:"chart_repo"`
	ChartVersion       string   `yaml:"chart_version" json:"chart_version"`
}

// FilteringConfig represents filtering configuration
// Note: Not yet implemented in the codebase
type FilteringConfig struct {
	// TODO: Implement filtering configuration
	// NamespacePatterns struct {
	//	UseDynamicDetection bool     `yaml:"use_dynamic_detection" json:"use_dynamic_detection"`
	//	UseSecureValidation bool     `yaml:"use_secure_validation" json:"use_secure_validation"`
	//	CustomPatterns      []string `yaml:"custom_patterns" json:"custom_patterns"`
	// } `yaml:"namespace_patterns" json:"namespace_patterns"`
	// ResourceFilter struct {
	//	UseDynamicFiltering bool              `yaml:"use_dynamic_filtering" json:"use_dynamic_filtering"`
	//	CustomFilters       map[string]string `yaml:"custom_filters" json:"custom_filters"`
	// } `yaml:"resource_filter" json:"resource_filter"`
}

// PerformanceConfig represents performance configuration
// Note: Not yet implemented in the codebase
type PerformanceConfig struct {
	// TODO: Implement performance configuration
	// EnableMetrics bool          `yaml:"enable_metrics" json:"enable_metrics"`
	// CPUProfile    bool          `yaml:"cpu_profile" json:"cpu_profile"`
	// MemoryProfile bool          `yaml:"memory_profile" json:"memory_profile"`
	// EnableCache   bool          `yaml:"enable_cache" json:"enable_cache"`
	// CacheTTL      time.Duration `yaml:"cache_ttl" json:"cache_ttl"`
}

// SecurityConfig represents security configuration
// Note: Not yet implemented in the codebase
type SecurityConfig struct {
	// TODO: Implement security configuration
	// ValidateSignatures bool     `yaml:"validate_signatures" json:"validate_signatures"`
	// AllowUnsignedRules bool     `yaml:"allow_unsigned_rules" json:"allow_unsigned_rules"`
	// TrustedSources     []string `yaml:"trusted_sources" json:"trusted_sources"`
}

// ReportingConfig represents reporting configuration
// Note: Not yet implemented in the codebase
type ReportingConfig struct {
	// TODO: Implement reporting configuration
	// IncludeMetadata    bool `yaml:"include_metadata" json:"include_metadata"`
	// IncludeRemediation bool `yaml:"include_remediation" json:"include_remediation"`
	// IncludeReferences  bool `yaml:"include_references" json:"include_references"`
	// GroupByCategory    bool `yaml:"group_by_category" json:"group_by_category"`
	// ShowProgress       bool `yaml:"show_progress" json:"show_progress"`
}

// IntegrationsConfig represents integrations configuration
// Note: Not yet implemented in the codebase
type IntegrationsConfig struct {
	// TODO: Implement integrations configuration
	// Webhooks []string `yaml:"webhooks" json:"webhooks"`
	// SARIF    struct {
	//	IncludeRuleHelp  bool `yaml:"include_rule_help" json:"include_rule_help"`
	//	IncludeLocations bool `yaml:"include_locations" json:"include_locations"`
	// } `yaml:"sarif" json:"sarif"`
}

// DevelopmentConfig represents development configuration
// Note: Not yet implemented in the codebase
type DevelopmentConfig struct {
	// TODO: Implement development configuration
	// Debug        bool `yaml:"debug" json:"debug"`
	// DryRun       bool `yaml:"dry_run" json:"dry_run"`
	// ValidateOnly bool `yaml:"validate_only" json:"validate_only"`
	// Experimental bool `yaml:"experimental" json:"experimental"`
}

// SpotterConfig represents the complete Spotter configuration
type SpotterConfig struct {
	// Legacy fields for backward compatibility
	HubURL   string `yaml:"hub_url" json:"hub_url"`
	APIKey   string `yaml:"api_key" json:"api_key"`
	CacheDir string `yaml:"cache_dir" json:"cache_dir"`
	RulesDir string `yaml:"rules_dir" json:"rules_dir"`
	PacksDir string `yaml:"packs_dir" json:"packs_dir"`

	// Implemented configuration sections
	Logging    LoggingConfig    `yaml:"logging" json:"logging"`
	Rules      RulesConfig      `yaml:"rules" json:"rules"`
	Output     OutputConfig     `yaml:"output" json:"output"`
	Kubernetes KubernetesConfig `yaml:"kubernetes" json:"kubernetes"`
	Helm       HelmConfig       `yaml:"helm" json:"helm"`

	// TODO: Uncomment when these features are implemented
	// Scanner      ScannerConfig      `yaml:"scanner" json:"scanner"`
	// Filtering    FilteringConfig    `yaml:"filtering" json:"filtering"`
	// Performance  PerformanceConfig  `yaml:"performance" json:"performance"`
	// Security     SecurityConfig     `yaml:"security" json:"security"`
	// Reporting    ReportingConfig    `yaml:"reporting" json:"reporting"`
	// Integrations IntegrationsConfig `yaml:"integrations" json:"integrations"`
	// Development  DevelopmentConfig  `yaml:"development" json:"development"`
}

// DefaultConfig returns the default configuration
func DefaultConfig() (*SpotterConfig, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("failed to get user home directory: %w", err)
	}
	
	config := &SpotterConfig{
		HubURL:   "https://rules.spotter.run/api/v1",
		APIKey:   "",
		CacheDir: filepath.Join(homeDir, ".spotter"),
		RulesDir: filepath.Join(homeDir, ".spotter", "rules"),
		PacksDir: filepath.Join(homeDir, ".spotter", "rulepacks"),
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Rules: RulesConfig{
			CustomPaths: []string{
				"./custom-rules/",
				"/etc/spotter/rules/",
			},
			SeverityFilter: []string{
				"CRITICAL",
				"HIGH",
				"MEDIUM",
				"LOW",
			},
			MinSeverity:   "",
			IncludeRules:  []string{},
			ExcludeRules:  []string{},
			Categories:    []string{},
			CustomFilters: map[string]string{},
			DefaultPacks: []string{
				"spotter-secure-defaults-pack",
			},
		},
		Output: OutputConfig{
			Format:  "table",
			Verbose: false,
			File:    "",
			Pretty:  true,
		},
		Kubernetes: KubernetesConfig{
			Kubeconfig: filepath.Join(homeDir, ".kube", "config"),
			Context:    "",
			Timeout:    30 * time.Second,
			Namespace:  "",
		},
		Helm: HelmConfig{
			ReleaseName:        "spotter-scan",
			Namespace:          "default",
			KubeVersion:        "",
			ValuesFiles:        []string{},
			SetValues:          []string{},
			SetStringValues:    []string{},
			SkipCRDs:           false,
			SkipTests:          false,
			ValidateSchema:     false,
			IncludeCRDs:        true,
			UpdateDependencies: false,
			ChartRepo:          "",
			ChartVersion:       "",
		},
	}
	
	return config, nil
}

// GetSpotterDir returns the Spotter configuration directory
func GetSpotterDir() (string, error) {
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(homeDir, ".spotter"), nil
}

// GetConfigPath returns the path to the configuration file
func GetConfigPath() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "config.yaml"), nil
}



// GetRulesDir returns the rules directory path
func GetRulesDir() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "rules"), nil
}

// GetRulePacksDir returns the rule packs directory path
func GetRulePacksDir() (string, error) {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(spotterDir, "rulepacks"), nil
}

// EnsureDirectories creates the necessary directories if they don't exist
func EnsureDirectories() error {
	spotterDir, err := GetSpotterDir()
	if err != nil {
		return err
	}

	// Create main .spotter directory
	if err := os.MkdirAll(spotterDir, 0755); err != nil {
		return err
	}

	// Create rules directory
	rulesDir, err := GetRulesDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(rulesDir, 0755); err != nil {
		return err
	}

	// Create rule packs directory
	packsDir, err := GetRulePacksDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(packsDir, 0755); err != nil {
		return err
	}

	return nil
}
