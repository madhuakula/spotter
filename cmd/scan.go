package cmd

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/k8s"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/progress"
	"github.com/madhuakula/spotter/pkg/reporter"
)

// BuiltinRulesFS is a reference to the embedded filesystem from main package
// This will be set by the main package during initialization
var BuiltinRulesFS fs.FS

// scanCmd represents the scan command
var scanCmd = &cobra.Command{
	Use:   "scan",
	Short: "Scan Kubernetes resources for security vulnerabilities",
	Long: `Scan Kubernetes resources for security vulnerabilities using CEL-based rules.

Supported scan targets:
- cluster: Scan live Kubernetes cluster
- manifests: Scan YAML/JSON manifest files
- helm: Scan Helm charts (future)

Examples:
  # Scan live cluster
  spotter scan cluster
  
  # Scan specific namespaces
  spotter scan cluster --namespace=default,kube-system
  
  # Scan manifest files
  spotter scan manifests ./k8s-manifests/
  
  # Scan with custom rules
  spotter scan cluster --rules-path=./custom-rules/
  
  # Output to file
  spotter scan cluster --output=json --output-file=results.json`,
}

// clusterCmd represents the cluster scan command
var clusterCmd = &cobra.Command{
	Use:   "cluster",
	Short: "Scan live Kubernetes cluster",
	Long: `Scan a live Kubernetes cluster for security vulnerabilities and misconfigurations.

This command connects to your Kubernetes cluster using the configured kubeconfig
and scans all accessible resources against the loaded security rules.

Examples:
  # Scan entire cluster
  spotter scan cluster
  
  # Scan specific namespaces
  spotter scan cluster --namespace=default,production
  
  # Exclude system namespaces
  spotter scan cluster --exclude-system-namespaces
  
  # Scan specific resource types
  spotter scan cluster --resource-types=pods,deployments,services`,
	RunE: runClusterScan,
}

// manifestsCmd represents the manifests scan command
var manifestsCmd = &cobra.Command{
	Use:   "manifests [path...]",
	Short: "Scan Kubernetes manifest files",
	Long: `Scan Kubernetes YAML/JSON manifest files for security vulnerabilities.

This command scans static manifest files without requiring a live cluster connection.
It supports both individual files and directories with recursive scanning.

Examples:
  # Scan a directory
  spotter scan manifests ./k8s-manifests/
  
  # Scan multiple paths
  spotter scan manifests ./app1/ ./app2/ deployment.yaml
  
  # Recursive scan
  spotter scan manifests ./projects/ --recursive
  
  # Scan with severity filter
  spotter scan manifests ./manifests/ --min-severity=high`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("at least one manifest path is required\n\nUsage: spotter scan manifests <path> [path...]\n\nExamples:\n  spotter scan manifests ./k8s-manifests/\n  spotter scan manifests deployment.yaml service.yaml\n  spotter scan manifests ./app1/ ./app2/")
		}
		return nil
	},
	RunE: runManifestsScan,
}

// helmCmd represents the helm scan command
var helmCmd = &cobra.Command{
	Use:   "helm [chart-path...]",
	Short: "Scan Helm charts",
	Long: `Scan Helm charts for security vulnerabilities and misconfigurations.

This command renders Helm charts and scans the resulting manifests
against the loaded security rules.

Examples:
  # Scan a Helm chart
  spotter scan helm ./my-chart/
  
  # Scan with custom values
  spotter scan helm ./chart/ --values=values.yaml
  
  # Scan multiple charts
  spotter scan helm ./chart1/ ./chart2/`,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return fmt.Errorf("at least one chart path is required\n\nUsage: spotter scan helm <chart-path> [chart-path...]\n\nExamples:\n  spotter scan helm ./my-chart/\n  spotter scan helm ./chart1/ ./chart2/\n  spotter scan helm ./chart/ --values=values.yaml")
		}
		return nil
	},
	RunE: runHelmScan,
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.AddCommand(clusterCmd)
	scanCmd.AddCommand(manifestsCmd)
	scanCmd.AddCommand(helmCmd)

	// Cluster scan flags
	clusterCmd.Flags().StringSliceP("namespace", "n", []string{}, "namespaces to scan (default: all non-system namespaces)")
	clusterCmd.Flags().StringSlice("exclude-namespaces", []string{}, "namespaces to exclude from scanning")
	clusterCmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces (kube-system, kube-public, etc.)")
	clusterCmd.Flags().StringSlice("resource-types", []string{}, "specific resource types to scan (format: group/version/kind, e.g., apps/v1/Deployment)")
	clusterCmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")
	clusterCmd.Flags().String("context", "", "kubernetes context to use")
	clusterCmd.Flags().Bool("watch", false, "watch for resource changes and continuously scan")
	clusterCmd.Flags().Duration("watch-interval", 30*time.Second, "interval for watch mode scanning")
	clusterCmd.Flags().Bool("fail-on-violations", false, "exit with non-zero code if violations are found")
	clusterCmd.Flags().Int("max-violations", 0, "maximum number of violations before stopping scan (0 = unlimited)")
	clusterCmd.Flags().Bool("include-passed", false, "include passed rules in the report")
	clusterCmd.Flags().String("label-selector", "", "label selector to filter resources (e.g., app=nginx,env=prod)")
	clusterCmd.Flags().String("field-selector", "", "field selector to filter resources")
	clusterCmd.Flags().Bool("dry-run", false, "show what would be scanned without actually scanning")
	clusterCmd.Flags().String("cache-dir", "", "directory to cache scan results")
	clusterCmd.Flags().Duration("cache-ttl", 5*time.Minute, "cache time-to-live for scan results")

	// Performance optimization flags
	clusterCmd.Flags().Int("batch-size", 50, "number of resources to process in each batch")
	clusterCmd.Flags().Int("parallelism", 4, "number of parallel workers for scanning")
	clusterCmd.Flags().Bool("streaming-mode", false, "enable streaming mode to reduce memory usage")
	clusterCmd.Flags().Int64("memory-limit", 0, "maximum memory usage in MB (0 = unlimited)")
	clusterCmd.Flags().Int("resource-pool-size", 100, "size of resource object pool for reuse")

	// Enhanced filtering flags

	// Interactive and user experience flags
	clusterCmd.Flags().Bool("interactive", false, "enable interactive mode with progress bars and real-time updates")
	clusterCmd.Flags().Bool("show-progress", true, "show progress indicators during scanning")
	clusterCmd.Flags().Bool("quiet", false, "suppress non-essential output")
	clusterCmd.Flags().Bool("summary-only", false, "show only summary statistics")

	// Manifests scan flags
	manifestsCmd.Flags().Bool("recursive", true, "recursively scan directories")
	manifestsCmd.Flags().StringSlice("file-extensions", []string{".yaml", ".yml", ".json"}, "file extensions to scan")
	manifestsCmd.Flags().Bool("validate-syntax", true, "validate YAML/JSON syntax before scanning")
	manifestsCmd.Flags().StringSlice("exclude-paths", []string{}, "paths to exclude from scanning")
	manifestsCmd.Flags().StringSlice("include-paths", []string{}, "paths to include in scanning (overrides exclude-paths)")
	manifestsCmd.Flags().Bool("ignore-parse-errors", false, "continue scanning even if some files fail to parse")
	manifestsCmd.Flags().String("baseline", "", "baseline file to compare against")
	manifestsCmd.Flags().Bool("update-baseline", false, "update the baseline file with current scan results")
	manifestsCmd.Flags().Bool("fail-on-violations", false, "exit with non-zero code if violations are found")
	manifestsCmd.Flags().Int("max-violations", 0, "maximum number of violations before stopping scan (0 = unlimited)")
	manifestsCmd.Flags().Bool("include-passed", false, "include passed rules in the report")
	manifestsCmd.Flags().Bool("follow-symlinks", false, "follow symbolic links when scanning directories")
	manifestsCmd.Flags().String("git-repo", "", "git repository URL to clone and scan")
	manifestsCmd.Flags().String("git-branch", "main", "git branch to scan")
	manifestsCmd.Flags().String("git-commit", "", "specific git commit to scan")
	manifestsCmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces (kube-system, kube-public, etc.)")
	manifestsCmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")

	// Performance optimization flags for manifests
	manifestsCmd.Flags().Int("batch-size", 50, "number of files to process in each batch")
	manifestsCmd.Flags().Int("parallelism", 4, "number of parallel workers for scanning")
	manifestsCmd.Flags().Bool("streaming-mode", false, "enable streaming mode to reduce memory usage")
	manifestsCmd.Flags().Int64("memory-limit", 0, "maximum memory usage in MB (0 = unlimited)")

	// Enhanced filtering flags for manifests

	// Interactive and user experience flags for manifests
	manifestsCmd.Flags().Bool("interactive", false, "enable interactive mode with progress bars")
	manifestsCmd.Flags().Bool("show-progress", true, "show progress indicators during scanning")
	manifestsCmd.Flags().Bool("quiet", false, "suppress non-essential output")
	manifestsCmd.Flags().Bool("summary-only", false, "show only summary statistics")

	// Helm scan flags
	helmCmd.Flags().StringSlice("values", []string{}, "values files for Helm chart rendering")
	helmCmd.Flags().StringSlice("set", []string{}, "set values for Helm chart rendering (key=value)")
	helmCmd.Flags().StringSlice("set-string", []string{}, "set STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	helmCmd.Flags().String("release-name", "test-release", "release name for Helm chart rendering")
	helmCmd.Flags().String("namespace", "default", "namespace for Helm chart rendering")
	helmCmd.Flags().Bool("include-dependencies", true, "include chart dependencies in scan")
	helmCmd.Flags().Bool("validate-schema", true, "validate chart schema before scanning")
	helmCmd.Flags().String("kube-version", "", "kubernetes version to use for rendering (e.g., 1.28.0)")
	helmCmd.Flags().Bool("fail-on-violations", false, "exit with non-zero code if violations are found")
	helmCmd.Flags().Int("max-violations", 0, "maximum number of violations before stopping scan (0 = unlimited)")
	helmCmd.Flags().Bool("include-passed", false, "include passed rules in the report")
	helmCmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces (kube-system, kube-public, etc.)")
	helmCmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")
	helmCmd.Flags().Bool("skip-tests", false, "skip test templates when scanning")
	helmCmd.Flags().Bool("skip-crds", false, "skip Custom Resource Definitions when scanning")
	helmCmd.Flags().String("chart-repo", "", "helm chart repository URL")
	helmCmd.Flags().String("chart-version", "", "specific chart version to scan")
	helmCmd.Flags().Bool("update-dependencies", false, "update chart dependencies before scanning")

	// Enhanced filtering flags for helm

	// Common scan flags
	for _, cmd := range []*cobra.Command{clusterCmd, manifestsCmd, helmCmd} {
		cmd.Flags().String("min-severity", "", "minimum severity level to report (low, medium, high, critical)")
		cmd.Flags().StringSlice("include-rules", []string{}, "specific rule IDs to include")
		cmd.Flags().StringSlice("exclude-rules", []string{}, "specific rule IDs to exclude")
		cmd.Flags().StringSlice("categories", []string{}, "rule categories to include")
		cmd.Flags().StringToString("custom-filters", map[string]string{}, "custom filter expressions (key=value)")
		cmd.Flags().Bool("fail-on-high", false, "exit with non-zero code if high severity issues found")
		cmd.Flags().Bool("fail-on-critical", false, "exit with non-zero code if critical severity issues found")
		cmd.Flags().Bool("continue-on-error", true, "continue scanning even if some resources fail")
		// Note: 'no-color' flag is inherited from global persistent flags
	}
}

func runClusterScan(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(viper.GetString("timeout")))
	defer cancel()

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Starting cluster scan")
	}

	// Load and filter security rules
	rules, err := loadAndFilterSecurityRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
	}

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Initialize Kubernetes client
	k8sClient, err := initializeK8sClient()
	if err != nil {
		return fmt.Errorf("failed to initialize Kubernetes client: %w", err)
	}

	// Validate cluster connection
	if err := k8sClient.ValidateConnection(ctx); err != nil {
		return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
	}

	// Initialize scanner and engine
	scanner := initializeScanner(k8sClient)
	engine, err := initializeEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize evaluation engine: %w", err)
	}

	// Execute cluster scan
	scanResult, err := executeClusterScan(ctx, scanner, engine, rules, scanConfig)
	if err != nil {
		return fmt.Errorf("cluster scan failed: %w", err)
	}

	// Generate and output report
	if err := generateReport(scanResult, scanConfig); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Cluster scan completed successfully", "violations", scanResult.Failed, "total_resources", scanResult.TotalResources)
	}
	return nil
}

func runManifestsScan(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(viper.GetString("timeout")))
	defer cancel()

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Starting manifests scan")
	}

	// Load and filter security rules
	rules, err := loadAndFilterSecurityRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
	}

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Collect all manifest files
	var manifestFiles []string
	recursive, _ := cmd.Flags().GetBool("recursive")
	extensions, _ := cmd.Flags().GetStringSlice("file-extensions")

	for _, path := range args {
		files, err := collectManifestFiles(path, recursive, extensions)
		if err != nil {
			return fmt.Errorf("failed to collect manifest files from %s: %w", path, err)
		}
		manifestFiles = append(manifestFiles, files...)
	}

	if logLevel == "debug" {
		logger.Info("Found manifest files to scan", "count", len(manifestFiles))
	}

	// Initialize scanner and engine
	scanner := initializeFileScanner()
	engine, err := initializeEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize evaluation engine: %w", err)
	}

	// Execute manifests scan
	scanResult, err := executeManifestsScan(ctx, scanner, engine, rules, manifestFiles, scanConfig)
	if err != nil {
		return fmt.Errorf("manifests scan failed: %w", err)
	}

	// Generate and output report
	if err := generateReport(scanResult, scanConfig); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Manifests scan completed successfully", "violations", scanResult.Failed, "total_resources", scanResult.TotalResources)
	}
	return nil
}

func runHelmScan(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(viper.GetString("timeout")))
	defer cancel()

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Starting Helm charts scan")
	}

	// Load and filter security rules
	rules, err := loadAndFilterSecurityRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
		logger.Info("Scanning Helm charts", "count", len(args))
	}

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Initialize scanner and engine
	scanner := initializeHelmScanner()
	engine, err := initializeEngine()
	if err != nil {
		return fmt.Errorf("failed to initialize evaluation engine: %w", err)
	}

	// Execute Helm scan
	scanResult, err := executeHelmScan(ctx, scanner, engine, rules, args, scanConfig)
	if err != nil {
		return fmt.Errorf("helm scan failed: %w", err)
	}

	// Generate and output report
	if err := generateReport(scanResult, scanConfig); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Helm charts scan completed successfully", "violations", scanResult.Failed, "total_resources", scanResult.TotalResources)
	}
	return nil
}

// loadSecurityRules loads security rules from built-in embedded rules and configured paths
func loadSecurityRules() ([]*models.SecurityRule, error) {
	parser := parser.NewYAMLParser(true)
	var allRules []*models.SecurityRule

	// Always load built-in rules first
	builtinRules, err := loadBuiltinRules(parser)
	if err != nil {
		return nil, fmt.Errorf("failed to load built-in rules: %w", err)
	}
	allRules = append(allRules, builtinRules...)

	// Load external rules if specified
	rulesPaths := viper.GetStringSlice("rules-path")
	if len(rulesPaths) > 0 {
		externalRules, err := loadExternalRules(parser, rulesPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to load external rules: %w", err)
		}
		allRules = append(allRules, externalRules...)
	}

	return allRules, nil
}

// loadAndFilterSecurityRules loads security rules and applies include/exclude filtering
func loadAndFilterSecurityRules(cmd *cobra.Command) ([]*models.SecurityRule, error) {
	// Load all rules first
	allRules, err := loadSecurityRules()
	if err != nil {
		return nil, err
	}

	// Get filter flags
	includeRules, _ := cmd.Flags().GetStringSlice("include-rules")
	excludeRules, _ := cmd.Flags().GetStringSlice("exclude-rules")
	categories, _ := cmd.Flags().GetStringSlice("categories")

	// Apply filtering
	filteredRules := applyRuleFilters(allRules, includeRules, excludeRules, categories)

	return filteredRules, nil
}

// applyRuleFilters filters rules based on include/exclude criteria
func applyRuleFilters(rules []*models.SecurityRule, includeRules, excludeRules, categories []string) []*models.SecurityRule {
	// If no filters specified, return all rules
	if len(includeRules) == 0 && len(excludeRules) == 0 && len(categories) == 0 {
		return rules
	}

	var filteredRules []*models.SecurityRule

	// Convert slices to maps for faster lookup
	includeMap := make(map[string]bool)
	for _, id := range includeRules {
		includeMap[id] = true
	}

	excludeMap := make(map[string]bool)
	for _, id := range excludeRules {
		excludeMap[id] = true
	}

	categoryMap := make(map[string]bool)
	for _, cat := range categories {
		categoryMap[strings.ToLower(cat)] = true
	}

	for _, rule := range rules {
		ruleID := rule.Spec.ID
		ruleCategory := strings.ToLower(rule.Spec.Category)

		// Skip if explicitly excluded
		if excludeMap[ruleID] {
			continue
		}

		// If include-rules is specified, only include those rules
		if len(includeRules) > 0 {
			if !includeMap[ruleID] {
				continue
			}
		}

		// If categories is specified, only include rules from those categories
		if len(categories) > 0 {
			if !categoryMap[ruleCategory] {
				continue
			}
		}

		filteredRules = append(filteredRules, rule)
	}

	return filteredRules
}

// loadBuiltinRules loads the embedded built-in security rules
func loadBuiltinRules(parser *parser.YAMLParser) ([]*models.SecurityRule, error) {
	if BuiltinRulesFS == nil {
		return nil, fmt.Errorf("built-in rules filesystem not initialized")
	}
	rules, err := parser.ParseRulesFromFS(context.Background(), BuiltinRulesFS, "rules/builtin")
	if err != nil {
		return nil, fmt.Errorf("failed to parse built-in rules: %w", err)
	}
	return rules, nil
}

// loadExternalRules loads security rules from external file paths
func loadExternalRules(parser *parser.YAMLParser, rulesPaths []string) ([]*models.SecurityRule, error) {
	var allRules []*models.SecurityRule

	for _, path := range rulesPaths {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return nil, fmt.Errorf("rules path does not exist: %s", path)
		}

		info, err := os.Stat(path)
		if err != nil {
			return nil, fmt.Errorf("failed to stat rules path %s: %w", path, err)
		}

		if info.IsDir() {
			rules, err := parser.ParseRulesFromDirectory(context.Background(), path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse rules from directory %s: %w", path, err)
			}
			allRules = append(allRules, rules...)
		} else {
			rule, err := parser.ParseRuleFromFile(context.Background(), path)
			if err != nil {
				return nil, fmt.Errorf("failed to parse rule from file %s: %w", path, err)
			}
			allRules = append(allRules, rule)
		}
	}

	return allRules, nil
}

// collectManifestFiles collects all manifest files from the given path
func collectManifestFiles(path string, recursive bool, extensions []string) ([]string, error) {
	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		// Single file
		if hasValidExtension(path, extensions) {
			return []string{path}, nil
		}
		return nil, nil
	}

	// Directory
	if recursive {
		err = filepath.WalkDir(path, func(filePath string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && hasValidExtension(filePath, extensions) {
				files = append(files, filePath)
			}
			return nil
		})
	} else {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				filePath := filepath.Join(path, entry.Name())
				if hasValidExtension(filePath, extensions) {
					files = append(files, filePath)
				}
			}
		}
	}

	return files, err
}

// hasValidExtension checks if the file has a valid extension
func hasValidExtension(filePath string, extensions []string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	for _, validExt := range extensions {
		if ext == strings.ToLower(validExt) {
			return true
		}
	}
	return false
}

// parseDuration parses a duration string with fallback
func parseDuration(s string) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return 5 * time.Minute // Default timeout
	}
	return d
}

// ScanConfig holds configuration for scan operations
type ScanConfig struct {
	Output                  string
	OutputFile              string
	MaxConcurrency          int
	Timeout                 time.Duration
	MinSeverity             string
	IncludeNamespaces       []string
	ExcludeNamespaces       []string
	ResourceTypes           []string
	Recursive               bool
	FileExtensions          []string
	NoColor                 bool
	Verbose                 bool
	FailOnViolations        bool
	ExcludeSystemNamespaces bool
	IncludeClusterResources bool
}

// buildScanConfig creates scan configuration from command flags
func buildScanConfig(cmd *cobra.Command) (*ScanConfig, error) {
	// Get command name to determine which section of config to use
	cmdName := cmd.Name()

	config := &ScanConfig{
		Output:         viper.GetString("output"),
		OutputFile:     viper.GetString("output-file"),
		MaxConcurrency: viper.GetInt("max-concurrency"),
		Timeout:        parseDuration(viper.GetString("timeout")),
		NoColor:        viper.GetBool("no-color"),
		Verbose:        viper.GetBool("verbose"),
	}

	// Set defaults based on config file for specific command types
	switch cmdName {
	case "cluster":
		// Read cluster-specific settings from config
		config.ExcludeSystemNamespaces = viper.GetBool("scan.cluster.exclude-system-namespaces")
		config.IncludeClusterResources = viper.GetBool("scan.cluster.include-cluster-resources")
	case "manifests":
		// Read manifests-specific settings from config
		config.Recursive = viper.GetBool("scan.manifests.recursive")
	case "helm":
		// Read helm-specific settings from config
	}

	// Get command-specific flags (these override config file settings)
	if cmd.Flags().Changed("min-severity") {
		config.MinSeverity, _ = cmd.Flags().GetString("min-severity")
	}
	if cmd.Flags().Changed("namespace") {
		namespaces, _ := cmd.Flags().GetStringSlice("namespace")
		config.IncludeNamespaces = namespaces
	}
	if cmd.Flags().Changed("exclude-namespaces") {
		excludeNs, _ := cmd.Flags().GetStringSlice("exclude-namespaces")
		config.ExcludeNamespaces = excludeNs
	}
	if cmd.Flags().Changed("resource-types") {
		resTypes, _ := cmd.Flags().GetStringSlice("resource-types")
		config.ResourceTypes = resTypes
	}
	if cmd.Flags().Changed("recursive") {
		config.Recursive, _ = cmd.Flags().GetBool("recursive")
	}
	if cmd.Flags().Changed("file-extensions") {
		extensions, _ := cmd.Flags().GetStringSlice("file-extensions")
		config.FileExtensions = extensions
	}
	if cmd.Flags().Changed("exclude-system-namespaces") {
		config.ExcludeSystemNamespaces, _ = cmd.Flags().GetBool("exclude-system-namespaces")
	}
	if cmd.Flags().Changed("include-cluster-resources") {
		config.IncludeClusterResources, _ = cmd.Flags().GetBool("include-cluster-resources")
	}

	// Set defaults
	if len(config.FileExtensions) == 0 {
		config.FileExtensions = []string{".yaml", ".yml", ".json"}
	}
	if config.MaxConcurrency <= 0 {
		config.MaxConcurrency = 10
	}

	return config, nil
}

// initializeK8sClient creates and configures Kubernetes client
func initializeK8sClient() (k8s.Client, error) {
	kubeconfig := viper.GetString("kubeconfig")
	context := viper.GetString("context")

	client, err := k8s.NewClient(kubeconfig, context)
	if err != nil {
		return nil, fmt.Errorf("failed to create Kubernetes client: %w", err)
	}

	return client, nil
}

// initializeScanner creates resource scanner for cluster operations
func initializeScanner(client k8s.Client) k8s.ResourceScanner {
	return k8s.NewScanner(client)
}

// initializeFileScanner creates scanner for file-based operations
func initializeFileScanner() k8s.ResourceScanner {
	return k8s.NewScanner(nil) // File scanner doesn't need k8s client
}

// initializeHelmScanner creates scanner for Helm chart operations
func initializeHelmScanner() k8s.ResourceScanner {
	return k8s.NewScanner(nil) // Helm scanner doesn't need k8s client
}

// initializeEngine creates and configures CEL evaluation engine
func initializeEngine() (engine.EvaluationEngine, error) {
	engine, err := engine.NewCELEngine()
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL engine: %w", err)
	}

	return engine, nil
}

// executeClusterScan performs the actual cluster scanning with concurrency control
func executeClusterScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SecurityRule, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Convert resource types from strings to GVKs
	var gvks []schema.GroupVersionKind
	for _, rt := range config.ResourceTypes {
		// Parse resource type string (format: group/version/kind)
		parts := strings.Split(rt, "/")
		if len(parts) == 3 {
			gvks = append(gvks, schema.GroupVersionKind{
				Group:   parts[0],
				Version: parts[1],
				Kind:    parts[2],
			})
		}
	}

	// Build scan options with dynamic filtering enabled
	scanOptions := k8s.ScanOptions{
		IncludeNamespaces:       config.IncludeNamespaces,
		ExcludeNamespaces:       config.ExcludeNamespaces,
		ResourceTypes:           gvks,
		IncludeSystemNamespaces: !config.ExcludeSystemNamespaces, // Use the config value
		IncludeClusterResources: config.IncludeClusterResources,  // Use the config value
		MaxConcurrency:          config.MaxConcurrency,
		Timeout:                 config.Timeout.String(),
		NamespacePatterns: k8s.NamespaceFilterConfig{
			UseDynamicDetection: true,
			UseSecureValidation: true,
		},
		ResourceFilterConfig: k8s.ResourceFilterConfig{
			UseDynamicFiltering: true,
		},
	}

	// Scan cluster resources
	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Scanning cluster resources...")
	}

	resources, err := scanner.ScanCluster(ctx, scanOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to scan cluster: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Found resources to evaluate", "count", len(resources))
	}

	// Evaluate rules against resources with concurrency control
	return evaluateResourcesConcurrently(ctx, engine, rules, resources, config)
}

// executeManifestsScan performs manifest file scanning with concurrency control
func executeManifestsScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SecurityRule, manifestFiles []string, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Build scan options with dynamic filtering enabled
	scanOptions := k8s.ScanOptions{
		Recursive:               config.Recursive,
		MaxConcurrency:          config.MaxConcurrency,
		Timeout:                 config.Timeout.String(),
		IncludeSystemNamespaces: !config.ExcludeSystemNamespaces, // Use the config value
		IncludeClusterResources: config.IncludeClusterResources,  // Use the config value
		NamespacePatterns: k8s.NamespaceFilterConfig{
			UseDynamicDetection: true,
			UseSecureValidation: true,
		},
		ResourceFilterConfig: k8s.ResourceFilterConfig{
			UseDynamicFiltering: true,
		},
	}

	// Scan manifest files
	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Parsing manifest files...")
	}
	resources, err := scanner.ScanManifests(ctx, manifestFiles, scanOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to scan manifests: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Parsed resources from manifest files", "count", len(resources))
	}

	// Evaluate rules against resources with concurrency control
	return evaluateResourcesConcurrently(ctx, engine, rules, resources, config)
}

// executeHelmScan performs Helm chart scanning
func executeHelmScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SecurityRule, chartPaths []string, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Get Helm-specific flags
	valuesFiles := viper.GetStringSlice("values")
	setValues := viper.GetStringSlice("set")
	setStringValues := viper.GetStringSlice("set-string")
	releaseName := viper.GetString("release-name")
	namespace := viper.GetString("namespace")
	kubeVersion := viper.GetString("kube-version")
	skipCRDs := viper.GetBool("skip-crds")
	skipTests := viper.GetBool("skip-tests")
	validateSchema := viper.GetBool("validate-schema")
	updateDependencies := viper.GetBool("update-dependencies")

	// Build scan options with dynamic filtering enabled
	scanOptions := k8s.ScanOptions{
		MaxConcurrency:          config.MaxConcurrency,
		Timeout:                 config.Timeout.String(),
		IncludeSystemNamespaces: !config.ExcludeSystemNamespaces, // Use the config value
		IncludeClusterResources: config.IncludeClusterResources,  // Use the config value
		NamespacePatterns: k8s.NamespaceFilterConfig{
			UseDynamicDetection: true,
			UseSecureValidation: true,
		},
		ResourceFilterConfig: k8s.ResourceFilterConfig{
			UseDynamicFiltering: true,
		},
		HelmOptions: k8s.HelmOptions{
			ReleaseName:        releaseName,
			Namespace:          namespace,
			KubeVersion:        kubeVersion,
			ValuesFiles:        valuesFiles,
			SetValues:          setValues,
			SetStringValues:    setStringValues,
			SkipCRDs:           skipCRDs,
			SkipTests:          skipTests,
			ValidateSchema:     validateSchema,
			UpdateDependencies: updateDependencies,
			IncludeCRDs:        !skipCRDs, // Inverse of SkipCRDs
		},
	}

	// Scan Helm charts
	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Rendering and scanning Helm charts...")
	}
	resources, err := scanner.ScanHelmCharts(ctx, chartPaths, scanOptions)
	if err != nil {
		return nil, fmt.Errorf("failed to scan Helm charts: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Rendered resources from Helm charts", "count", len(resources))
	}

	// Evaluate rules against resources with concurrency control
	return evaluateResourcesConcurrently(ctx, engine, rules, resources, config)
}

// evaluateResourcesConcurrently evaluates rules against resources with controlled concurrency
func evaluateResourcesConcurrently(ctx context.Context, engine engine.EvaluationEngine, rules []*models.SecurityRule, resources []map[string]interface{}, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()
	startTime := time.Now()

	// Initialize progress bar
	progressBar := progress.NewProgressBar(len(resources), "🔍 Scanning resources")
	defer progressBar.Finish()

	// Create worker pool for concurrent evaluation
	resourceChan := make(chan map[string]interface{}, len(resources))
	resultChan := make(chan *models.ScanResult, config.MaxConcurrency)
	errorChan := make(chan error, config.MaxConcurrency)

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < config.MaxConcurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for resource := range resourceChan {
				select {
				case <-ctx.Done():
					errorChan <- ctx.Err()
					return
				default:
					result, err := engine.EvaluateRulesAgainstResources(ctx, rules, []map[string]interface{}{resource})
					if err != nil {
						errorChan <- fmt.Errorf("failed to evaluate resource: %w", err)
						return
					}
					resultChan <- result
					// Update progress after processing each resource
					progressBar.Increment()
				}
			}
		}()
	}

	// Send resources to workers
	go func() {
		defer close(resourceChan)
		for _, resource := range resources {
			select {
			case <-ctx.Done():
				return
			case resourceChan <- resource:
			}
		}
	}()

	// Collect results
	go func() {
		wg.Wait()
		close(resultChan)
		close(errorChan)
	}()

	// Aggregate results
	finalResult := &models.ScanResult{
		TotalResources: len(resources),
		TotalRules:     len(rules),
		Results:        make([]models.ValidationResult, 0),
		Timestamp:      startTime,
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case err := <-errorChan:
			if err != nil {
				return nil, err
			}
		case result, ok := <-resultChan:
			if !ok {
				// All results collected
				endTime := time.Now()
				finalResult.Duration = endTime.Sub(startTime)

				// Count failed (violations) vs passed results correctly
				failedCount := 0
				passedCount := 0
				for _, result := range finalResult.Results {
					if result.Passed {
						passedCount++
					} else {
						failedCount++
					}
				}
				finalResult.Failed = failedCount
				finalResult.Passed = passedCount

				// Filter by severity if specified
				if config.MinSeverity != "" {
					finalResult.Results = filterBySeverity(finalResult.Results, config.MinSeverity)

					// Recalculate passed/failed counts after filtering
					failedCount = 0
					passedCount = 0
					for _, result := range finalResult.Results {
						if result.Passed {
							passedCount++
						} else {
							failedCount++
						}
					}
					finalResult.Failed = failedCount
					finalResult.Passed = passedCount
				}

				logLevel := viper.GetString("log-level")
				if logLevel == "debug" {
					logger.Info("Evaluation completed", "duration", finalResult.Duration)
				}
				return finalResult, nil
			}
			if result != nil {
				finalResult.Results = append(finalResult.Results, result.Results...)
			}
		}
	}
}

// filterBySeverity filters results by minimum severity level
func filterBySeverity(results []models.ValidationResult, minSeverity string) []models.ValidationResult {
	severityLevels := map[string]int{
		"low":      1,
		"medium":   2,
		"high":     3,
		"critical": 4,
	}

	minLevel, exists := severityLevels[strings.ToLower(minSeverity)]
	if !exists {
		return results // Return all if invalid severity
	}

	var filtered []models.ValidationResult
	for _, result := range results {
		if !result.Passed {
			resultLevel, exists := severityLevels[strings.ToLower(string(result.Severity))]
			if exists && resultLevel >= minLevel {
				filtered = append(filtered, result)
			}
		}
	}

	return filtered
}

// generateReport creates and outputs the scan report
func generateReport(scanResult *models.ScanResult, config *ScanConfig) error {
	logger := GetLogger()
	ctx := context.Background()

	// Create reporter factory
	factory := reporter.NewFactory()

	// Create reporter based on output format
	reporter, err := factory.CreateReporterWithOptions(config.Output, config.NoColor, config.Verbose)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	// Generate report
	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Generating scan report...")
	}
	if config.OutputFile != "" {
		// Write to file
		file, err := os.Create(config.OutputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file: %w", err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error("Failed to close output file", "error", err)
			}
		}()

		if err := reporter.WriteReport(ctx, scanResult, file); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}

		if logLevel == "debug" {
			logger.Info("Report saved", "file", config.OutputFile)
		}
	} else {
		// Write to stdout
		if err := reporter.WriteReport(ctx, scanResult, os.Stdout); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
	}

	// Exit with non-zero code if violations found and fail-on-violations is enabled
	if config.FailOnViolations && scanResult.Failed > 0 {
		os.Exit(1)
	}

	return nil
}
