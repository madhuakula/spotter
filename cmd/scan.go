package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/madhuakula/spotter/pkg/cache"
	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/k8s"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/recommendations"
	"github.com/madhuakula/spotter/pkg/reporter"
	"github.com/madhuakula/spotter/pkg/utils"
)

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
  spotter scan cluster --include-rules=SPOTTER-WORKLOAD-SECURITY-105
  
  # Output to file
  spotter scan cluster --output=json --output-file=results.json`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Bind persistent flags from root command
		if err := viper.BindPFlag("output", cmd.Root().PersistentFlags().Lookup("output")); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to bind output flag: %v\n", err)
		}
		if err := viper.BindPFlag("output-file", cmd.Root().PersistentFlags().Lookup("output-file")); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to bind output-file flag: %v\n", err)
		}
	},
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
  spotter scan cluster --resource-types=apps/v1/Deployment,v1/Pod`,
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
	clusterCmd.Flags().StringSlice("resource-types", []string{}, "specific resource types to scan (format: group/version/kind, e.g., apps/v1/Deployment)")
	clusterCmd.Flags().String("context", "", "kubernetes context to use")

	// Manifests scan flags
	manifestsCmd.Flags().Bool("recursive", true, "recursively scan directories")
	manifestsCmd.Flags().StringSlice("file-extensions", []string{".yaml", ".yml", ".json"}, "file extensions to scan")
	manifestsCmd.Flags().StringSlice("include-paths", []string{}, "paths to include in scanning")
	manifestsCmd.Flags().Bool("follow-symlinks", false, "follow symbolic links when scanning directories")

	// Helm scan flags
	helmCmd.Flags().StringSlice("values", []string{}, "values files for Helm chart rendering")
	helmCmd.Flags().StringSlice("set", []string{}, "set values for Helm chart rendering (key=value)")
	helmCmd.Flags().StringSlice("set-string", []string{}, "set STRING values on the command line (can specify multiple or separate values with commas: key1=val1,key2=val2)")
	helmCmd.Flags().String("release-name", "test-release", "release name for Helm chart rendering")
	helmCmd.Flags().String("namespace", "default", "namespace for Helm chart rendering")
	helmCmd.Flags().Bool("include-dependencies", true, "include chart dependencies in scan")
	helmCmd.Flags().Bool("validate-schema", true, "validate chart schema before scanning")
	helmCmd.Flags().String("kube-version", "", "kubernetes version to use for rendering (e.g., 1.28.0)")
	helmCmd.Flags().Bool("skip-tests", false, "skip test templates when scanning")
	helmCmd.Flags().Bool("skip-crds", false, "skip Custom Resource Definitions when scanning")
	helmCmd.Flags().String("chart-repo", "", "helm chart repository URL")
	helmCmd.Flags().String("chart-version", "", "specific chart version to scan")
	helmCmd.Flags().Bool("update-dependencies", false, "update chart dependencies before scanning")

	// Common scan flags
	for _, cmd := range []*cobra.Command{clusterCmd, manifestsCmd, helmCmd} {
		cmd.Flags().StringSlice("include-rules", []string{}, "specific rule IDs to include")
		cmd.Flags().StringSlice("exclude-rules", []string{}, "specific rule IDs to exclude")
		cmd.Flags().StringSlice("categories", []string{}, "rule categories to include")
		cmd.Flags().StringSlice("rules", []string{}, "specific cached rule IDs to use for scanning")
		cmd.Flags().StringSlice("packs", []string{}, "specific cached rule pack IDs to use for scanning")
		cmd.Flags().StringSlice("default-packs", []string{}, "default rule pack IDs to use when no specific rules or packs are specified (auto-pulls if not cached)")
		cmd.Flags().Int("parallelism", 4, "number of parallel workers for scanning and rule evaluation")
		cmd.Flags().String("min-severity", "", "minimum severity level to include (low, medium, high, critical)")
		cmd.Flags().Int("max-violations", 0, "maximum number of violations before stopping scan (0 = no limit)")
		cmd.Flags().Bool("quiet", false, "suppress non-error output")
		cmd.Flags().Bool("summary-only", false, "show only summary statistics")
		cmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces (kube-system, kube-public, etc.)")
		cmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")

		// Note: 'no-color' flag is inherited from global persistent flags

		// Bind common flags to viper so they can be set in config file
		if err := viper.BindPFlag("scan.include-rules", cmd.Flags().Lookup("include-rules")); err != nil {
			panic(fmt.Errorf("failed to bind include-rules flag: %w", err))
		}
		if err := viper.BindPFlag("scan.exclude-rules", cmd.Flags().Lookup("exclude-rules")); err != nil {
			panic(fmt.Errorf("failed to bind exclude-rules flag: %w", err))
		}
		if err := viper.BindPFlag("scan.categories", cmd.Flags().Lookup("categories")); err != nil {
			panic(fmt.Errorf("failed to bind categories flag: %w", err))
		}
		if err := viper.BindPFlag("scan.rules", cmd.Flags().Lookup("rules")); err != nil {
			panic(fmt.Errorf("failed to bind rules flag: %w", err))
		}
		if err := viper.BindPFlag("scan.packs", cmd.Flags().Lookup("packs")); err != nil {
			panic(fmt.Errorf("failed to bind packs flag: %w", err))
		}
		if err := viper.BindPFlag("scan.default-packs", cmd.Flags().Lookup("default-packs")); err != nil {
			panic(fmt.Errorf("failed to bind default-packs flag: %w", err))
		}
		if err := viper.BindPFlag("scan.parallelism", cmd.Flags().Lookup("parallelism")); err != nil {
			panic(fmt.Errorf("failed to bind parallelism flag: %w", err))
		}
		if err := viper.BindPFlag("scan.min-severity", cmd.Flags().Lookup("min-severity")); err != nil {
			panic(fmt.Errorf("failed to bind min-severity flag: %w", err))
		}
		if err := viper.BindPFlag("scan.max-violations", cmd.Flags().Lookup("max-violations")); err != nil {
			panic(fmt.Errorf("failed to bind max-violations flag: %w", err))
		}
		if err := viper.BindPFlag("scan.quiet", cmd.Flags().Lookup("quiet")); err != nil {
			panic(fmt.Errorf("failed to bind quiet flag: %w", err))
		}
		if err := viper.BindPFlag("scan.summary-only", cmd.Flags().Lookup("summary-only")); err != nil {
			panic(fmt.Errorf("failed to bind summary-only flag: %w", err))
		}
		if err := viper.BindPFlag("scan.exclude-system-namespaces", cmd.Flags().Lookup("exclude-system-namespaces")); err != nil {
			panic(fmt.Errorf("failed to bind exclude-system-namespaces flag: %w", err))
		}
		if err := viper.BindPFlag("scan.include-cluster-resources", cmd.Flags().Lookup("include-cluster-resources")); err != nil {
			panic(fmt.Errorf("failed to bind include-cluster-resources flag: %w", err))
		}

	}

	// Bind scan-specific flags to viper for config file support
	// Cluster flags
	if err := viper.BindPFlag("scan.cluster.namespace", clusterCmd.Flags().Lookup("namespace")); err != nil {
		panic(fmt.Errorf("failed to bind scan.cluster.namespace flag: %w", err))
	}
	if err := viper.BindPFlag("scan.cluster.exclude-namespaces", clusterCmd.Flags().Lookup("exclude-namespaces")); err != nil {
		panic(fmt.Errorf("failed to bind scan.cluster.exclude-namespaces flag: %w", err))
	}
	if err := viper.BindPFlag("scan.cluster.resource-types", clusterCmd.Flags().Lookup("resource-types")); err != nil {
		panic(fmt.Errorf("failed to bind scan.cluster.resource-types flag: %w", err))
	}
	if err := viper.BindPFlag("scan.cluster.context", clusterCmd.Flags().Lookup("context")); err != nil {
		panic(fmt.Errorf("failed to bind scan.cluster.context flag: %w", err))
	}

	// Manifests flags
	if err := viper.BindPFlag("scan.manifests.recursive", manifestsCmd.Flags().Lookup("recursive")); err != nil {
		panic(fmt.Errorf("failed to bind scan.manifests.recursive flag: %w", err))
	}
	if err := viper.BindPFlag("scan.manifests.file-extensions", manifestsCmd.Flags().Lookup("file-extensions")); err != nil {
		panic(fmt.Errorf("failed to bind scan.manifests.file-extensions flag: %w", err))
	}
	if err := viper.BindPFlag("scan.manifests.include-paths", manifestsCmd.Flags().Lookup("include-paths")); err != nil {
		panic(fmt.Errorf("failed to bind scan.manifests.include-paths flag: %w", err))
	}
	if err := viper.BindPFlag("scan.manifests.follow-symlinks", manifestsCmd.Flags().Lookup("follow-symlinks")); err != nil {
		panic(fmt.Errorf("failed to bind scan.manifests.follow-symlinks flag: %w", err))
	}

	// Helm flags
	if err := viper.BindPFlag("scan.helm.values", helmCmd.Flags().Lookup("values")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.values flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.set", helmCmd.Flags().Lookup("set")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.set flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.set-string", helmCmd.Flags().Lookup("set-string")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.set-string flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.release-name", helmCmd.Flags().Lookup("release-name")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.release-name flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.namespace", helmCmd.Flags().Lookup("namespace")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.namespace flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.include-dependencies", helmCmd.Flags().Lookup("include-dependencies")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.include-dependencies flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.validate-schema", helmCmd.Flags().Lookup("validate-schema")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.validate-schema flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.kube-version", helmCmd.Flags().Lookup("kube-version")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.kube-version flag: %w", err))
	}

	if err := viper.BindPFlag("scan.helm.skip-tests", helmCmd.Flags().Lookup("skip-tests")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.skip-tests flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.skip-crds", helmCmd.Flags().Lookup("skip-crds")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.skip-crds flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.chart-repo", helmCmd.Flags().Lookup("chart-repo")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.chart-repo flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.chart-version", helmCmd.Flags().Lookup("chart-version")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.chart-version flag: %w", err))
	}
	if err := viper.BindPFlag("scan.helm.update-dependencies", helmCmd.Flags().Lookup("update-dependencies")); err != nil {
		panic(fmt.Errorf("failed to bind scan.helm.update-dependencies flag: %w", err))
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

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Show startup message unless quiet mode is enabled
	if !scanConfig.Quiet {
		fmt.Println("🔍 Starting Kubernetes cluster security scan...")
	}

	// Load and filter security rules
	rules, err := loadAndFilterRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	// Show startup message
	fmt.Fprintf(os.Stderr, "🚀 Starting cluster scan with %d rules...\n", len(rules))

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
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

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Show startup message unless quiet mode is enabled
	if !scanConfig.Quiet {
		fmt.Println("📄 Starting Kubernetes manifest security scan...")
	}

	// Load and filter security rules using resolved config
	rules, err := loadAndFilterRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	// Show startup message
	fmt.Fprintf(os.Stderr, "🚀 Starting manifests scan with %d rules...\n", len(rules))

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
	}

	// Collect all manifest files
	var manifestFiles []string
	recursive, _ := cmd.Flags().GetBool("recursive")
	extensions, _ := cmd.Flags().GetStringSlice("file-extensions")
	followSymlinks := viper.GetBool("scan.manifests.follow-symlinks")

	pathsToScan := append([]string{}, args...)
	includePaths := viper.GetStringSlice("scan.manifests.include-paths")
	pathsToScan = append(pathsToScan, includePaths...)

	for _, path := range pathsToScan {
		files, err := utils.CollectFiles(path, utils.FileCollectionOptions{
			Recursive:      recursive,
			Extensions:     extensions,
			FollowSymlinks: followSymlinks,
		})
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

	// Initialize scan configuration
	scanConfig, err := buildScanConfig(cmd)
	if err != nil {
		return fmt.Errorf("failed to build scan configuration: %w", err)
	}

	// Show startup message unless quiet mode is enabled
	if !scanConfig.Quiet {
		fmt.Println("⎈ Starting Helm chart security scan...")
	}

	// Load and filter security rules using resolved config
	rules, err := loadAndFilterRules(cmd)
	if err != nil {
		return fmt.Errorf("failed to load security rules: %w", err)
	}

	// Show startup message
	fmt.Fprintf(os.Stderr, "🚀 Starting Helm charts scan with %d rules...\n", len(rules))

	if logLevel == "debug" {
		logger.Info("Loaded security rules", "count", len(rules))
		logger.Info("Scanning Helm charts", "count", len(args))
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

// loadSpecificRulesAndPacks loads specific rules and rules from packs
func loadSpecificRulesAndPacks(ruleIDs, packIDs []string) ([]*models.SpotterRule, error) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	cacheManager := cache.NewCacheManager(cfg)
	allRules := make([]*models.SpotterRule, 0)
	ruleIDSet := make(map[string]bool)

	// Load specific rules
	for _, ruleID := range ruleIDs {
		rule, err := cacheManager.GetRule(ruleID)
		if err != nil {
			return nil, fmt.Errorf("failed to load rule %s: %w", ruleID, err)
		}
		if !ruleIDSet[rule.GetID()] {
			allRules = append(allRules, rule)
			ruleIDSet[rule.GetID()] = true
		}
	}

	// Load rules from specific packs
	for _, packID := range packIDs {
		pack, err := cacheManager.GetRulePack(packID)
		if err != nil {
			return nil, fmt.Errorf("failed to load pack %s: %w", packID, err)
		}
		// Add all rules from the pack (Rules field contains rule IDs)
		for _, ruleID := range pack.Rules {
			if !ruleIDSet[ruleID] {
				// Load the actual rule from cache
				rule, err := cacheManager.GetRule(ruleID)
				if err != nil {
					return nil, fmt.Errorf("failed to load rule %s from pack %s: %w", ruleID, packID, err)
				}
				allRules = append(allRules, rule)
				ruleIDSet[ruleID] = true
			}
		}
	}

	return allRules, nil
}

// loadDefaultPacksWithAutoPull loads rules from default packs with auto-pull functionality
func loadDefaultPacksWithAutoPull(packIDs []string) ([]*models.SpotterRule, error) {
	cfg, err := config.LoadConfig("")
		if err != nil {
			return nil, fmt.Errorf("failed to load config: %w", err)
		}

	cacheManager := cache.NewCacheManager(cfg)
	hubClient := hub.NewClientWithConfig(cfg)
	allRules := make([]*models.SpotterRule, 0)
	ruleIDSet := make(map[string]bool)

	// Process each default pack
	for _, packID := range packIDs {
		// Check if pack is cached locally
		if !cacheManager.IsPackCached(packID) {
			// Auto-pull the pack from hub
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			pack, err := hubClient.GetRulePack(ctx, packID)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("failed to auto-pull pack %s: %w", packID, err)
			}

			// Save pack to cache
			if err := cacheManager.SaveRulePack(pack); err != nil {
				return nil, fmt.Errorf("failed to cache pack %s: %w", packID, err)
			}

			// Auto-pull all rules in the pack
			for _, ruleID := range pack.Rules {
				if !cacheManager.IsRuleCached(ruleID) {
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					rule, err := hubClient.GetRule(ctx, ruleID)
					cancel()
					if err != nil {
						return nil, fmt.Errorf("failed to auto-pull rule %s from pack %s: %w", ruleID, packID, err)
					}

					if err := cacheManager.SaveRule(rule); err != nil {
						return nil, fmt.Errorf("failed to cache rule %s: %w", ruleID, err)
					}
				}
			}
		}

		// Load pack from cache
		pack, err := cacheManager.GetRulePack(packID)
		if err != nil {
			return nil, fmt.Errorf("failed to load pack %s: %w", packID, err)
		}

		// Load all rules from the pack
		for _, ruleID := range pack.Rules {
			if !ruleIDSet[ruleID] {
				rule, err := cacheManager.GetRule(ruleID)
				if err != nil {
					return nil, fmt.Errorf("failed to load rule %s from pack %s: %w", ruleID, packID, err)
				}
				allRules = append(allRules, rule)
				ruleIDSet[ruleID] = true
			}
		}
	}

	return allRules, nil
}



// loadAndFilterRules loads security rules and applies include/exclude filtering
func loadAndFilterRules(cmd *cobra.Command) ([]*models.SpotterRule, error) {
	// Get specific rules and packs flags
	specificRules, _ := cmd.Flags().GetStringSlice("rules")
	specificPacks, _ := cmd.Flags().GetStringSlice("packs")
	defaultPacks, _ := cmd.Flags().GetStringSlice("default-packs")

	// If specific rules or packs are provided, load only those
	if len(specificRules) > 0 || len(specificPacks) > 0 {
		return loadSpecificRulesAndPacks(specificRules, specificPacks)
	}

	// If default packs are specified, use them with auto-pull
	if len(defaultPacks) > 0 {
		return loadDefaultPacksWithAutoPull(defaultPacks)
	}

	// If no specific rules or packs are provided, use spotter-secure-defaults-pack as default
	return loadDefaultPacksWithAutoPull([]string{"spotter-secure-defaults-pack"})
}



// loadExternalRules loads security rules from external file paths
func loadExternalRules(parser *parser.YAMLParser, rulesPaths []string) ([]*models.SpotterRule, error) {
	var allRules []*models.SpotterRule

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
	Parallelism             int
	Timeout                 time.Duration
	MinSeverity             string
	MaxViolations           int
	Quiet                   bool
	SummaryOnly             bool
	IncludeNamespaces       []string
	ExcludeNamespaces       []string
	ResourceTypes           []string
	Recursive               bool
	FileExtensions          []string
	IncludePaths            []string
	FollowSymlinks          bool
	NoColor                 bool
	Verbose                 bool
	FailOnViolations        bool
	ExcludeSystemNamespaces bool
	IncludeClusterResources bool
}

// buildScanConfig creates scan configuration from command flags
func buildScanConfig(cmd *cobra.Command) (*ScanConfig, error) {
	logger := GetLogger()
	// Get command name to determine which section of config to use
	cmdName := cmd.Name()

	// Get output format with default fallback
	outputFormat := viper.GetString("output")
	if outputFormat == "" {
		outputFormat = "table" // Default to table format
	}

	config := &ScanConfig{
		Output:      outputFormat,
		OutputFile:  viper.GetString("output-file"),
		Parallelism: 4, // Default parallelism, will be overridden by flag
		Timeout:     parseDuration(viper.GetString("timeout")),
		NoColor:     viper.GetBool("no-color"),
		Verbose:     viper.GetBool("verbose"),
	}

	// Load common scan config values from viper (could be from config file or flags)
	config.MinSeverity = viper.GetString("scan.min-severity")
	config.MaxViolations = viper.GetInt("scan.max-violations")
	config.Quiet = viper.GetBool("scan.quiet")
	config.SummaryOnly = viper.GetBool("scan.summary-only")
	config.Parallelism = viper.GetInt("scan.parallelism")

	// Set defaults based on config file for specific command types
	switch cmdName {
	case "cluster":
		// Read cluster-specific settings from config
		config.ExcludeSystemNamespaces = viper.GetBool("scan.cluster.exclude-system-namespaces")
		config.IncludeClusterResources = viper.GetBool("scan.cluster.include-cluster-resources")
		if len(config.IncludeNamespaces) == 0 {
			config.IncludeNamespaces = viper.GetStringSlice("scan.cluster.namespace")
		}
		if len(config.ExcludeNamespaces) == 0 {
			config.ExcludeNamespaces = viper.GetStringSlice("scan.cluster.exclude-namespaces")
		}
		if len(config.ResourceTypes) == 0 {
			config.ResourceTypes = viper.GetStringSlice("scan.cluster.resource-types")
		}
	case "manifests":
		// Read manifests-specific settings from config
		config.Recursive = viper.GetBool("scan.manifests.recursive")
		config.FileExtensions = viper.GetStringSlice("scan.manifests.file-extensions")
		config.ExcludeSystemNamespaces = viper.GetBool("scan.manifests.exclude-system-namespaces")
		config.IncludeClusterResources = viper.GetBool("scan.manifests.include-cluster-resources")
		config.IncludePaths = viper.GetStringSlice("scan.manifests.include-paths")
		config.FollowSymlinks = viper.GetBool("scan.manifests.follow-symlinks")
	case "helm":
		// Read helm-specific settings from config
		config.ExcludeSystemNamespaces = viper.GetBool("scan.helm.exclude-system-namespaces")
		config.IncludeClusterResources = viper.GetBool("scan.helm.include-cluster-resources")
	}

	// Get command-specific flags (these override config file settings)
	if cmd.Flags().Changed("min-severity") {
		config.MinSeverity, _ = cmd.Flags().GetString("min-severity")
	}
	if cmd.Flags().Changed("max-violations") {
		config.MaxViolations, _ = cmd.Flags().GetInt("max-violations")
	}
	if cmd.Flags().Changed("quiet") {
		config.Quiet, _ = cmd.Flags().GetBool("quiet")
	}
	if cmd.Flags().Changed("summary-only") {
		config.SummaryOnly, _ = cmd.Flags().GetBool("summary-only")
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
	if cmd.Flags().Changed("parallelism") {
		config.Parallelism, _ = cmd.Flags().GetInt("parallelism")
	}

	// Set defaults
	if len(config.FileExtensions) == 0 {
		config.FileExtensions = []string{".yaml", ".yml", ".json"}
	}
	if config.Parallelism <= 0 {
		config.Parallelism = 4
	}

	// Log final configuration summary
	logger.Debug("This is the config we're using for the scan",
		"command", cmdName,
		"config_file", viper.ConfigFileUsed(),
		"output", config.Output,
		"parallelism", config.Parallelism,
		"min-severity", config.MinSeverity,
		"max-violations", config.MaxViolations,
		"quiet", config.Quiet,
		"summary-only", config.SummaryOnly,
		"recursive", config.Recursive,
		"file-extensions", config.FileExtensions,
		"exclude-system-namespaces", config.ExcludeSystemNamespaces,
		"include-cluster-resources", config.IncludeClusterResources)

	return config, nil
}

// initializeK8sClient creates and configures Kubernetes client
func initializeK8sClient() (k8s.Client, error) {
	kubeconfig := viper.GetString("kubeconfig")
	context := viper.GetString("context")

	// Read client configuration
	clientConfig := &k8s.ClientConfig{
		QPS:            viper.GetFloat64("client.qps"),
		Burst:          viper.GetInt("client.burst"),
		MaxConcurrency: viper.GetInt("client.max_concurrency"),
		Retry: k8s.RetryConfig{
			MaxAttempts: viper.GetInt("client.retry.max_attempts"),
			BaseDelayMs: viper.GetInt("client.retry.base_delay_ms"),
			MaxDelayS:   viper.GetInt("client.retry.max_delay_s"),
		},
	}

	// Set defaults if not configured
	if clientConfig.QPS == 0 {
		clientConfig.QPS = 50.0
	}
	if clientConfig.Burst == 0 {
		clientConfig.Burst = 100
	}
	if clientConfig.MaxConcurrency == 0 {
		clientConfig.MaxConcurrency = 5
	}
	if clientConfig.Retry.MaxAttempts == 0 {
		clientConfig.Retry.MaxAttempts = 3
	}
	if clientConfig.Retry.BaseDelayMs == 0 {
		clientConfig.Retry.BaseDelayMs = 100
	}
	if clientConfig.Retry.MaxDelayS == 0 {
		clientConfig.Retry.MaxDelayS = 5
	}

	client, err := k8s.NewClientWithConfig(kubeconfig, context, clientConfig)
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
func executeClusterScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SpotterRule, config *ScanConfig) (*models.ScanResult, error) {
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
func executeManifestsScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SpotterRule, manifestFiles []string, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Build scan options with dynamic filtering enabled
	scanOptions := k8s.ScanOptions{
		Recursive:               config.Recursive,
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
func executeHelmScan(ctx context.Context, scanner k8s.ResourceScanner, engine engine.EvaluationEngine, rules []*models.SpotterRule, chartPaths []string, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Get Helm-specific flags
	valuesFiles := viper.GetStringSlice("scan.helm.values")
	setValues := viper.GetStringSlice("scan.helm.set")
	setStringValues := viper.GetStringSlice("scan.helm.set-string")
	releaseName := viper.GetString("scan.helm.release-name")
	namespace := viper.GetString("scan.helm.namespace")
	kubeVersion := viper.GetString("scan.helm.kube-version")
	skipCRDs := viper.GetBool("scan.helm.skip-crds")
	skipTests := viper.GetBool("scan.helm.skip-tests")
	validateSchema := viper.GetBool("scan.helm.validate-schema")
	updateDependencies := viper.GetBool("scan.helm.update-dependencies")

	// Build scan options with dynamic filtering enabled
	scanOptions := k8s.ScanOptions{
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
func evaluateResourcesConcurrently(ctx context.Context, engine engine.EvaluationEngine, rules []*models.SpotterRule, resources []map[string]interface{}, config *ScanConfig) (*models.ScanResult, error) {
	logger := GetLogger()

	// Use the engine's built-in concurrency with configured parallelism
	// This avoids the double worker pool issue that was causing duplicate evaluations
	result, err := engine.EvaluateRulesAgainstResourcesConcurrent(ctx, rules, resources, config.Parallelism)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate resources: %w", err)
	}

	// Filter by severity if specified
	if config.MinSeverity != "" {
		result.Results = filterBySeverity(result.Results, config.MinSeverity)

		// Recalculate passed/failed counts after filtering
		failedCount := 0
		passedCount := 0
		for _, res := range result.Results {
			if res.Passed {
				passedCount++
			} else {
				failedCount++
			}
		}
		result.Failed = failedCount
		result.Passed = passedCount
	}

	// Apply max-violations limit if specified
	if config.MaxViolations > 0 && result.Failed > config.MaxViolations {
		// Keep only the first MaxViolations failures
		filteredResults := []models.ValidationResult{}
		violationCount := 0

		for _, res := range result.Results {
			if res.Passed {
				filteredResults = append(filteredResults, res)
			} else if violationCount < config.MaxViolations {
				filteredResults = append(filteredResults, res)
				violationCount++
			}
		}

		result.Results = filteredResults
		result.Failed = violationCount
		result.Passed = len(filteredResults) - violationCount

		logLevel := viper.GetString("log-level")
		if logLevel == "debug" {
			logger.Info("Applied max-violations limit", "limit", config.MaxViolations, "actual_violations", violationCount)
		}
	}

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Evaluation completed", "duration", result.Duration)
	}
	return result, nil
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

	// AI enrichment: when enabled, add AI recommendations as separate section
	if viper.GetBool("ai.enable") {
		ctxAI, cancelAI := context.WithTimeout(ctx, parseDuration(viper.GetString("timeout")))
		defer cancelAI()
		out, err := recommendations.GenerateRecommendations(ctxAI, *scanResult, recommendations.Params{
			TopN:     5,
			Model:    viper.GetString("ai.model"),
			Host:     viper.GetString("ai.host"),
			Timeout:  parseDuration(viper.GetString("timeout")),
			Provider: viper.GetString("ai.provider"),
			APIKey:   viper.GetString("ai.apikey"),
		})
		if err == nil {
			// Always store AI output (may contain error or recommendations)
			scanResult.AIRecommendations = out
			if logLevel := viper.GetString("log-level"); logLevel == "debug" {
				if out.Error != "" {
					logger.Debug("AI recommendations generation had issues", "error", out.Error)
				} else if len(out.Recommendations) > 0 {
					logger.Debug("AI recommendations generated successfully", "count", len(out.Recommendations))
				} else {
					logger.Debug("AI model returned no recommendations")
				}
			}
		} else {
			// This shouldn't happen with our new error handling, but keep as fallback
			if logLevel := viper.GetString("log-level"); logLevel == "debug" {
				logger.Debug("AI recommendations generation failed completely", "error", err)
			}
			scanResult.AIRecommendations = nil
		}
	}

	// Create reporter factory
	factory := reporter.NewFactory()

	// Create reporter based on output format
	reporter, err := factory.CreateReporterWithAdvancedOptions(config.Output, config.NoColor, config.Verbose, config.Quiet, config.SummaryOnly)
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
