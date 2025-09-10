package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/madhuakula/spotter/pkg/graphstore"
	"github.com/madhuakula/spotter/pkg/k8s"
)

// inventoryCmd represents the inventory command
var inventoryCmd = &cobra.Command{
	Use:   "inventory",
	Short: "Create a graph database inventory of Kubernetes resources",
	Long: `Create a graph database inventory of Kubernetes resources for attack path analysis.

This command scans Kubernetes resources and creates a graph database that can be used
for attack path analysis. The graph database contains nodes and relationships between
resources like pods, secrets, service accounts, etc.

Examples:
  # Create inventory from live cluster
  spotter inventory --path=./graph.db
  
  # Create inventory with custom cache settings
  spotter inventory --path=./graph.db --cache-ttl=2h --no-cache=false
  
  # Force refresh existing inventory
  spotter inventory --path=./graph.db --force-refresh`,
	RunE: runInventory,
}

func init() {
	rootCmd.AddCommand(inventoryCmd)

	// Inventory flags
	inventoryCmd.Flags().String("path", "", "path where to create the graph database (required)")
	inventoryCmd.Flags().String("cache-ttl", "1h", "cache time-to-live (e.g., 10m, 1h, 24h)")
	inventoryCmd.Flags().String("cache-dir", "", "cache directory (default: follows XDG Base Directory spec)")
	inventoryCmd.Flags().Bool("no-cache", false, "disable caching (in-memory only)")
	inventoryCmd.Flags().Bool("force-refresh", false, "force cache refresh")

	// Cluster scanning options
	inventoryCmd.Flags().StringSliceP("namespace", "n", []string{}, "namespaces to scan (default: all non-system namespaces)")
	inventoryCmd.Flags().StringSlice("exclude-namespaces", []string{}, "namespaces to exclude from scanning")
	inventoryCmd.Flags().StringSlice("resource-types", []string{}, "specific resource types to scan (format: group/version/kind, e.g., apps/v1/Deployment)")
	inventoryCmd.Flags().String("context", "", "kubernetes context to use")
	inventoryCmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces (kube-system, kube-public, etc.)")
	inventoryCmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")

	// Mark path flag as required
	_ = inventoryCmd.MarkFlagRequired("path")
}

func runInventory(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(viper.GetString("timeout")))
	defer cancel()

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Starting inventory creation")
	}

	// Get flags
	graphPath, _ := cmd.Flags().GetString("path")
	cacheTTLStr, _ := cmd.Flags().GetString("cache-ttl")
	cacheDir, _ := cmd.Flags().GetString("cache-dir")
	noCache, _ := cmd.Flags().GetBool("no-cache")
	forceRefresh, _ := cmd.Flags().GetBool("force-refresh")
	includeNamespaces, _ := cmd.Flags().GetStringSlice("namespace")
	excludeNamespaces, _ := cmd.Flags().GetStringSlice("exclude-namespaces")
	kubeContext, _ := cmd.Flags().GetString("context")
	excludeSystemNamespaces, _ := cmd.Flags().GetBool("exclude-system-namespaces")
	includeClusterResources, _ := cmd.Flags().GetBool("include-cluster-resources")

	// Parse cache TTL
	cacheTTL, err := time.ParseDuration(cacheTTLStr)
	if err != nil {
		cacheTTL = time.Hour // Default to 1 hour
	}

	fmt.Println("🏗️  Creating graph database inventory...")

	// Create cache configuration
	cacheConfig := &graphstore.CacheConfig{
		CacheDir:     cacheDir,
		TTL:          cacheTTL,
		NoCache:      noCache,
		ForceRefresh: forceRefresh,
		Target:       "cluster",
	}

	// Create graph store
	graphStore := graphstore.NewKuzuGraphStore(cacheConfig)

	// Force refresh if requested
	if forceRefresh {
		if err := graphStore.Invalidate(); err != nil {
			logger.Warn("Failed to invalidate cache", "error", err)
		}
	}

	// Ensure graph directory exists
	if err := graphstore.EnsureCacheDir(graphPath); err != nil {
		return fmt.Errorf("failed to create graph directory: %w", err)
	}

	// Open graph database
	if err := graphStore.Open(graphPath); err != nil {
		return fmt.Errorf("failed to open graph database: %w", err)
	}
	defer func() {
		if err := graphStore.Close(); err != nil {
			logger.Error("Failed to close graph store", "error", err)
		}
	}()

	// Ensure schema
	if err := graphStore.EnsureSchema(ctx); err != nil {
		return fmt.Errorf("failed to ensure graph schema: %w", err)
	}

	// Initialize Kubernetes client
	k8sClient, err := initializeK8sClient()
	if err != nil {
		return fmt.Errorf("failed to initialize Kubernetes client: %w", err)
	}

	// Set context if provided
	if kubeContext != "" {
		// Note: The k8s client should handle context switching
		// This might need to be implemented in the k8s client
		logger.Info("Using kubernetes context", "context", kubeContext)
	}

	// Validate cluster connection
	if err := k8sClient.ValidateConnection(ctx); err != nil {
		return fmt.Errorf("failed to connect to Kubernetes cluster: %w", err)
	}

	// Initialize scanner
	scanner := initializeScanner(k8sClient)

	// Build scan options
	scanOptions := k8s.ScanOptions{
		IncludeNamespaces:       includeNamespaces,
		ExcludeNamespaces:       excludeNamespaces,
		IncludeSystemNamespaces: !excludeSystemNamespaces,
		IncludeClusterResources: includeClusterResources,
		Timeout:                 viper.GetString("timeout"),
	}

	// Scan cluster resources
	if logLevel == "debug" {
		logger.Info("Scanning cluster resources for inventory...")
	}

	resources, err := scanner.ScanCluster(ctx, scanOptions)
	if err != nil {
		return fmt.Errorf("failed to scan cluster: %w", err)
	}

	fmt.Printf("📦 Found %d resources to analyze\n", len(resources))

	// Extract facts from resources
	extractor := graphstore.NewFactExtractor()
	facts, err := extractor.ExtractFacts(resources)
	if err != nil {
		return fmt.Errorf("failed to extract facts from resources: %w", err)
	}

	// Upsert facts into graph
	if err := graphStore.UpsertFacts(ctx, facts); err != nil {
		return fmt.Errorf("failed to upsert facts into graph: %w", err)
	}

	fmt.Printf("✅ Graph database created successfully at %s\n", graphPath)
	fmt.Printf("   Pods: %d, Secrets: %d, Relationships: %d\n",
		len(facts.Pods), len(facts.Secrets), len(facts.Relationships))

	if logLevel == "debug" {
		logger.Info("Inventory creation completed successfully",
			"path", graphPath,
			"pods", len(facts.Pods),
			"secrets", len(facts.Secrets),
			"relationships", len(facts.Relationships))
	}

	return nil
}
