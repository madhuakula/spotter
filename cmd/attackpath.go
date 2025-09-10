package cmd

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/madhuakula/spotter/pkg/graphstore"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/reporter"
)

// attackPathCmd represents the attack-path command
var attackPathCmd = &cobra.Command{
	Use:   "attack-path",
	Short: "Analyze attack paths using an existing graph database",
	Long: `Analyze attack paths using an existing graph database created by the inventory command.

This command loads an existing graph database and runs correlation queries to identify
potential attack paths such as credential exfiltration and RBAC privilege escalation.

Examples:
  # Analyze attack paths from graph database
  spotter attack-path --path=./graph.db
  
  # Analyze with different output format
  spotter attack-path --path=./graph.db --output=json
  
  # Save results to file
  spotter attack-path --path=./graph.db --output=json --output-file=attack-paths.json`,
	RunE: runAttackPath,
}

func init() {
	rootCmd.AddCommand(attackPathCmd)

	// Attack path flags
	attackPathCmd.Flags().String("path", "", "path to the graph database (required)")

	// Mark path flag as required
	_ = attackPathCmd.MarkFlagRequired("path")
}

func runAttackPath(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx, cancel := context.WithTimeout(context.Background(), parseDuration(viper.GetString("timeout")))
	defer cancel()

	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Starting attack path analysis")
	}

	// Get flags
	graphPath, _ := cmd.Flags().GetString("path")

	// Check if graph database exists
	if _, err := os.Stat(graphPath); os.IsNotExist(err) {
		return fmt.Errorf("graph database not found at %s. Please create it first using 'spotter inventory'", graphPath)
	}

	fmt.Println("🕸️  Starting attack path analysis...")

	startTime := time.Now()

	// Create cache configuration (for existing graph database)
	cacheConfig := &graphstore.CacheConfig{
		Target: "existing",
	}

	// Create graph store
	graphStore := graphstore.NewKuzuGraphStore(cacheConfig)

	// Open existing graph database
	if err := graphStore.Open(graphPath); err != nil {
		return fmt.Errorf("failed to open graph database: %w", err)
	}
	defer func() {
		if err := graphStore.Close(); err != nil {
			logger.Error("Failed to close graph store", "error", err)
		}
	}()

	// Run correlation queries
	correlationTypes := []string{"credential-exfil", "rbac-pivot"}
	findings, err := graphStore.RunCorrelations(ctx, correlationTypes)
	if err != nil {
		return fmt.Errorf("failed to run correlation queries: %w", err)
	}

	// Build result
	pathsByType := make(map[string]int)
	for _, finding := range findings {
		pathsByType[string(finding.Type)]++
	}

	result := &models.AttackPathResult{
		Findings:         findings,
		TotalPaths:       len(findings),
		PathsByType:      pathsByType,
		CacheHit:         true, // Always true since we're reading existing database
		AnalysisDuration: time.Since(startTime),
		Timestamp:        time.Now(),
	}

	fmt.Printf("🎯 Found %d attack paths (%d credential exfil, %d RBAC pivot)\n",
		result.TotalPaths,
		pathsByType[string(models.AttackPathTypeCredentialExfil)],
		pathsByType[string(models.AttackPathTypeRBACPivot)])

	// Create a scan result that contains only attack path findings
	scanResult := &models.ScanResult{
		AttackPathResult: result,
		Timestamp:        time.Now(),
		Duration:         time.Since(startTime),
	}

	// Generate and output report
	if err := generateAttackPathReport(scanResult); err != nil {
		return fmt.Errorf("failed to generate report: %w", err)
	}

	if logLevel == "debug" {
		logger.Info("Attack path analysis completed successfully",
			"total_paths", result.TotalPaths,
			"duration", result.AnalysisDuration)
	}

	return nil
}

// generateAttackPathReport creates and outputs the attack path report
func generateAttackPathReport(scanResult *models.ScanResult) error {
	logger := GetLogger()
	ctx := context.Background()

	// Get output configuration
	outputFormat := viper.GetString("output")
	if outputFormat == "" {
		outputFormat = "table" // Default to table format
	}
	outputFile := viper.GetString("output-file")
	noColor := viper.GetBool("no-color")
	verbose := viper.GetBool("verbose")
	quiet := false       // Don't suppress output for attack path analysis
	summaryOnly := false // Show full results

	// Create reporter factory
	factory := reporter.NewFactory()

	// Create reporter based on output format
	reporter, err := factory.CreateReporterWithAdvancedOptions(outputFormat, noColor, verbose, quiet, summaryOnly)
	if err != nil {
		return fmt.Errorf("failed to create reporter: %w", err)
	}

	// Generate report
	logLevel := viper.GetString("log-level")
	if logLevel == "debug" {
		logger.Info("Generating attack path report...")
	}

	if outputFile != "" {
		// Write to file
		file, err := os.Create(outputFile)
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
			logger.Info("Report saved", "file", outputFile)
		}
	} else {
		// Write to stdout
		if err := reporter.WriteReport(ctx, scanResult, os.Stdout); err != nil {
			return fmt.Errorf("failed to write report: %w", err)
		}
	}

	return nil
}
