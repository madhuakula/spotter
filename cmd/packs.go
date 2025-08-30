package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/madhuakula/spotter/pkg/cache"
	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/progress"
)

// PackWithSource represents a rule pack with its source information
type PackWithSource struct {
	hub.RulePackInfo
	Source string `json:"source"` // "local" or "remote"
	Local  bool   `json:"local"`  // whether it's available locally
}

// packsCmd represents the packs command
var packsCmd = &cobra.Command{
	Use:   "packs",
	Short: "Manage security rule packs",
	Long: `Manage security rule packs for Spotter scanner.

This command provides various operations for working with security rule packs:
- Search for available rule packs
- Pull rule packs from the hub
- List local rule packs
- Show detailed information about specific rule packs

Examples:
  # Search for rule packs
  spotter packs search kubernetes
  
  # Pull a specific rule pack
  spotter packs pull cis-kubernetes-benchmark
  
  # List all local rule packs
  spotter packs list
  
  # Show detailed information about a rule pack
  spotter packs info cis-kubernetes-benchmark`,
}

// packsSearchCmd represents the packs search command
var packsSearchCmd = &cobra.Command{
	Use:   "search [query]",
	Short: "Search for rule packs in the hub",
	Long: `Search for security rule packs in the Spotter hub.

This command searches the remote hub for rule packs matching your query.
You can search by name, description, or tags.

Examples:
  # Search for Kubernetes rule packs
  spotter packs search kubernetes
  
  # Search for CIS benchmarks
  spotter packs search cis
  
  # Search with JSON output
  spotter packs search nist --output json`,
	Args: cobra.MaximumNArgs(1),
	RunE: runPacksSearch,
}

// packsListCmd represents the packs list command
var packsListCmd = &cobra.Command{
	Use:   "list",
	Short: "List local rule packs",
	Long: `List rule packs that have been pulled and stored locally.

This command displays only rule packs that have been downloaded and are available
locally. To discover available rule packs from the hub, use 'spotter packs search'.

Examples:
  # List local rule packs
  spotter packs list
  
  # List with JSON output
  spotter packs list --output json`,
	RunE: runPacksList,
}

// packsPullCmd represents the packs pull command
var packsPullCmd = &cobra.Command{
	Use:   "pull <pack-id>",
	Short: "Pull a rule pack from the hub",
	Long: `Pull a security rule pack from the Spotter hub and store it locally.

This command downloads a rule pack from the remote hub and stores it in the
local storage for offline use. The pack will be available for use with other
Spotter commands.

Examples:
  # Pull a specific rule pack
  spotter packs pull cis-kubernetes-benchmark
  
  # Pull with verbose output
  spotter packs pull nist-800-53 --verbose
  
  # Force re-download even if stored locally
  spotter packs pull cis-kubernetes-benchmark --force`,
	Args: cobra.ExactArgs(1),
	RunE: runPacksPull,
}

// packsInfoCmd represents the packs info command
var packsInfoCmd = &cobra.Command{
	Use:   "info <pack-id>",
	Short: "Show detailed information about a rule pack",
	Long: `Show detailed information about a specific rule pack.

This command displays comprehensive information about a rule pack including:
- Pack metadata and description
- Version and author information
- List of included rules
- Local storage status

Examples:
  # Show pack information
  spotter packs info cis-kubernetes-benchmark
  
  # Show pack info with JSON output
  spotter packs info nist-800-53 --output json`,
	Args: cobra.ExactArgs(1),
	RunE: runPacksInfo,
}

// packsValidateCmd represents the packs validate command
var packsValidateCmd = &cobra.Command{
	Use:   "validate [file|directory]",
	Short: "Validate rule pack files schema",
	Long: `Validate SpotterRulePack YAML files for correct schema.

Examples:
  # Validate a single rule pack file
  spotter packs validate pack.yaml
  
  # Validate all rule packs in a directory
  spotter packs validate ./packs/
  
  # Output results in JSON format
  spotter packs validate pack.yaml --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		runTests := false // Rule packs don't have CEL tests
		outputFormat, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

		return runPacksValidation(path, runTests, outputFormat, verbose)
	},
}

// runPacksValidation validates rule pack files specifically
func runPacksValidation(path string, runTests bool, outputFormat string, verbose bool) error {
	// Import validation functionality from validate.go
	return runValidation(path, runTests, outputFormat, verbose)
}

func init() {
	// Add packs command to root
	rootCmd.AddCommand(packsCmd)

	// Add subcommands to packs
	packsCmd.AddCommand(packsSearchCmd)
	packsCmd.AddCommand(packsListCmd)
	packsCmd.AddCommand(packsPullCmd)
	packsCmd.AddCommand(packsInfoCmd)
	packsCmd.AddCommand(packsValidateCmd)

	// Flags for search command
	packsSearchCmd.Flags().IntP("limit", "l", 10, "Maximum number of results to return")
	packsSearchCmd.Flags().Int("offset", 0, "Number of results to skip")
	packsSearchCmd.Flags().StringP("output", "o", "table", "Output format (table, json)")

	// Flags for list command
	packsListCmd.Flags().StringP("output", "o", "table", "Output format (table, json)")

	// Flags for pull command
	packsPullCmd.Flags().BoolP("force", "f", false, "Force re-download even if pack is stored locally")
	packsPullCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Flags for info command
	packsInfoCmd.Flags().StringP("output", "o", "table", "Output format (table, json)")

	// Flags for validate command
	packsValidateCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
}

func runPacksSearch(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Create hub client
	hubClient := hub.NewClientWithConfig(cfg)

	// Prepare search parameters
	query := ""
	if len(args) > 0 {
		query = args[0]
	}

	limit, _ := cmd.Flags().GetInt("limit")
	offset, _ := cmd.Flags().GetInt("offset")

	// Search for packs
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	fmt.Printf("Searching for rule packs with query: '%s'\n", query)

	// Get all available packs from hub
	allPacks, err := hubClient.GetAllRulePacks(ctx)
	if err != nil {
		fmt.Printf("Warning: Failed to fetch packs from hub: %v\n", err)
		return nil
	}

	// Filter packs based on search query
	var filteredPacks []hub.RulePackInfo
	for _, pack := range allPacks {
		// If no query, include all packs
		if query == "" {
			filteredPacks = append(filteredPacks, pack)
			continue
		}

		// Simple text search in ID, title, and description
		queryLower := strings.ToLower(query)
		if strings.Contains(strings.ToLower(pack.ID), queryLower) ||
			strings.Contains(strings.ToLower(pack.Title), queryLower) ||
			strings.Contains(strings.ToLower(pack.Description), queryLower) {
			filteredPacks = append(filteredPacks, pack)
		}
	}

	// Apply offset and limit
	start := offset
	if start > len(filteredPacks) {
		start = len(filteredPacks)
	}

	end := start + limit
	if limit <= 0 || end > len(filteredPacks) {
		end = len(filteredPacks)
	}

	resultPacks := filteredPacks[start:end]

	if len(resultPacks) == 0 {
		fmt.Println("No rule packs found matching your search criteria.")
		return nil
	}

	// Check output format
	outputFormat, _ := cmd.Flags().GetString("output")
	if outputFormat == "json" {
		return outputPackSearchJSON(resultPacks, len(filteredPacks), limit, offset)
	}

	// Display results in table format
	outputPackSearchTable(resultPacks, len(filteredPacks), limit, offset)
	return nil
}

func runPacksList(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Create cache manager
	cacheManager := cache.NewCacheManager(cfg)

	// Get local packs only
	localPacks, err := cacheManager.ListCachedPacks()
	if err != nil {
		return fmt.Errorf("failed to list local packs: %w", err)
	}

	if len(localPacks) == 0 {
		fmt.Println("No local rule packs found. Use 'spotter packs search' to discover packs and 'spotter packs pull <pack-id>' to download them.")
		return nil
	}

	// Check output format
	outputFormat, _ := cmd.Flags().GetString("output")
	if outputFormat == "json" {
		return outputPacksJSON(localPacks)
	}

	// Output as table
	outputPacksTable(localPacks)
	return nil
}

func runPacksPull(cmd *cobra.Command, args []string) error {
	packID := args[0]

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Create cache manager and hub client
	cacheManager := cache.NewCacheManager(cfg)
	hubClient := hub.NewClientWithConfig(cfg)

	// Check if already stored locally
	force, _ := cmd.Flags().GetBool("force")
	verbose, _ := cmd.Flags().GetBool("verbose")

	if !force && cacheManager.IsPackCached(packID) {
		fmt.Printf("Rule pack '%s' is already stored locally. Use --force to re-download.\n", packID)
		// Still check and pull any missing rules
		if localPack, err := cacheManager.GetRulePack(packID); err == nil {
			if err := pullPackRules(hubClient, cacheManager, localPack, verbose, false); err != nil {
				return fmt.Errorf("failed to ensure all pack rules are stored locally: %w", err)
			}
		}
		return nil
	}

	// Initialize progress bar
	progressBar := progress.NewProgressBar(4, fmt.Sprintf("Pulling pack '%s'", packID))

	if verbose {
		fmt.Printf("\nPulling rule pack '%s' from hub...\n", packID)
	}

	// Pull pack from hub
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	progressBar.Increment() // Step 1: Downloading
	pack, err := hubClient.GetRulePack(ctx, packID)
	if err != nil {
		progressBar.Finish()
		return fmt.Errorf("failed to pull pack from hub: %w", err)
	}

	progressBar.Increment() // Step 2: Validating
	// Pack validation happens in the hub client

	// Save to cache
	progressBar.Increment() // Step 3: Caching
	if err := cacheManager.SaveRulePack(pack); err != nil {
		progressBar.Finish()
		return fmt.Errorf("failed to save pack to cache: %w", err)
	}

	// Pull all required rules for this pack
	progressBar.Increment() // Step 4: Downloading rules
	if err := pullPackRules(hubClient, cacheManager, pack, verbose, force); err != nil {
		progressBar.Finish()
		return fmt.Errorf("failed to pull pack rules: %w", err)
	}

	progressBar.Finish()

	fmt.Printf("Successfully pulled and stored rule pack '%s' (version %s) with %d rules\n", pack.ID, pack.Version, len(pack.Rules))

	if verbose {
		fmt.Printf("Author: %s\n", pack.Author)
		fmt.Printf("Description: %s\n", pack.Description)
	}

	return nil
}

func runPacksInfo(cmd *cobra.Command, args []string) error {
	packID := args[0]

	// Load configuration
	cfg, err := config.LoadConfig()
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Create cache manager
	cacheManager := cache.NewCacheManager(cfg)

	// Get pack from local cache only
	pack, err := cacheManager.GetRulePack(packID)
	if err != nil {
		return fmt.Errorf("rule pack '%s' not found locally. Use 'spotter packs pull %s' to download it from the hub", packID, packID)
	}

	// Check output format
	outputFormat, _ := cmd.Flags().GetString("output")
	if outputFormat == "json" {
		return outputPackInfoJSON(pack)
	}

	// Output as table
	return outputPackInfoTable(pack)
}

func outputPacksTable(packs []cache.CacheEntry) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTYPE\tVERSION\tCACHED AT\tLAST UPDATED")
	fmt.Fprintln(w, "--\t----\t-------\t---------\t------------")

	for _, pack := range packs {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			pack.ID,
			pack.Type,
			pack.Version,
			pack.CachedAt.Format("2006-01-02 15:04"),
			pack.LastUpdated.Format("2006-01-02 15:04"),
		)
	}

	w.Flush()
}

func outputPacksWithSourceTable(packs []PackWithSource) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "ID\tTITLE\tVERSION\tSOURCE\tLOCAL")
	fmt.Fprintln(w, "--\t-----\t-------\t------\t-----")

	for _, pack := range packs {
		localStatus := "No"
		if pack.Local {
			localStatus = "Yes"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			pack.ID,
			pack.Title,
			pack.Version,
			pack.Source,
			localStatus,
		)
	}

	w.Flush()
}

func outputPacksJSON(packs []cache.CacheEntry) error {
	data, err := json.MarshalIndent(packs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal packs to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func outputPacksWithSourceJSON(packs []PackWithSource) error {
	data, err := json.MarshalIndent(packs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal packs to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func outputPackSearchTable(packs []hub.RulePackInfo, totalCount, limit, offset int) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "ID\tTITLE\tVERSION\tDESCRIPTION\n")
	for _, pack := range packs {
		description := pack.Description
		if len(description) > 50 {
			description = description[:47] + "..."
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			pack.ID,
			pack.Title,
			pack.Version,
			description,
		)
	}

	w.Flush()

	// Show search summary
	fmt.Printf("\nShowing %d of %d total results", len(packs), totalCount)
	if offset > 0 {
		fmt.Printf(" (offset: %d)", offset)
	}
	if limit > 0 && len(packs) == limit {
		fmt.Printf(" (use --offset to see more)")
	}
	fmt.Println()
}

func outputPackSearchJSON(packs []hub.RulePackInfo, totalCount, limit, offset int) error {
	response := struct {
		Packs      []hub.RulePackInfo `json:"packs"`
		TotalCount int                `json:"total_count"`
		Limit      int                `json:"limit"`
		Offset     int                `json:"offset"`
	}{
		Packs:      packs,
		TotalCount: totalCount,
		Limit:      limit,
		Offset:     offset,
	}

	data, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal search results to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func outputPackInfoTable(pack *hub.RulePackInfo) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	fmt.Fprintf(w, "ID:\t%s\n", pack.ID)
	fmt.Fprintf(w, "Title:\t%s\n", pack.Title)
	fmt.Fprintf(w, "Description:\t%s\n", pack.Description)
	fmt.Fprintf(w, "Version:\t%s\n", pack.Version)
	fmt.Fprintf(w, "Author:\t%s\n", pack.Author)
	fmt.Fprintf(w, "Rules Count:\t%d\n", len(pack.Rules))

	if len(pack.Rules) > 0 {
		fmt.Fprintf(w, "Rules:\t%s\n", strings.Join(pack.Rules, ", "))
	}

	w.Flush()
	return nil
}

func outputPackInfoJSON(pack *hub.RulePackInfo) error {
	data, err := json.MarshalIndent(pack, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal pack to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

// pullPackRules downloads all rules referenced by a rule pack
func pullPackRules(hubClient *hub.Client, cacheManager *cache.CacheManager, pack *hub.RulePackInfo, verbose bool, force bool) error {
	if len(pack.Rules) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	if verbose {
		fmt.Printf("Downloading %d rules for pack '%s'...\n", len(pack.Rules), pack.ID)
	}

	for i, ruleID := range pack.Rules {
		// Check if rule is already stored locally and not forcing re-download
		if !force && cacheManager.IsRuleCached(ruleID) {
			if verbose {
				fmt.Printf("Rule %d/%d: %s (local)\n", i+1, len(pack.Rules), ruleID)
			}
			continue
		}

		if verbose {
			if force && cacheManager.IsRuleCached(ruleID) {
				fmt.Printf("Rule %d/%d: %s (re-downloading)\n", i+1, len(pack.Rules), ruleID)
			} else {
				fmt.Printf("Rule %d/%d: %s (downloading)\n", i+1, len(pack.Rules), ruleID)
			}
		}

		// Download rule from hub
		rule, err := hubClient.GetRule(ctx, ruleID)
		if err != nil {
			return fmt.Errorf("failed to download rule '%s': %w", ruleID, err)
		}

		// Save rule locally
		if err := cacheManager.SaveRule(rule); err != nil {
			return fmt.Errorf("failed to store rule '%s' locally: %w", ruleID, err)
		}
	}

	if verbose {
		fmt.Printf("Successfully downloaded all rules for pack '%s'\n", pack.ID)
	}

	return nil
}
