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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/madhuakula/spotter/pkg/cache"
	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/progress"
	"github.com/madhuakula/spotter/pkg/runner"
	"github.com/madhuakula/spotter/pkg/vap"
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

// packsExportVAPCmd represents the packs export-vap command
var packsExportVAPCmd = &cobra.Command{
	Use:   "export-vap <pack-id>",
	Short: "Export rule pack to ValidatingAdmissionPolicy format",
	Long: `Export a Spotter rule pack to Kubernetes ValidatingAdmissionPolicy (VAP) format.

This command converts all rules in a Spotter rule pack into ValidatingAdmissionPolicy and
ValidatingAdmissionPolicyBinding resources that can be applied directly to Kubernetes clusters
for native policy enforcement.

Examples:
  # Export a specific rule pack to VAP
  spotter packs export-vap cis-kubernetes-benchmark
  
  # Export with custom namespace and name prefix
  spotter packs export-vap cis-kubernetes-benchmark --namespace=security --name-prefix=cis
  
  # Group rules by category into separate policies
  spotter packs export-vap cis-kubernetes-benchmark --group-by-category
  
  # Group rules by severity level
  spotter packs export-vap cis-kubernetes-benchmark --group-by-severity
  
  # Save to file
  spotter packs export-vap cis-kubernetes-benchmark --output=policies.yaml
  
  # Include apply instructions
  spotter packs export-vap cis-kubernetes-benchmark --include-instructions`,
	Args: cobra.ExactArgs(1),
	RunE: runPacksExportVAP,
}

// runPacksValidation validates rule pack files specifically
func runPacksValidation(path string, runTests bool, outputFormat string, verbose bool) error {
	// Import validation functionality from runner package
	return runner.RunValidation(path, runTests, outputFormat, verbose)
}

// runPacksExportVAP exports a rule pack to ValidatingAdmissionPolicy format
func runPacksExportVAP(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	packID := args[0]

	logger.Debug("Exporting rule pack to ValidatingAdmissionPolicy format", "pack-id", packID)

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		cfg = config.DefaultConfig()
	}

	// Create cache manager
	cacheManager := cache.NewCacheManager(cfg)

	// Get pack from local cache
	pack, err := cacheManager.GetRulePack(packID)
	if err != nil {
		return fmt.Errorf("rule pack '%s' not found locally. Use 'spotter packs pull %s' to download it from the hub", packID, packID)
	}

	// Load all rules for the pack
	var packRules []*models.SpotterRule
	for _, ruleID := range pack.Rules {
		rule, err := loadRuleByID(ruleID)
		if err != nil {
			logger.Warn("Failed to load rule from pack", "rule-id", ruleID, "error", err)
			continue
		}
		packRules = append(packRules, rule)
	}

	if len(packRules) == 0 {
		return fmt.Errorf("no valid rules found in pack %s", packID)
	}

	// Get command flags
	namespace, _ := cmd.Flags().GetString("namespace")
	namePrefix, _ := cmd.Flags().GetString("name-prefix")
	validationActions, _ := cmd.Flags().GetStringSlice("validation-actions")
	failurePolicy, _ := cmd.Flags().GetString("failure-policy")
	groupByCategory, _ := cmd.Flags().GetBool("group-by-category")
	groupBySeverity, _ := cmd.Flags().GetBool("group-by-severity")
	outputFile, _ := cmd.Flags().GetString("output")
	includeInstructions, _ := cmd.Flags().GetBool("include-instructions")
	includeComments, _ := cmd.Flags().GetBool("include-comments")
	matchNamespaces, _ := cmd.Flags().GetStringSlice("match-namespaces")
	excludeNamespaces, _ := cmd.Flags().GetStringSlice("exclude-namespaces")

	// Convert validation actions to proper format
	var vapValidationActions []admissionregistrationv1.ValidationAction
	for _, action := range validationActions {
		switch strings.ToLower(action) {
		case "warn":
			vapValidationActions = append(vapValidationActions, admissionregistrationv1.Warn)
		case "audit":
			vapValidationActions = append(vapValidationActions, admissionregistrationv1.Audit)
		case "deny":
			vapValidationActions = append(vapValidationActions, admissionregistrationv1.Deny)
		default:
			return fmt.Errorf("invalid validation action: %s (valid: warn, audit, deny)", action)
		}
	}

	// Convert failure policy
	var vapFailurePolicy *admissionregistrationv1.FailurePolicyType
	switch strings.ToLower(failurePolicy) {
	case "fail":
		fail := admissionregistrationv1.Fail
		vapFailurePolicy = &fail
	case "ignore":
		ignore := admissionregistrationv1.Ignore
		vapFailurePolicy = &ignore
	default:
		return fmt.Errorf("invalid failure policy: %s (valid: fail, ignore)", failurePolicy)
	}

	// Prepare base export options
	baseOptions := &vap.ExportOptions{
		Namespace:         namespace,
		ValidationActions: vapValidationActions,
		FailurePolicy:     vapFailurePolicy,
	}

	// Set namespace selector if match-namespaces is specified
	if len(matchNamespaces) > 0 {
		baseOptions.NamespaceSelector = &metav1.LabelSelector{
			MatchExpressions: []metav1.LabelSelectorRequirement{
				{
					Key:      "kubernetes.io/metadata.name",
					Operator: metav1.LabelSelectorOpIn,
					Values:   matchNamespaces,
				},
			},
		}
	}

	// Set namespace exclusion if exclude-namespaces is specified
	if len(excludeNamespaces) > 0 {
		if baseOptions.NamespaceSelector == nil {
			baseOptions.NamespaceSelector = &metav1.LabelSelector{}
		}
		baseOptions.NamespaceSelector.MatchExpressions = append(
			baseOptions.NamespaceSelector.MatchExpressions,
			metav1.LabelSelectorRequirement{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpNotIn,
				Values:   excludeNamespaces,
			},
		)
	}

	// Prepare pack export options
	packOptions := &vap.PackExportOptions{
		BaseOptions:     baseOptions,
		GroupByCategory: groupByCategory,
		GroupBySeverity: groupBySeverity,
		NamePrefix:      namePrefix,
	}

	// Convert hub.RulePackInfo to models.SpotterRulePack
	spotterPack := &models.SpotterRulePack{
		APIVersion: "rules.spotter.dev/v1alpha1",
		Kind:       "SpotterRulePack",
		Metadata: models.RuleMetadata{
			Name: pack.ID,
			Annotations: map[string]string{
				"rules.spotter.dev/title":       pack.Title,
				"rules.spotter.dev/description": pack.Description,
				"rules.spotter.dev/version":     pack.Version,
				"rules.spotter.dev/author":      pack.Author,
			},
		},
		Spec: models.RulePackSpec{
			Rules: pack.Rules,
		},
	}

	// Export the pack
	result, err := vap.ExportRulePackToVAP(spotterPack, packRules, packOptions)
	if err != nil {
		return fmt.Errorf("failed to export pack to VAP: %w", err)
	}

	// Report any errors encountered during export
	if len(result.Errors) > 0 {
		for _, exportErr := range result.Errors {
			logger.Warn("Export error", "error", exportErr)
		}
	}

	if len(result.Policies) == 0 {
		return fmt.Errorf("no policies were generated from pack %s", packID)
	}

	// Prepare format options
	formatOptions := &vap.FormatOptions{
		Format:          vap.OutputFormatYAML,
		IncludeComments: includeComments,
		SeparateFiles:   false,
		IndentSize:      2,
	}

	// Format the output
	outputBytes, err := vap.FormatVAPResources(result.Policies, result.Bindings, formatOptions)
	if err != nil {
		return fmt.Errorf("failed to format VAP resources: %w", err)
	}

	output := string(outputBytes)

	// Add apply instructions if requested
	if includeInstructions {
		instructions := vap.GenerateApplyInstructions(result.Policies, result.Bindings)
		output = instructions + "\n" + output
	}

	// Write output
	if outputFile != "" {
		err = os.WriteFile(outputFile, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("ValidatingAdmissionPolicy resources exported to %s\n", outputFile)
	} else {
		fmt.Print(output)
	}

	return nil
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
	packsCmd.AddCommand(packsExportVAPCmd)

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

	// Flags for export-vap command
	packsExportVAPCmd.Flags().String("namespace", "default", "target namespace for the ValidatingAdmissionPolicyBinding")
	packsExportVAPCmd.Flags().String("name-prefix", "", "prefix for generated policy and binding names")
	packsExportVAPCmd.Flags().StringSlice("validation-actions", []string{"warn"}, "validation actions (warn, audit, deny)")
	packsExportVAPCmd.Flags().String("failure-policy", "fail", "failure policy (fail, ignore)")
	packsExportVAPCmd.Flags().Bool("group-by-category", false, "group rules by category into separate policies")
	packsExportVAPCmd.Flags().Bool("group-by-severity", false, "group rules by severity into separate policies")
	packsExportVAPCmd.Flags().String("output", "", "output file path (default: stdout)")
	packsExportVAPCmd.Flags().Bool("include-instructions", false, "include kubectl apply instructions in output")
	packsExportVAPCmd.Flags().Bool("include-comments", true, "include explanatory comments in YAML output")
	packsExportVAPCmd.Flags().StringSlice("match-namespaces", []string{}, "namespaces to match (empty for all)")
	packsExportVAPCmd.Flags().StringSlice("exclude-namespaces", []string{}, "namespaces to exclude")
	packsExportVAPCmd.Flags().StringSlice("match-kinds", []string{}, "resource kinds to match (empty for all)")
}

func runPacksSearch(cmd *cobra.Command, args []string) error {
	// Load configuration
	cfg, err := config.LoadConfig("")
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
	cfg, err := config.LoadConfig("")
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
	cfg, err := config.LoadConfig("")
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
	cfg, err := config.LoadConfig("")
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
	_, _ = fmt.Fprintln(w, "ID\tTYPE\tVERSION\tCACHED AT\tLAST UPDATED")
	_, _ = fmt.Fprintln(w, "--\t----\t-------\t---------\t------------")

	for _, pack := range packs {
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			pack.ID,
			pack.Type,
			pack.Version,
			pack.CachedAt.Format("2006-01-02 15:04"),
			pack.LastUpdated.Format("2006-01-02 15:04"),
		)
	}

	_ = w.Flush()
}

func outputPacksJSON(packs []cache.CacheEntry) error {
	data, err := json.MarshalIndent(packs, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal packs to JSON: %w", err)
	}

	fmt.Println(string(data))
	return nil
}

func outputPackSearchTable(packs []hub.RulePackInfo, totalCount, limit, offset int) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	_, _ = fmt.Fprintf(w, "ID\tTITLE\tVERSION\tDESCRIPTION\n")
	for _, pack := range packs {
		description := pack.Description
		if len(description) > 50 {
			description = description[:47] + "..."
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			pack.ID,
			pack.Title,
			pack.Version,
			description,
		)
	}

	_ = w.Flush()

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

	_, _ = fmt.Fprintf(w, "ID:\t%s\n", pack.ID)
	_, _ = fmt.Fprintf(w, "Title:\t%s\n", pack.Title)
	_, _ = fmt.Fprintf(w, "Description:\t%s\n", pack.Description)
	_, _ = fmt.Fprintf(w, "Version:\t%s\n", pack.Version)
	_, _ = fmt.Fprintf(w, "Author:\t%s\n", pack.Author)
	_, _ = fmt.Fprintf(w, "Rules Count:\t%d\n", len(pack.Rules))

	if len(pack.Rules) > 0 {
		_, _ = fmt.Fprintf(w, "Rules:\t%s\n", strings.Join(pack.Rules, ", "))
	}

	_ = w.Flush()
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
