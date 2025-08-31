package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"

	"github.com/madhuakula/spotter/pkg/cache"
	"github.com/madhuakula/spotter/pkg/config"
	"github.com/madhuakula/spotter/pkg/hub"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/progress"
	"github.com/madhuakula/spotter/pkg/runner"
	"github.com/madhuakula/spotter/pkg/vap"
)

// RuleWithSource wraps a SpotterRule with its source information
type RuleWithSource struct {
	*models.SpotterRule
	Source string // "local" or "remote"
}

// rulesCmd represents the rules command
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage security rules",
	Long: `Manage security rules for Spotter scanner.

This command provides various operations for working with security rules:
- List local rules (pulled from hub)
- Show detailed information about specific rules
- Search for rules in the remote hub
- Pull rules from the hub
- Generate new rule templates
- Export rules in different formats

Examples:
  # List all local rules
  spotter rules list
  
  # Search for rules in the hub
  spotter rules search kubernetes
  
  # Pull a rule from the hub
  spotter rules pull privileged-containers
  
  # Show detailed information about a rule
  spotter rules info privileged-containers
  
  # Generate a new rule template
  spotter rules generate --name=my-rule
  
  # Export rules to JSON
  spotter rules export --format=json --output=rules.json`,
}

// listCmd represents the list subcommand
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List local security rules",
	Long: `List locally stored security rules that have been pulled from the hub.

This command displays rules in a table format showing rule ID, name, severity,
category, and description. Only rules that have been pulled from the hub are shown.
To discover available rules from the hub, use 'spotter rules search'.

Examples:
  # List all local rules
  spotter rules list
  
  # List rules by severity
  spotter rules list --severity=high,critical
  
  # List rules by category
  spotter rules list --category=security,compliance
  
  # Output as JSON
  spotter rules list --output=json`,
	RunE: runListRules,
}

// infoCmd represents the info subcommand
var infoCmd = &cobra.Command{
	Use:   "info <rule-id>",
	Short: "Show detailed information about a rule",
	Long: `Show detailed information about a specific security rule.

This command displays comprehensive information about a rule including:
- Rule metadata and description
- Severity and category
- CEL expression
- Match criteria
- Remediation instructions
- References and compliance mappings

Examples:
  # Show rule information
  spotter rules info privileged-containers
  
  # Show rule info with CEL expression
  spotter rules info privileged-containers --show-cel
  
  # Output as JSON
  spotter rules info privileged-containers --output=json`,
	Args: cobra.ExactArgs(1),
	RunE: runRuleInfo,
}

// generateCmd represents the generate subcommand
var generateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate a new security rule template",
	Long: `Generate a new security rule template with proper structure and examples.

This command creates a new rule file with the correct YAML structure,
including all required fields, proper metadata, and example CEL expressions.
The generated rule follows Spotter's rule creation guidelines.

Examples:
  # Generate a basic rule template
  spotter rules generate
  
  # Generate rule with specific name and category
  spotter rules generate --name="my-security-rule" --category="Workload Security"
  
  # Generate rule and save to file
  spotter rules generate --output=my-rule.yaml`,
	RunE: runGenerateRule,
}

// exportCmd represents the export subcommand
var exportCmd = &cobra.Command{
	Use:   "export",
	Short: "Export rules in different formats",
	Long: `Export local security rules in various formats for integration with other tools.

Supported export formats:
- JSON: Machine-readable format
- YAML: Human-readable format
- SARIF: Static Analysis Results Interchange Format
- CSV: Comma-separated values for spreadsheets

Examples:
  # Export all local rules to JSON
  spotter rules export --format=json --output=rules.json
  
  # Export rules by category
  spotter rules export --category=security --format=sarif
  
  # Export rules by severity
  spotter rules export --severity=high --format=yaml`,
	RunE: runExportRules,
}

// pullCmd represents the pull subcommand
var pullCmd = &cobra.Command{
	Use:   "pull <rule-id>",
	Short: "Pull a rule from the hub",
	Long: `Pull a security rule from the Spotter hub and store it locally.

This command downloads a rule from the remote hub and stores it in the
local storage for offline use. The rule will be available for use with other
Spotter commands.

Examples:
  # Pull a specific rule
  spotter rules pull privileged-containers
  
  # Pull with verbose output
  spotter rules pull host-network --verbose
  
  # Force re-download even if stored locally
  spotter rules pull privileged-containers --force`,
	Args: cobra.ExactArgs(1),
	RunE: runRulesPull,
}

// rulesSearchCmd represents the rules search command
var rulesSearchCmd = &cobra.Command{
	Use:   "search <query>",
	Short: "Search for rules in the Spotter hub",
	Long: `Search for security rules in the Spotter hub repository.
You can search by rule name, category, severity, or keywords.

This command queries the remote hub to find available rules that match
your search criteria. Use 'spotter rules pull <rule-id>' to download
rules locally after finding them.

Examples:
  # Search for rules containing 'privileged'
  spotter rules search privileged
  
  # Search by category
  spotter rules search containers --category="Workload Security"
  
  # Search by severity
  spotter rules search network --severity=high
  
  # Output results in JSON format
  spotter rules search kubernetes --output=json`,
	Args: cobra.ExactArgs(1),
	RunE: runRulesSearch,
}

// rulesValidateCmd represents the rules validate command
var rulesValidateCmd = &cobra.Command{
	Use:   "validate [file|directory]",
	Short: "Validate rule files schema and run tests",
	Long: `Validate SpotterRule YAML files for correct schema,
and optionally run CEL expression tests against test cases.

Examples:
  # Validate a single rule file
  spotter rules validate rule.yaml
  
  # Validate all rules in a directory
  spotter rules validate ./rules/
  
  # Validate and run tests
  spotter rules validate rule.yaml --test
  
  # Output results in JSON format
  spotter rules validate rule.yaml --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		runTests, _ := cmd.Flags().GetBool("test")
		outputFormat, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

		return runRulesValidation(path, runTests, outputFormat, verbose)
	},
}

// exportVAPCmd represents the export-vap subcommand
var exportVAPCmd = &cobra.Command{
	Use:   "export-vap [rule-id...]",
	Short: "Export rules to ValidatingAdmissionPolicy format",
	Long: `Export Spotter security rules to Kubernetes ValidatingAdmissionPolicy (VAP) format.

This command converts Spotter rules into ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
resources that can be applied directly to Kubernetes clusters for native policy enforcement.

Examples:
  # Export a specific rule to VAP
  spotter rules export-vap privileged-containers
  
  # Export multiple rules
  spotter rules export-vap privileged-containers host-network
  
  # Export all local rules
  spotter rules export-vap
  
  # Export with custom namespace and policy name
  spotter rules export-vap privileged-containers --namespace=security --policy-name=custom-policy
  
  # Save to file
  spotter rules export-vap privileged-containers --output=policy.yaml
  
  # Include apply instructions
  spotter rules export-vap privileged-containers --include-instructions`,
	RunE: runExportVAP,
}

// runRulesValidation validates rule files specifically
func runRulesValidation(path string, runTests bool, outputFormat string, verbose bool) error {
	// Import validation functionality from runner package
	return runner.RunValidation(path, runTests, outputFormat, verbose)
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(listCmd)
	rulesCmd.AddCommand(infoCmd)
	rulesCmd.AddCommand(generateCmd)
	rulesCmd.AddCommand(exportCmd)
	rulesCmd.AddCommand(exportVAPCmd)
	rulesCmd.AddCommand(pullCmd)
	rulesCmd.AddCommand(rulesSearchCmd)
	rulesCmd.AddCommand(rulesValidateCmd)

	// List command flags
	listCmd.Flags().StringSlice("severity", []string{}, "filter by severity levels (low, medium, high, critical)")
	listCmd.Flags().StringSlice("category", []string{}, "filter by rule categories")
	listCmd.Flags().String("search", "", "search rules by name or description")
	listCmd.Flags().Bool("show-description", false, "show rule descriptions in output")
	// Note: 'output' flag is inherited from global persistent flags

	// Info command flags
	infoCmd.Flags().Bool("show-cel", false, "show CEL expression in output")
	// Note: 'output' flag is inherited from global persistent flags

	// Generate command flags
	generateCmd.Flags().String("name", "", "rule name (will be converted to DNS-1123 format)")
	generateCmd.Flags().String("category", "Workload Security", "rule category")
	generateCmd.Flags().String("severity", "MEDIUM", "rule severity (LOW, MEDIUM, HIGH, CRITICAL)")
	generateCmd.Flags().String("output", "", "output file path (default: stdout)")
	generateCmd.Flags().Bool("interactive", false, "interactive mode for rule generation")

	// Export command flags
	exportCmd.Flags().String("format", "json", "export format (json, yaml, sarif, csv)")
	// Note: 'output' flag is inherited from global persistent flags (as 'output-file')
	exportCmd.Flags().StringSlice("category", []string{}, "export rules by category")
	exportCmd.Flags().StringSlice("severity", []string{}, "export rules by severity")
	exportCmd.Flags().Bool("include-metadata", true, "include rule metadata in export")

	// Pull command flags
	pullCmd.Flags().BoolP("force", "f", false, "Force re-download even if rule is stored locally")
	pullCmd.Flags().BoolP("verbose", "v", false, "Enable verbose output")

	// Search command flags
	rulesSearchCmd.Flags().StringSlice("category", []string{}, "filter by rule categories")
	rulesSearchCmd.Flags().StringSlice("severity", []string{}, "filter by severity levels (low, medium, high, critical)")
	rulesSearchCmd.Flags().Int("limit", 20, "maximum number of results to return")
	rulesSearchCmd.Flags().Bool("show-description", false, "show rule descriptions in output")

	// Validate command flags
	rulesValidateCmd.Flags().BoolP("test", "t", false, "Run CEL expression tests if test files are found")
	rulesValidateCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")

	// Export VAP command flags
	exportVAPCmd.Flags().String("namespace", "default", "target namespace for the ValidatingAdmissionPolicyBinding")
	exportVAPCmd.Flags().String("policy-name", "", "custom name for the ValidatingAdmissionPolicy (auto-generated if not provided)")
	exportVAPCmd.Flags().String("binding-name", "", "custom name for the ValidatingAdmissionPolicyBinding (auto-generated if not provided)")
	exportVAPCmd.Flags().StringSlice("validation-actions", []string{"warn"}, "validation actions for the policy binding (warn, audit, deny)")
	exportVAPCmd.Flags().String("failure-policy", "Fail", "failure policy for the ValidatingAdmissionPolicy (Fail, Ignore)")
	exportVAPCmd.Flags().Bool("include-instructions", false, "include apply instructions in the output")
	exportVAPCmd.Flags().Bool("include-comments", true, "include helpful comments in YAML output")
	exportVAPCmd.Flags().String("output", "", "output file path (default: stdout)")
	exportVAPCmd.Flags().StringSlice("match-kinds", []string{}, "override match kinds (e.g., Pod, Deployment)")
	exportVAPCmd.Flags().StringSlice("match-namespaces", []string{}, "limit policy to specific namespaces")
	exportVAPCmd.Flags().StringSlice("exclude-namespaces", []string{}, "exclude specific namespaces from policy")

}

func runListRules(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	logger.Debug("Loading security rules for listing")

	// Load rules based on flags
	rules, err := loadRulesForCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Apply filters
	filteredRules := filterRules(rules, cmd)

	// Convert to SpotterRule slice for export
	// Sort rules by ID
	sort.Slice(filteredRules, func(i, j int) bool {
		return filteredRules[i].GetID() < filteredRules[j].GetID()
	})

	// Output rules
	outputFormat := viper.GetString("output")
	switch outputFormat {
	case "json":
		return outputRulesJSON(filteredRules)
	case "yaml":
		return outputRulesYAML(filteredRules)
	default:
		showDescription, _ := cmd.Flags().GetBool("show-description")
		outputRulesTable(filteredRules, showDescription, false)
		return nil
	}
}

func runRuleInfo(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ruleID := args[0]

	logger.Debug("Looking up rule information", "rule_id", ruleID)

	// Load all rules (local only)
	rules, err := loadRulesForCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Find the specific rule
	var targetRule *models.SpotterRule
	for _, rule := range rules {
		if rule.GetID() == ruleID {
			targetRule = rule.SpotterRule
			break
		}
	}

	// If rule not found locally, return error
	if targetRule == nil {
		return fmt.Errorf("rule '%s' not found locally. Use 'spotter rules pull %s' to download it from the hub", ruleID, ruleID)
	}

	// Output rule information
	outputFormat := viper.GetString("output")
	switch outputFormat {
	case "json":
		return outputRuleInfoJSON(targetRule)
	case "yaml":
		return outputRuleInfoYAML(targetRule)
	default:
		return outputRuleInfoTable(targetRule, cmd)
	}
}

func runGenerateRule(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	logger.Debug("Generating new security rule template")

	// Get flags
	ruleName, _ := cmd.Flags().GetString("name")
	category, _ := cmd.Flags().GetString("category")
	severity, _ := cmd.Flags().GetString("severity")
	outputFile, _ := cmd.Flags().GetString("output")
	interactive, _ := cmd.Flags().GetBool("interactive")

	// Generate rule template
	ruleTemplate, err := generateRuleTemplate(ruleName, category, severity, interactive)
	if err != nil {
		return fmt.Errorf("failed to generate rule template: %w", err)
	}

	// Write to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, []byte(ruleTemplate), 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		logger.Info("Rule template generated", "output_file", outputFile)
	} else {
		fmt.Print(ruleTemplate)
	}

	return nil
}

func runExportRules(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	logger.Debug("Exporting security rules")

	// Load rules based on flags
	rules, err := loadRulesForCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Apply filters
	filteredRules := filterRules(rules, cmd)

	// Convert to SpotterRule slice for export
	var spotterRules []*models.SpotterRule
	for _, rule := range filteredRules {
		spotterRules = append(spotterRules, rule.SpotterRule)
	}

	// Sort rules by ID
	sort.Slice(spotterRules, func(i, j int) bool {
		return spotterRules[i].GetID() < spotterRules[j].GetID()
	})

	// Get export format and output file
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output-file")

	// Export rules
	var data []byte
	switch format {
	case "json":
		data, err = json.MarshalIndent(spotterRules, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(spotterRules)
	case "sarif":
		data, err = exportToSARIF(spotterRules)
	case "csv":
		data, err = exportToCSV(spotterRules)
	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}

	if err != nil {
		return fmt.Errorf("failed to export rules: %w", err)
	}

	// Write to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		logger.Info("Rules exported", "output_file", outputFile)
	} else {
		fmt.Print(string(data))
	}

	return nil
}

func runExportVAP(cmd *cobra.Command, args []string) error {
	logger := GetLogger()

	logger.Debug("Exporting rules to ValidatingAdmissionPolicy format")

	// Load rules based on arguments or all local rules
	var targetRules []*models.SpotterRule
	if len(args) > 0 {
		// Load specific rules by ID
		for _, ruleID := range args {
			rule, err := loadRuleByID(ruleID)
			if err != nil {
				return fmt.Errorf("failed to load rule %s: %w", ruleID, err)
			}
			targetRules = append(targetRules, rule)
		}
	} else {
		// Load all local rules
		rules, err := loadRulesForCommand(cmd)
		if err != nil {
			return fmt.Errorf("failed to load rules: %w", err)
		}
		for _, rule := range rules {
			targetRules = append(targetRules, rule.SpotterRule)
		}
	}

	if len(targetRules) == 0 {
		return fmt.Errorf("no rules found to export")
	}

	// Get command flags
	namespace, _ := cmd.Flags().GetString("namespace")
	validationActions, _ := cmd.Flags().GetStringSlice("validation-actions")
	failurePolicy, _ := cmd.Flags().GetString("failure-policy")
	includeInstructions, _ := cmd.Flags().GetBool("include-instructions")
	includeComments, _ := cmd.Flags().GetBool("include-comments")
	outputFile, _ := cmd.Flags().GetString("output")

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
			return fmt.Errorf("invalid validation action: %s (must be warn, audit, or deny)", action)
		}
	}

	// Convert failure policy
	var vapFailurePolicy *admissionregistrationv1.FailurePolicyType
	switch strings.ToLower(failurePolicy) {
	case "fail":
		fp := admissionregistrationv1.Fail
		vapFailurePolicy = &fp
	case "ignore":
		fp := admissionregistrationv1.Ignore
		vapFailurePolicy = &fp
	default:
		return fmt.Errorf("invalid failure policy: %s (must be Fail or Ignore)", failurePolicy)
	}

	// Prepare export options
	exportOptions := &vap.ExportOptions{
		Namespace:         namespace,
		ValidationActions: vapValidationActions,
		FailurePolicy:     vapFailurePolicy,
	}

	// Export rules to VAP
	var allPolicies []admissionregistrationv1.ValidatingAdmissionPolicy
	var allBindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding

	for _, rule := range targetRules {
		policy, binding, err := vap.ExportRuleToVAP(rule, exportOptions)
		if err != nil {
			return fmt.Errorf("failed to export rule %s to VAP: %w", rule.GetID(), err)
		}
		allPolicies = append(allPolicies, *policy)
		allBindings = append(allBindings, *binding)
	}

	// Format output
	formatOptions := &vap.FormatOptions{
		Format:          vap.OutputFormatYAML,
		IncludeComments: includeComments,
		SeparateFiles:   false,
		IndentSize:      2,
	}

	data, err := vap.FormatVAPResources(allPolicies, allBindings, formatOptions)
	if err != nil {
		return fmt.Errorf("failed to format VAP resources: %w", err)
	}

	// Add instructions if requested
	if includeInstructions {
		instructions := vap.GenerateApplyInstructions(allPolicies, allBindings)
		data = append([]byte(instructions), append([]byte("\n\n"), data...)...)
	}

	// Write to file or stdout
	if outputFile != "" {
		if err := os.WriteFile(outputFile, data, 0644); err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		logger.Info("VAP resources exported", "output_file", outputFile, "policies", len(allPolicies), "bindings", len(allBindings))
	} else {
		fmt.Print(string(data))
	}

	return nil
}

func runRulesPull(cmd *cobra.Command, args []string) error {
	ruleID := args[0]

	// Get flags
	force, _ := cmd.Flags().GetBool("force")
	verbose, _ := cmd.Flags().GetBool("verbose")

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		cfg, err = config.DefaultConfig()
		if err != nil {
			return fmt.Errorf("failed to load default config: %w", err)
		}
	}

	// Initialize cache manager
	cacheManager := cache.NewCacheManager(cfg)

	// Check if rule is already stored locally
	if !force && cacheManager.IsRuleCached(ruleID) {
		if verbose {
			fmt.Printf("Rule '%s' is already stored locally\n", ruleID)
		}
		fmt.Printf("Rule '%s' is already stored locally. Use --force to re-download.\n", ruleID)
		return nil
	}

	// Initialize hub client
	hubClient := hub.NewClientWithConfig(cfg)

	// Initialize progress bar
	progressBar := progress.NewProgressBar(3, fmt.Sprintf("Pulling rule '%s'", ruleID))

	// Pull rule from hub
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if verbose {
		fmt.Printf("\nPulling rule '%s' from hub...\n", ruleID)
	}

	progressBar.Increment() // Step 1: Downloading
	rule, err := hubClient.GetRule(ctx, ruleID)
	if err != nil {
		progressBar.Finish()
		return fmt.Errorf("failed to pull rule from hub: %w", err)
	}

	progressBar.Increment() // Step 2: Validating
	// Rule validation happens in the hub client

	// Save rule locally
	progressBar.Increment() // Step 3: Storing
	if err := cacheManager.SaveRule(rule); err != nil {
		progressBar.Finish()
		return fmt.Errorf("failed to store rule locally: %w", err)
	}

	progressBar.Finish()

	if verbose {
		fmt.Printf("Rule '%s' (version %s) pulled and stored locally successfully\n", rule.GetID(), rule.GetVersion())
		fmt.Printf("Title: %s\n", rule.GetTitle())
		fmt.Printf("Description: %s\n", rule.GetDescription())
	} else {
		fmt.Printf("Successfully pulled and stored rule '%s'\n", ruleID)
	}

	return nil
}

func runRulesSearch(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	query := args[0]

	logger.Debug("Searching for rules in hub", "query", query)

	// Get flags
	categories, _ := cmd.Flags().GetStringSlice("category")
	severities, _ := cmd.Flags().GetStringSlice("severity")
	limit, _ := cmd.Flags().GetInt("limit")
	showDescription, _ := cmd.Flags().GetBool("show-description")

	// Load configuration
	cfg, err := config.LoadConfig("")
	if err != nil {
		cfg, err = config.DefaultConfig()
		if err != nil {
			return fmt.Errorf("failed to load default config: %w", err)
		}
	}

	// Initialize hub client
	hubClient := hub.NewClientWithConfig(cfg)

	// Create search request
	searchReq := hub.SearchRequest{
		Query: query,
		Limit: limit,
	}

	// Set category filter (use first category if multiple provided)
	if len(categories) > 0 {
		searchReq.Category = categories[0]
	}

	// Set severity filter (use first severity if multiple provided)
	if len(severities) > 0 {
		searchReq.Severity = severities[0]
	}

	// Search for rules
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	results, err := hubClient.SearchRules(ctx, searchReq)
	if err != nil {
		return fmt.Errorf("failed to search rules: %w", err)
	}

	// Output results
	outputFormat := viper.GetString("output")
	switch outputFormat {
	case "json":
		return outputSearchResultsJSON(results.Rules)
	case "yaml":
		return outputSearchResultsYAML(results.Rules)
	default:
		outputSearchResultsTable(results.Rules, showDescription)
		return nil
	}
}

func outputSearchResultsTable(results []hub.RuleInfo, showDescription bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Build header
	header := "ID\tNAME\tSEVERITY\tCATEGORY\tVERSION"
	if showDescription {
		header += "\tDESCRIPTION"
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		logger := GetLogger()
		logger.Error("Failed to write header", "error", err)
	}

	// Build rows
	for _, result := range results {
		// Use Title field for the name display since that's where the actual rule names are stored
		ruleName := result.Title
		if ruleName == "" {
			// Fallback to Name field if Title is empty
			ruleName = result.Name
		}

		row := fmt.Sprintf("%s\t%s\t%s\t%s\t%s",
			result.ID,
			ruleName,
			result.Severity,
			result.Category,
			result.Version)

		if showDescription {
			desc := result.Description
			if len(desc) > 50 {
				desc = desc[:47] + "..."
			}
			row += "\t" + desc
		}

		if _, err := fmt.Fprintln(w, row); err != nil {
			logger := GetLogger()
			logger.Error("Failed to write row", "error", err)
		}
	}

	if err := w.Flush(); err != nil {
		logger := GetLogger()
		logger.Error("Failed to flush writer", "error", err)
	}

	fmt.Printf("\nFound %d rules. Use 'spotter rules pull <rule-id>' to download a rule.\n", len(results))
}

func outputSearchResultsJSON(results []hub.RuleInfo) error {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputSearchResultsYAML(results []hub.RuleInfo) error {
	data, err := yaml.Marshal(results)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

// Helper functions

// loadRuleByID loads a specific rule by its ID from local cache
func loadRuleByID(ruleID string) (*models.SpotterRule, error) {
	cfg, err := config.LoadConfig("")
	if err != nil {
		return nil, fmt.Errorf("failed to load config: %w", err)
	}

	cacheManager := cache.NewCacheManager(cfg)
	rule, err := cacheManager.GetRule(ruleID)
	if err != nil {
		return nil, fmt.Errorf("rule %s not found locally. Use 'spotter rules pull %s' to download it from the hub: %w", ruleID, ruleID, err)
	}

	if rule == nil {
		return nil, fmt.Errorf("rule %s not found locally. Use 'spotter rules pull %s' to download it from the hub", ruleID, ruleID)
	}

	return rule, nil
}

func loadRulesForCommand(cmd *cobra.Command) ([]*RuleWithSource, error) {
	parser := parser.NewYAMLParser(true)
	var allRules []*RuleWithSource
	ruleIDMap := make(map[string]bool)     // Track rule IDs to prevent duplicates
	ruleNameMap := make(map[string]string) // Track rule names to detect duplicates with different IDs

	// Load local rules first
	cfg, err := config.LoadConfig("")
	if err == nil {
		cacheManager := cache.NewCacheManager(cfg)
		localRules, err := cacheManager.ListCachedRules()
		if err == nil {
			for _, cacheEntry := range localRules {
				rule, err := cacheManager.GetRule(cacheEntry.ID)
				if err == nil && rule != nil {
					if !ruleIDMap[rule.GetID()] {
						if existingID, found := ruleNameMap[rule.GetTitle()]; found {
							logger.Warn("Found duplicate rule with different ID", "name", rule.GetTitle(), "existing_id", existingID, "new_id", rule.GetID())
							continue
						}
						ruleIDMap[rule.GetID()] = true
						ruleNameMap[rule.GetTitle()] = rule.GetID()
						allRules = append(allRules, &RuleWithSource{
							SpotterRule: rule,
							Source:      "local",
						})
					}
				}
			}
		}
	}

	// Load external rules
	rulesPaths := viper.GetStringSlice("rules-path")
	if len(rulesPaths) > 0 {
		externalRules, err := loadExternalRules(parser, rulesPaths)
		if err != nil {
			return nil, fmt.Errorf("failed to load external rules: %w", err)
		}
		for _, rule := range externalRules {
			// Check if we've already seen this rule ID
			if !ruleIDMap[rule.GetID()] {
				// Check if we've seen a rule with the same name but different ID
				if existingID, found := ruleNameMap[rule.GetTitle()]; found {
					logger.Warn("Found duplicate rule with different ID", "name", rule.GetTitle(), "existing_id", existingID, "new_id", rule.GetID())
					// Skip this rule as we already have one with the same name
					continue
				}

				ruleIDMap[rule.GetID()] = true
				ruleNameMap[rule.GetTitle()] = rule.GetID()
				allRules = append(allRules, &RuleWithSource{
					SpotterRule: rule,
					Source:      "custom",
				})
			}
		}
	}

	return allRules, nil
}

func filterRules(rules []*RuleWithSource, cmd *cobra.Command) []*RuleWithSource {
	var filtered []*RuleWithSource

	severities, _ := cmd.Flags().GetStringSlice("severity")
	categories, _ := cmd.Flags().GetStringSlice("category")
	search, _ := cmd.Flags().GetString("search")

	for _, rule := range rules {
		// Filter by severity
		if len(severities) > 0 {
			match := false
			for _, sev := range severities {
				if strings.EqualFold(string(rule.GetSeverityLevel()), sev) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// Filter by category
		if len(categories) > 0 {
			match := false
			for _, cat := range categories {
				if strings.EqualFold(rule.GetCategory(), cat) {
					match = true
					break
				}
			}
			if !match {
				continue
			}
		}

		// Filter by search term
		if search != "" {
			searchLower := strings.ToLower(search)
			if !strings.Contains(strings.ToLower(rule.GetTitle()), searchLower) &&
				!strings.Contains(strings.ToLower(rule.GetDescription()), searchLower) {
				continue
			}
		}

		filtered = append(filtered, rule)
	}

	return filtered
}

func outputRulesTable(rules []*RuleWithSource, showDescription bool, showSource bool) {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	// Build header
	header := "ID\tNAME\tSEVERITY\tCATEGORY"
	if showDescription {
		header += "\tDESCRIPTION"
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		logger.Error("Failed to write header", "error", err)
	}

	// Build rows
	for _, rule := range rules {
		row := fmt.Sprintf("%s\t%s\t%s\t%s",
			rule.GetID(),
			rule.GetTitle(),
			string(rule.GetSeverityLevel()),
			rule.GetCategory())

		if showDescription {
			desc := rule.GetDescription()
			if len(desc) > 50 {
				desc = desc[:47] + "..."
			}
			row += "\t" + desc
		}

		if _, err := fmt.Fprintln(w, row); err != nil {
			logger.Error("Failed to write row", "error", err)
		}
	}

	if err := w.Flush(); err != nil {
		logger.Error("Failed to flush writer", "error", err)
	}
}

func outputRulesJSON(rules []*RuleWithSource) error {
	data, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputRulesYAML(rules []*RuleWithSource) error {
	data, err := yaml.Marshal(rules)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

func outputRuleInfoTable(rule *models.SpotterRule, cmd *cobra.Command) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	printField := func(field, value string) {
		if _, err := fmt.Fprintf(w, "%s:\t%s\n", field, value); err != nil {
			logger.Error("Failed to write field", "field", field, "error", err)
		}
	}

	printField("ID", rule.GetID())
	printField("Name", rule.GetTitle())
	printField("Version", rule.GetVersion())
	printField("Severity", string(rule.GetSeverityLevel()))
	printField("Category", rule.GetCategory())
	if rule.GetCWE() != "" {
		printField("CWE", rule.GetCWE())
	}
	printField("Description", rule.GetDescription())

	showCEL, _ := cmd.Flags().GetBool("show-cel")
	if showCEL {
		printField("CEL Expression", rule.GetCELExpression())
	}

	if rule.GetRemediation() != "" {
		printField("Remediation", rule.GetRemediation())
	}

	if len(rule.Spec.References) > 0 {
		var references strings.Builder
		for i, ref := range rule.Spec.References {
			if i > 0 {
				references.WriteString(", ")
			}
			references.WriteString(fmt.Sprintf("%s (%s)", ref.Title, ref.URL))
		}
		printField("References", references.String())
	}

	return w.Flush()
}

func outputRuleInfoJSON(rule *models.SpotterRule) error {
	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputRuleInfoYAML(rule *models.SpotterRule) error {
	data, err := yaml.Marshal(rule)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

func exportToSARIF(rules []*models.SpotterRule) ([]byte, error) {
	// SARIF export implementation
	// This is a simplified version - a full implementation would create proper SARIF format
	sarif := map[string]interface{}{
		"version": "2.1.0",
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"runs": []map[string]interface{}{
			{
				"tool": map[string]interface{}{
					"driver": map[string]interface{}{
						"name":    "Spotter",
						"version": "1.0.0",
						"rules":   convertRulesToSARIF(rules),
					},
				},
				"results": []interface{}{},
			},
		},
	}

	return json.MarshalIndent(sarif, "", "  ")
}

func convertRulesToSARIF(rules []*models.SpotterRule) []map[string]interface{} {
	var sarifRules []map[string]interface{}

	for _, rule := range rules {
		sarifRule := map[string]interface{}{
			"id":   rule.GetID(),
			"name": rule.GetTitle(),
			"shortDescription": map[string]interface{}{
				"text": rule.GetTitle(),
			},
			"fullDescription": map[string]interface{}{
				"text": rule.GetDescription(),
			},
			"defaultConfiguration": map[string]interface{}{
				"level": convertSeverityToSARIF(rule.GetSeverityLevel()),
			},
			"properties": map[string]interface{}{
				"category": rule.GetCategory(),
				"severity": string(rule.GetSeverityLevel()),
			},
		}

		if rule.GetCWE() != "" {
			sarifRule["properties"].(map[string]interface{})["cwe"] = rule.GetCWE()
		}

		sarifRules = append(sarifRules, sarifRule)
	}

	return sarifRules
}

func convertSeverityToSARIF(severity models.SeverityLevel) string {
	switch severity {
	case models.SeverityCritical, models.SeverityHigh:
		return "error"
	case models.SeverityMedium:
		return "warning"
	case models.SeverityLow:
		return "note"
	default:
		return "warning"
	}
}

func exportToCSV(rules []*models.SpotterRule) ([]byte, error) {
	var lines []string
	// CSV header
	lines = append(lines, "ID,Name,Severity,Category,Description,CWE")

	// CSV data
	for _, rule := range rules {
		// Escape commas and quotes in description
		desc := strings.ReplaceAll(rule.GetDescription(), "\"", "\"\"")
		if strings.Contains(desc, ",") || strings.Contains(desc, "\"") {
			desc = "\"" + desc + "\""
		}

		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s",
			rule.GetID(),
			rule.GetTitle(),
			rule.GetSeverityLevel(),
			rule.GetCategory(),
			desc,
			rule.GetCWE())
		lines = append(lines, line)
	}

	return []byte(strings.Join(lines, "\n")), nil
}

// Test case validation structures
type TestConfig struct {
	TestCases map[string]TestCaseConfig `yaml:"testCases"`
}

type TestCaseConfig struct {
	RuleID string         `yaml:"ruleID"`
	Good   []TestCaseFile `yaml:"good"`
	Bad    []TestCaseFile `yaml:"bad"`
}

type TestCaseFile struct {
	File        string `yaml:"file"`
	Expected    bool   `yaml:"expected"`
	Description string `yaml:"description"`
}

func generateRuleTemplate(ruleName, category, severity string, interactive bool) (string, error) {
	// Convert rule name to DNS-1123 format if provided
	if ruleName == "" {
		ruleName = "my-security-rule"
	} else {
		// Convert to lowercase and replace spaces/underscores with hyphens
		ruleName = strings.ToLower(ruleName)
		ruleName = strings.ReplaceAll(ruleName, " ", "-")
		ruleName = strings.ReplaceAll(ruleName, "_", "-")
	}

	// Generate rule ID based on category
	categoryUpper := strings.ToUpper(strings.ReplaceAll(category, " ", "-"))
	ruleID := fmt.Sprintf("SPOTTER-%s-001", categoryUpper)

	// Create rule template
	template := fmt.Sprintf(`apiVersion: rules.spotter.dev/v1alpha1
kind: SpotterRule
metadata:
  name: %s
  labels:
    category: "%s"
    severity: %s
spec:
  id: %s
  name: "%s"
  version: "1.0.0"
  description: "Description of what this rule detects and why it matters for security"
  
  severity:
    level: "%s"
    score: 5.0  # 0.0-10.0 CVSS-like score
  
  category: "%s"
  subcategory: "Resource Management"  # Optional
  cwe: "CWE-770"  # Optional Common Weakness Enumeration

  regulatoryStandards:
    - name: "CIS Kubernetes Benchmark"
      reference: "https://cisecurity.org/..."
    - name: "NIST SP 800-53"
      reference: "https://csrc.nist.gov/..."

  match:
    resources:
      kubernetes:
        apiGroups: ["", "apps"]
        versions: ["v1"]
        kinds: ["Pod", "Deployment"]
        namespaces:  # Optional
          include: ["*"]
          exclude: ["kube-system"]
  
  cel: |
    # CEL expression to evaluate the resource
    # Example: Check if resource limits are missing
    has(object.spec.containers) &&
    object.spec.containers.exists(container,
      !has(container.resources) ||
      !has(container.resources.limits)
    )
  
  remediation:
    manual: |
      1. Add resource limits to container specifications
      2. Set appropriate CPU and memory limits
      3. Review and adjust limits based on application requirements
  
  references:
    - title: "Kubernetes Resource Management"
      url: "https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/"
  
  metadata:
    author: "Security Team"
    created: "%s"
`, ruleName, category, strings.ToLower(severity), ruleID, cases.Title(language.Und).String(strings.ReplaceAll(ruleName, "-", " ")), severity, category, "2024-01-01")

	return template, nil
}
