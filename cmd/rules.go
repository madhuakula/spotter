package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/text/cases"
	"golang.org/x/text/language"
	"gopkg.in/yaml.v3"

	"github.com/madhuakula/spotter/pkg/engine"
	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/parser"
)

// RuleWithSource wraps a SecurityRule with its source information
type RuleWithSource struct {
	*models.SecurityRule
	Source string // "built-in" or "custom"
}

// rulesCmd represents the rules command
var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage security rules",
	Long: `Manage security rules for Spotter scanner.

This command provides various operations for working with security rules:
- List available rules (built-in and custom)
- Validate rule syntax and structure
- Show detailed information about specific rules
- Export rules in different formats

Examples:
  # List all available rules
  spotter rules list
  
  # List only built-in rules
  spotter rules list --builtin-only
  
  # List rules by category
  spotter rules list --category=security
  
  # Validate custom rules
  spotter rules validate ./custom-rules/
  
  # Show detailed information about a rule
  spotter rules info privileged-containers
  
  # Export rules to JSON
  spotter rules export --format=json --output=rules.json`,
}

// listCmd represents the list subcommand
var listCmd = &cobra.Command{
	Use:   "list",
	Short: "List available security rules",
	Long: `List all available security rules including built-in and custom rules.

This command displays rules in a table format showing rule ID, name, severity,
category, and description. You can filter rules by various criteria.

Examples:
  # List all rules
  spotter rules list
  
  # List only built-in rules
  spotter rules list --builtin-only
  
  # List rules by severity
  spotter rules list --severity=high,critical
  
  # List rules by category
  spotter rules list --category=security,compliance
  
  # Output as JSON
  spotter rules list --output=json`,
	RunE: runListRules,
}

// validateCmd represents the validate subcommand
var validateCmd = &cobra.Command{
	Use:   "validate [path...]",
	Short: "Validate security rules",
	Long: `Validate the syntax and structure of security rules.

This command checks rule files for:
- Valid YAML/JSON syntax
- Required fields and structure
- CEL expression syntax
- Rule metadata completeness
- Duplicate rule IDs
- Test case validation (automatically looks for *_test.yaml files in same directory)

Examples:
  # Validate rules in a directory (automatically runs test cases if found)
  spotter rules validate ./rules/
  
  # Validate specific rule files
  spotter rules validate rule1.yaml rule2.yaml
  
  # Validate with additional test cases from specific directory
  spotter rules validate ./rules/ --test-cases=./test-cases/
  
  # Validate with strict mode (all warnings as errors)
  spotter rules validate ./rules/ --strict
  
  # Show detailed validation output
  spotter rules validate ./rules/ --verbose`,
	Args: cobra.MinimumNArgs(1),
	RunE: runValidateRules,
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
	Long: `Export security rules in various formats for integration with other tools.

Supported export formats:
- JSON: Machine-readable format
- YAML: Human-readable format
- SARIF: Static Analysis Results Interchange Format
- CSV: Comma-separated values for spreadsheets

Examples:
  # Export all rules to JSON
  spotter rules export --format=json --output=rules.json
  
  # Export built-in rules only
  spotter rules export --builtin-only --format=yaml
  
  # Export rules by category
  spotter rules export --category=security --format=sarif`,
	RunE: runExportRules,
}

func init() {
	rootCmd.AddCommand(rulesCmd)
	rulesCmd.AddCommand(listCmd)
	rulesCmd.AddCommand(validateCmd)
	rulesCmd.AddCommand(generateCmd)
	rulesCmd.AddCommand(infoCmd)
	rulesCmd.AddCommand(exportCmd)

	// List command flags
	listCmd.Flags().Bool("builtin-only", false, "show only built-in rules")
	listCmd.Flags().Bool("custom-only", false, "show only custom rules")
	listCmd.Flags().StringSlice("severity", []string{}, "filter by severity levels (low, medium, high, critical)")
	listCmd.Flags().StringSlice("category", []string{}, "filter by rule categories")
	listCmd.Flags().String("search", "", "search rules by name or description")
	listCmd.Flags().Bool("show-description", false, "show rule descriptions in output")
	listCmd.Flags().Bool("show-source", false, "show rule source (built-in or custom) in output")
	// Note: 'output' flag is inherited from global persistent flags

	// Validate command flags
	validateCmd.Flags().Bool("strict", false, "treat warnings as errors")
	validateCmd.Flags().Bool("recursive", true, "recursively validate directories")
	validateCmd.Flags().StringSlice("file-extensions", []string{".yaml", ".yml"}, "file extensions to validate")
	validateCmd.Flags().Bool("check-duplicates", true, "check for duplicate rule IDs")
	validateCmd.Flags().Bool("validate-cel", true, "validate CEL expressions")
	validateCmd.Flags().String("test-cases", "", "path to additional test cases directory")

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
	exportCmd.Flags().Bool("builtin-only", false, "export only built-in rules")
	exportCmd.Flags().Bool("custom-only", false, "export only custom rules")
	exportCmd.Flags().StringSlice("category", []string{}, "export rules by category")
	exportCmd.Flags().StringSlice("severity", []string{}, "export rules by severity")
	exportCmd.Flags().Bool("include-metadata", true, "include rule metadata in export")

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

	// Convert to SecurityRule slice for export
	// Sort rules by ID
	sort.Slice(filteredRules, func(i, j int) bool {
		return filteredRules[i].Spec.ID < filteredRules[j].Spec.ID
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
		showSource, _ := cmd.Flags().GetBool("show-source")
		outputRulesTable(filteredRules, showDescription, showSource)
		return nil
	}
}

func runValidateRules(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ctx := context.Background()

	logger.Info("Starting rule validation")

	parser := parser.NewYAMLParser(true)
	var allRules []*models.SecurityRule
	var validationErrors []string
	var validationWarnings []string

	recursive, _ := cmd.Flags().GetBool("recursive")
	extensions, _ := cmd.Flags().GetStringSlice("file-extensions")
	checkDuplicates, _ := cmd.Flags().GetBool("check-duplicates")
	validateCEL, _ := cmd.Flags().GetBool("validate-cel")
	strict, _ := cmd.Flags().GetBool("strict")

	// Collect and validate rule files
	for _, path := range args {
		files, err := collectRuleFiles(path, recursive, extensions)
		if err != nil {
			return fmt.Errorf("failed to collect rule files from %s: %w", path, err)
		}

		for _, file := range files {
			logger.Debug("Validating rule file", "file", file)

			// Parse rule file
			rule, err := parser.ParseRuleFromFile(ctx, file)
			if err != nil {
				validationErrors = append(validationErrors, fmt.Sprintf("%s: %v", file, err))
				continue
			}

			// Validate rule structure
			if warnings := validateRuleStructure(rule, file); len(warnings) > 0 {
				validationWarnings = append(validationWarnings, warnings...)
			}

			// Validate CEL expression if requested
			if validateCEL {
				if err := validateCELExpression(rule); err != nil {
					validationErrors = append(validationErrors, fmt.Sprintf("%s: CEL validation failed: %v", file, err))
				}
			}

			allRules = append(allRules, rule)
		}
	}

	// Check for duplicate rule IDs
	if checkDuplicates {
		if duplicates := findDuplicateRuleIDs(allRules); len(duplicates) > 0 {
			for _, dup := range duplicates {
				validationErrors = append(validationErrors, fmt.Sprintf("Duplicate rule ID: %s", dup))
			}
		}
	}

	// Always run test case validation for co-located test files
	if testErrors, testWarnings := runNewTestCaseValidation(allRules, args, ""); len(testErrors) > 0 || len(testWarnings) > 0 {
		validationErrors = append(validationErrors, testErrors...)
		validationWarnings = append(validationWarnings, testWarnings...)
	}

	// Run additional test case validation if path provided
	testCasesPath, _ := cmd.Flags().GetString("test-cases")
	if testCasesPath != "" {
		if testErrors, testWarnings := runNewTestCaseValidation(allRules, args, testCasesPath); len(testErrors) > 0 || len(testWarnings) > 0 {
			validationErrors = append(validationErrors, testErrors...)
			validationWarnings = append(validationWarnings, testWarnings...)
		}
	}

	// Output validation results
	logger.Info("Validation completed", "processed_rules", len(allRules))

	if len(validationWarnings) > 0 {
		logger.Warn("Found warnings", "count", len(validationWarnings))
		for _, warning := range validationWarnings {
			logger.Warn(warning)
		}
	}

	if len(validationErrors) > 0 {
		logger.Error("Found errors", "count", len(validationErrors))
		for _, err := range validationErrors {
			logger.Error(err)
		}
		return fmt.Errorf("validation failed with %d errors", len(validationErrors))
	}

	// In strict mode, treat warnings as errors
	if strict && len(validationWarnings) > 0 {
		return fmt.Errorf("validation failed in strict mode with %d warnings", len(validationWarnings))
	}

	logger.Info("All rules validated successfully")
	return nil
}

func runRuleInfo(cmd *cobra.Command, args []string) error {
	logger := GetLogger()
	ruleID := args[0]

	logger.Debug("Looking up rule information", "rule_id", ruleID)

	// Load all rules
	rules, err := loadRulesForCommand(cmd)
	if err != nil {
		return fmt.Errorf("failed to load rules: %w", err)
	}

	// Find the specific rule
	var targetRule *models.SecurityRule
	for _, rule := range rules {
		if rule.Spec.ID == ruleID {
			targetRule = rule.SecurityRule
			break
		}
	}

	if targetRule == nil {
		return fmt.Errorf("rule not found: %s", ruleID)
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

	// Convert to SecurityRule slice for export
	var securityRules []*models.SecurityRule
	for _, rule := range filteredRules {
		securityRules = append(securityRules, rule.SecurityRule)
	}

	// Sort rules by ID
	sort.Slice(securityRules, func(i, j int) bool {
		return securityRules[i].Spec.ID < securityRules[j].Spec.ID
	})

	// Get export format and output file
	format, _ := cmd.Flags().GetString("format")
	outputFile, _ := cmd.Flags().GetString("output-file")

	// Export rules
	var data []byte
	switch format {
	case "json":
		data, err = json.MarshalIndent(securityRules, "", "  ")
	case "yaml":
		data, err = yaml.Marshal(securityRules)
	case "sarif":
		data, err = exportToSARIF(securityRules)
	case "csv":
		data, err = exportToCSV(securityRules)
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

// Helper functions

func loadRulesForCommand(cmd *cobra.Command) ([]*RuleWithSource, error) {
	parser := parser.NewYAMLParser(true)
	var allRules []*RuleWithSource
	ruleIDMap := make(map[string]bool)     // Track rule IDs to prevent duplicates
	ruleNameMap := make(map[string]string) // Track rule names to detect duplicates with different IDs

	builtinOnly, _ := cmd.Flags().GetBool("builtin-only")
	customOnly, _ := cmd.Flags().GetBool("custom-only")

	// Load built-in rules unless custom-only is specified
	if !customOnly {
		builtinRules, err := loadBuiltinRules(parser)
		if err != nil {
			return nil, fmt.Errorf("failed to load built-in rules: %w", err)
		}
		for _, rule := range builtinRules {
			// Check if we've already seen this rule ID
			if !ruleIDMap[rule.Spec.ID] {
				// Check if we've seen a rule with the same name but different ID
				if existingID, found := ruleNameMap[rule.Spec.Name]; found {
					logger.Warn("Found duplicate rule with different ID", "name", rule.Spec.Name, "existing_id", existingID, "new_id", rule.Spec.ID)
					// Skip this rule as we already have one with the same name
					continue
				}
				
				ruleIDMap[rule.Spec.ID] = true
				ruleNameMap[rule.Spec.Name] = rule.Spec.ID
				allRules = append(allRules, &RuleWithSource{
					SecurityRule: rule,
					Source:       "built-in",
				})
			}
		}
	}

	// Load external rules unless builtin-only is specified
	if !builtinOnly {
		rulesPaths := viper.GetStringSlice("rules-path")
		if len(rulesPaths) > 0 {
			externalRules, err := loadExternalRules(parser, rulesPaths)
			if err != nil {
				return nil, fmt.Errorf("failed to load external rules: %w", err)
			}
			for _, rule := range externalRules {
				// Check if we've already seen this rule ID
				if !ruleIDMap[rule.Spec.ID] {
					// Check if we've seen a rule with the same name but different ID
					if existingID, found := ruleNameMap[rule.Spec.Name]; found {
						logger.Warn("Found duplicate rule with different ID", "name", rule.Spec.Name, "existing_id", existingID, "new_id", rule.Spec.ID)
						// Skip this rule as we already have one with the same name
						continue
					}
					
					ruleIDMap[rule.Spec.ID] = true
					ruleNameMap[rule.Spec.Name] = rule.Spec.ID
					allRules = append(allRules, &RuleWithSource{
						SecurityRule: rule,
						Source:       "custom",
					})
				}
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
				if strings.EqualFold(string(rule.Spec.Severity.Level), sev) {
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
				if strings.EqualFold(rule.Spec.Category, cat) {
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
			if !strings.Contains(strings.ToLower(rule.Spec.Name), searchLower) &&
				!strings.Contains(strings.ToLower(rule.Spec.Description), searchLower) {
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
	if showSource {
		header += "\tSOURCE"
	}
	if showDescription {
		header += "\tDESCRIPTION"
	}
	if _, err := fmt.Fprintln(w, header); err != nil {
		logger.Error("Failed to write header", "error", err)
	}

	// Build rows
	for _, rule := range rules {
		row := fmt.Sprintf("%s\t%s\t%s\t%s",
			rule.Spec.ID,
			rule.Spec.Name,
			string(rule.Spec.Severity.Level),
			rule.Spec.Category)

		if showSource {
			row += "\t" + rule.Source
		}

		if showDescription {
			desc := rule.Spec.Description
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

func outputRuleInfoTable(rule *models.SecurityRule, cmd *cobra.Command) error {
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)

	printField := func(field, value string) {
		if _, err := fmt.Fprintf(w, "%s:\t%s\n", field, value); err != nil {
			logger.Error("Failed to write field", "field", field, "error", err)
		}
	}

	printField("ID", rule.Spec.ID)
	printField("Name", rule.Spec.Name)
	printField("Version", rule.Spec.Version)
	printField("Severity", string(rule.Spec.Severity.Level))
	printField("Category", rule.Spec.Category)
	if rule.Spec.Subcategory != "" {
		printField("Subcategory", rule.Spec.Subcategory)
	}
	if rule.Spec.CWE != "" {
		printField("CWE", rule.Spec.CWE)
	}
	printField("Description", rule.Spec.Description)

	showCEL, _ := cmd.Flags().GetBool("show-cel")
	if showCEL {
		printField("CEL Expression", rule.Spec.CEL)
	}

	if len(rule.Spec.RegulatoryStandards) > 0 {
		var standards strings.Builder
		for i, std := range rule.Spec.RegulatoryStandards {
			if i > 0 {
				standards.WriteString(", ")
			}
			standards.WriteString(fmt.Sprintf("%s (%s)", std.Name, std.Reference))
		}
		printField("Regulatory Standards", standards.String())
	}

	if rule.Spec.Remediation != nil && rule.Spec.Remediation.Manual != "" {
		printField("Remediation", rule.Spec.Remediation.Manual)
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

func outputRuleInfoJSON(rule *models.SecurityRule) error {
	data, err := json.MarshalIndent(rule, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

func outputRuleInfoYAML(rule *models.SecurityRule) error {
	data, err := yaml.Marshal(rule)
	if err != nil {
		return err
	}
	fmt.Print(string(data))
	return nil
}

func collectRuleFiles(path string, recursive bool, extensions []string) ([]string, error) {
	var files []string

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		// Single file
		if hasValidExtension(path, extensions) && !isTestFile(path) {
			files = append(files, path)
		}
		return files, nil
	}

	// Directory
	if recursive {
		err = filepath.WalkDir(path, func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && hasValidExtension(filePath, extensions) && !isTestFile(filePath) {
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
				if hasValidExtension(filePath, extensions) && !isTestFile(filePath) {
					files = append(files, filePath)
				}
			}
		}
	}

	return files, err
}

// isTestFile checks if the file is a test file (ends with _test.yaml or _test.yml)
func isTestFile(filePath string) bool {
	baseName := filepath.Base(filePath)
	return strings.HasSuffix(baseName, "_test.yaml") || strings.HasSuffix(baseName, "_test.yml")
}

func validateRuleStructure(rule *models.SecurityRule, filePath string) []string {
	var warnings []string

	// Check required fields
	if rule.Spec.ID == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing rule ID", filePath))
	}
	if rule.Spec.Name == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing rule name", filePath))
	}
	if rule.Spec.Description == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing rule description", filePath))
	}
	if rule.Spec.CEL == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing CEL expression", filePath))
	}
	if rule.Spec.Category == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing rule category", filePath))
	}

	// Check severity
	if rule.Spec.Severity.Level == "" {
		warnings = append(warnings, fmt.Sprintf("%s: missing severity level", filePath))
	}

	// Check match criteria
	if len(rule.Spec.Match.Resources.Kubernetes.Kinds) == 0 {
		warnings = append(warnings, fmt.Sprintf("%s: no resource kinds specified in match criteria", filePath))
	}

	return warnings
}

func validateCELExpression(rule *models.SecurityRule) error {
	ctx := context.Background()

	// Create CEL engine for validation
	celEngine, err := engine.NewCELEngine()
	if err != nil {
		return fmt.Errorf("failed to create CEL engine: %w", err)
	}

	// Use the engine's validation method
	return celEngine.ValidateCELExpression(ctx, rule.Spec.CEL)
}

func findDuplicateRuleIDs(rules []*models.SecurityRule) []string {
	seenIDs := make(map[string]bool)
	var duplicates []string

	for _, rule := range rules {
		if seenIDs[rule.Spec.ID] {
			duplicates = append(duplicates, rule.Spec.ID)
		} else {
			seenIDs[rule.Spec.ID] = true
		}
	}

	return duplicates
}

func exportToSARIF(rules []*models.SecurityRule) ([]byte, error) {
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

func convertRulesToSARIF(rules []*models.SecurityRule) []map[string]interface{} {
	var sarifRules []map[string]interface{}

	for _, rule := range rules {
		sarifRule := map[string]interface{}{
			"id":   rule.Spec.ID,
			"name": rule.Spec.Name,
			"shortDescription": map[string]interface{}{
				"text": rule.Spec.Name,
			},
			"fullDescription": map[string]interface{}{
				"text": rule.Spec.Description,
			},
			"defaultConfiguration": map[string]interface{}{
				"level": convertSeverityToSARIF(rule.Spec.Severity.Level),
			},
			"properties": map[string]interface{}{
				"category": rule.Spec.Category,
				"severity": string(rule.Spec.Severity.Level),
			},
		}

		if rule.Spec.CWE != "" {
			sarifRule["properties"].(map[string]interface{})["cwe"] = rule.Spec.CWE
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

func exportToCSV(rules []*models.SecurityRule) ([]byte, error) {
	var lines []string
	// CSV header
	lines = append(lines, "ID,Name,Severity,Category,Description,CWE")

	// CSV data
	for _, rule := range rules {
		// Escape commas and quotes in description
		desc := strings.ReplaceAll(rule.Spec.Description, "\"", "\"\"")
		if strings.Contains(desc, ",") || strings.Contains(desc, "\"") {
			desc = "\"" + desc + "\""
		}

		line := fmt.Sprintf("%s,%s,%s,%s,%s,%s",
			rule.Spec.ID,
			rule.Spec.Name,
			rule.Spec.Severity.Level,
			rule.Spec.Category,
			desc,
			rule.Spec.CWE)
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







// runNewTestCaseValidation validates rules using the new _test.yaml file approach
func runNewTestCaseValidation(rules []*models.SecurityRule, rulePaths []string, testCasesDir string) ([]string, []string) {
	logger := GetLogger()
	ctx := context.Background()
	var errors []string
	var warnings []string

	// Create a map of rules by their metadata name for quick lookup
	ruleMap := make(map[string]*models.SecurityRule)
	for _, rule := range rules {
		ruleMap[rule.Metadata.Name] = rule
	}

	// Find test files for each rule
	for _, rulePath := range rulePaths {
		testFiles, err := findTestFiles(rulePath, testCasesDir)
		if err != nil {
			errors = append(errors, fmt.Sprintf("failed to find test files for %s: %v", rulePath, err))
			continue
		}

		for ruleFile, testFile := range testFiles {
			// Extract rule name from file path
			ruleName := strings.TrimSuffix(filepath.Base(ruleFile), filepath.Ext(ruleFile))
			rule, exists := ruleMap[ruleName]
			if !exists {
				warnings = append(warnings, fmt.Sprintf("test file %s found but no corresponding rule %s", testFile, ruleName))
				continue
			}

			// Load and validate test cases
			testSuite, err := loadTestSuite(testFile)
			if err != nil {
				errors = append(errors, fmt.Sprintf("failed to load test suite %s: %v", testFile, err))
				continue
			}

			// Run each test case
			for i, testCase := range testSuite {
				if err := validateNewTestCase(ctx, rule, testCase, i); err != nil {
					errors = append(errors, fmt.Sprintf("test case '%s' in %s failed: %v", testCase.Name, testFile, err))
				} else {
					logger.Debug("Test case passed", "rule", ruleName, "test", testCase.Name)
				}
			}
		}
	}

	return errors, warnings
}

// findTestFiles finds corresponding test files for rule files
func findTestFiles(rulePath, testCasesDir string) (map[string]string, error) {
	testFiles := make(map[string]string)

	// Collect rule files
	ruleFiles, err := collectRuleFiles(rulePath, true, []string{".yaml", ".yml"})
	if err != nil {
		return nil, err
	}

	for _, ruleFile := range ruleFiles {
		// Generate test file name
		ruleDir := filepath.Dir(ruleFile)
		ruleBase := strings.TrimSuffix(filepath.Base(ruleFile), filepath.Ext(ruleFile))
		testFileName := ruleBase + "_test.yaml"

		// Determine test file path
		var testFilePath string
		if testCasesDir != "" {
			// Use specified test cases directory
			testFilePath = filepath.Join(testCasesDir, testFileName)
		} else {
			// Use same directory as rule file
			testFilePath = filepath.Join(ruleDir, testFileName)
		}

		// Check if test file exists
		if _, err := os.Stat(testFilePath); err == nil {
			testFiles[ruleFile] = testFilePath
		}
	}

	return testFiles, nil
}

// loadTestSuite loads test cases from a test file
func loadTestSuite(testFilePath string) (models.RuleTestSuite, error) {
	testData, err := os.ReadFile(testFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test file: %w", err)
	}

	var testSuite models.RuleTestSuite
	if err := yaml.Unmarshal(testData, &testSuite); err != nil {
		return nil, fmt.Errorf("failed to parse test file: %w", err)
	}

	return testSuite, nil
}

// validateNewTestCase validates a single test case against a rule
func validateNewTestCase(ctx context.Context, rule *models.SecurityRule, testCase models.RuleTestCase, index int) error {
	// Parse test input as Kubernetes resource
	var resource map[string]interface{}
	if err := yaml.Unmarshal([]byte(testCase.Input), &resource); err != nil {
		return fmt.Errorf("failed to parse test input: %w", err)
	}

	// Create CEL engine and evaluate rule
	celEngine, err := engine.NewCELEngine()
	if err != nil {
		return fmt.Errorf("failed to create CEL engine: %w", err)
	}

	result, err := celEngine.EvaluateRule(ctx, rule, resource)
	if err != nil {
		return fmt.Errorf("failed to evaluate rule: %w", err)
	}

	// Check if result matches expectation
	// testCase.Pass == true means the test should pass the security check (result.Passed = true)
	// testCase.Pass == false means the test should fail the security check (result.Passed = false)
	if result.Passed != testCase.Pass {
		return fmt.Errorf("expected passed=%v, got passed=%v", testCase.Pass, result.Passed)
	}

	return nil
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
	template := fmt.Sprintf(`apiVersion: rules.spotter.run/v1
kind: SecurityRule
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
    - name: "CIS Kubernetes x.x.x"
      reference: "https://cisecurity.org/..."
    - name: "NIST SP xxx-xx xx-x"
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
