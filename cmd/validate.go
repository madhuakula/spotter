package cmd

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/testing"
	"github.com/madhuakula/spotter/pkg/validation"
)

// validateSchemaCmd represents the validate command for schema validation
var validateSchemaCmd = &cobra.Command{
	Use:   "validate [file|directory]",
	Short: "Validate rules and rulepacks schema and run tests",
	Long: `Validate SpotterRule and SpotterRulePack YAML files for correct schema,
and optionally run CEL expression tests against test cases.

Examples:
  # Validate a single rule file
  spotter validate rule.yaml
  
  # Validate all rules in a directory
  spotter validate ./rules/
  
  # Validate and run tests
  spotter validate rule.yaml --test
  
  # Output results in JSON format
  spotter validate rule.yaml --output json`,
	Args: cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		path := args[0]
		runTests, _ := cmd.Flags().GetBool("test")
		outputFormat, _ := cmd.Flags().GetString("output")
		verbose, _ := cmd.Root().PersistentFlags().GetBool("verbose")

		return runValidation(path, runTests, outputFormat, verbose)
	},
}

func init() {
	rootCmd.AddCommand(validateSchemaCmd)

	validateSchemaCmd.Flags().BoolP("test", "t", false, "Run CEL expression tests if test files are found")
	validateSchemaCmd.Flags().StringP("output", "o", "text", "Output format (text, json)")
}

type ValidationReport struct {
	Path             string                       `json:"path"`
	Valid            bool                         `json:"valid"`
	RulesCount       int                          `json:"rulesCount"`
	RulePacksCount   int                          `json:"rulePacksCount"`
	ValidationErrors []validation.ValidationError `json:"validationErrors,omitempty"`
	LoadErrors       []string                     `json:"loadErrors,omitempty"`
	TestResults      []testing.TestSuiteResult    `json:"testResults,omitempty"`
	TestsRun         bool                         `json:"testsRun"`
}

func runValidation(path string, runTests bool, outputFormat string, verbose bool) error {
	var reports []ValidationReport

	// Check if path is a file or directory
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path %s: %w", path, err)
	}

	if info.IsDir() {
		// Validate directory
		reports, err = validateDirectory(path, runTests, verbose)
		if err != nil {
			return err
		}
	} else {
		// Validate single file
		report, err := validateFile(path, runTests, verbose)
		if err != nil {
			return err
		}
		reports = append(reports, *report)
	}

	// Output results
	return outputResults(reports, outputFormat)
}

func validateDirectory(dirPath string, runTests bool, verbose bool) ([]ValidationReport, error) {
	var reports []ValidationReport

	// Load all rules and rulepacks from directory
	loadResult, err := parser.LoadFromDirectory(dirPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load from directory: %w", err)
	}

	// Create a single report for the directory
	report := ValidationReport{
		Path:           dirPath,
		Valid:          true,
		RulesCount:     len(loadResult.Rules),
		RulePacksCount: len(loadResult.RulePacks),
		TestsRun:       runTests,
	}

	// Process load errors
	for _, loadErr := range loadResult.Errors {
		report.LoadErrors = append(report.LoadErrors, loadErr.Error())
		report.Valid = false
	}

	// Validate loaded rules
	for _, rule := range loadResult.Rules {
		validationResult := validation.ValidateSpotterRule(rule)
		if !validationResult.Valid {
			report.Valid = false
			report.ValidationErrors = append(report.ValidationErrors, validationResult.Errors...)
		}
	}

	// Validate loaded rulepacks
	for _, rulePack := range loadResult.RulePacks {
		validationResult := validation.ValidateSpotterRulePack(rulePack)
		if !validationResult.Valid {
			report.Valid = false
			report.ValidationErrors = append(report.ValidationErrors, validationResult.Errors...)
		}
	}

	// Run tests if requested
	if runTests && len(loadResult.Rules) > 0 {
		testRunner, err := testing.NewRuleTestRunner()
		if err != nil {
			if verbose {
				fmt.Printf("Warning: failed to create test runner: %v\n", err)
			}
		} else {
			// Find and run tests for each rule
			for _, rule := range loadResult.Rules {
				// Look for test files in the directory
				testFilePath := parser.GetRuleTestFile(dirPath + "/" + rule.Metadata.Name + ".yaml")
				if _, err := os.Stat(testFilePath); err == nil {
					// Test file exists, load and run tests
					testSuite, err := parser.LoadTestCases(testFilePath)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: failed to load test cases from %s: %v\n", testFilePath, err)
						}
						continue
					}

					testResult, err := testRunner.RunTestSuite(rule, testSuite)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: failed to run tests for rule %s: %v\n", rule.GetID(), err)
						}
						continue
					}

					report.TestResults = append(report.TestResults, *testResult)
					if !testResult.Success {
						report.Valid = false
					}
				}
			}
		}
	}

	reports = append(reports, report)
	return reports, nil

}

func validateFile(filePath string, runTests bool, verbose bool) (*ValidationReport, error) {
	report := &ValidationReport{
		Path:     filePath,
		Valid:    true,
		TestsRun: false,
	}

	// Load and validate the file
	result, validationResults, err := parser.ValidateAndLoad(filePath)
	if err != nil {
		report.Valid = false
		report.LoadErrors = append(report.LoadErrors, err.Error())
		return report, nil
	}

	report.RulesCount = len(result.Rules)
	report.RulePacksCount = len(result.RulePacks)

	// Add load errors
	for _, loadErr := range result.Errors {
		report.LoadErrors = append(report.LoadErrors, loadErr.Error())
		report.Valid = false
	}

	// Process validation results
	for _, validationResult := range validationResults {
		if !validationResult.Valid {
			report.Valid = false
			report.ValidationErrors = append(report.ValidationErrors, validationResult.Errors...)
		}
	}

	// Run tests if requested and rules are present
	if runTests && len(result.Rules) > 0 {
		testRunner, err := testing.NewRuleTestRunner()
		if err != nil {
			if verbose {
				fmt.Printf("Warning: failed to create test runner: %v\n", err)
			}
		} else {
			report.TestsRun = true
			for _, rule := range result.Rules {
				testFilePath := parser.GetRuleTestFile(filePath)
				if _, err := os.Stat(testFilePath); err == nil {
					// Test file exists, load and run tests
					testSuite, err := parser.LoadTestCases(testFilePath)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: failed to load test cases from %s: %v\n", testFilePath, err)
						}
						continue
					}

					testResult, err := testRunner.RunTestSuite(rule, testSuite)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: failed to run tests for rule %s: %v\n", rule.GetID(), err)
						}
						continue
					}

					report.TestResults = append(report.TestResults, *testResult)
					if !testResult.Success {
						report.Valid = false
					}
				} else if verbose {
					fmt.Printf("Info: no test file found for rule %s (expected: %s)\n", rule.GetID(), testFilePath)
				}
			}
		}
	}

	return report, nil
}

func outputResults(reports []ValidationReport, format string) error {
	switch format {
	case "json":
		return outputJSON(reports)
	case "text":
		return outputText(reports)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

func outputJSON(reports []ValidationReport) error {
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

func outputText(reports []ValidationReport) error {
	totalFiles := len(reports)
	validFiles := 0
	totalRules := 0
	totalRulePacks := 0
	totalTests := 0
	passedTests := 0

	for _, report := range reports {
		if report.Valid {
			validFiles++
		}
		totalRules += report.RulesCount
		totalRulePacks += report.RulePacksCount

		// Print file-level results
		status := "✓ VALID"
		if !report.Valid {
			status = "✗ INVALID"
		}
		fmt.Printf("%s %s\n", status, report.Path)

		if report.RulesCount > 0 {
			fmt.Printf("  Rules: %d\n", report.RulesCount)
		}
		if report.RulePacksCount > 0 {
			fmt.Printf("  Rule Packs: %d\n", report.RulePacksCount)
		}

		// Print validation errors
		if len(report.ValidationErrors) > 0 {
			fmt.Printf("  Validation Errors:\n")
			for _, err := range report.ValidationErrors {
				fmt.Printf("    - %s\n", err.Error())
			}
		}

		// Print load errors
		if len(report.LoadErrors) > 0 {
			fmt.Printf("  Load Errors:\n")
			for _, err := range report.LoadErrors {
				fmt.Printf("    - %s\n", err)
			}
		}

		// Print test results
		if report.TestsRun && len(report.TestResults) > 0 {
			fmt.Printf("  Test Results:\n")
			for _, testResult := range report.TestResults {
				totalTests += testResult.TotalTests
				passedTests += testResult.PassedTests

				testStatus := "✓ PASSED"
				if !testResult.Success {
					testStatus = "✗ FAILED"
				}
				fmt.Printf("    %s %s (%d/%d tests passed)\n",
					testStatus, testResult.RuleID, testResult.PassedTests, testResult.TotalTests)

				// Show failed test details
				for _, result := range testResult.Results {
					if !result.Passed {
						fmt.Printf("      - %s: %s\n", result.TestCase.Name, result.Description)
						if result.Error != "" {
							fmt.Printf("        Error: %s\n", result.Error)
						}
					}
				}
			}
		}

		fmt.Println()
	}

	// Print summary
	fmt.Printf("Summary:\n")
	fmt.Printf("  Files: %d/%d valid\n", validFiles, totalFiles)
	fmt.Printf("  Rules: %d\n", totalRules)
	fmt.Printf("  Rule Packs: %d\n", totalRulePacks)
	if totalTests > 0 {
		fmt.Printf("  Tests: %d/%d passed\n", passedTests, totalTests)
	}

	if validFiles != totalFiles || (totalTests > 0 && passedTests != totalTests) {
		os.Exit(1)
	}

	return nil
}