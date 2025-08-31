package runner

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/madhuakula/spotter/pkg/parser"
	"github.com/madhuakula/spotter/pkg/testing"
	"github.com/madhuakula/spotter/pkg/utils"
	"github.com/madhuakula/spotter/pkg/validation"
)

// ValidationReport represents the result of validating files or directories
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

// RunValidation validates files or directories and returns results
func RunValidation(path string, runTests bool, outputFormat string, verbose bool) error {
	var reports []ValidationReport

	// Check if path is a file or directory
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to access path %s: %w", path, err)
	}

	if info.IsDir() {
		// Validate directory
		reports, err = ValidateDirectory(path, runTests, verbose)
		if err != nil {
			return err
		}
	} else {
		// Validate single file
		report, err := ValidateFile(path, runTests, verbose)
		if err != nil {
			return err
		}
		reports = append(reports, *report)
	}

	// Output results
	return OutputResults(reports, outputFormat)
}

// ValidateDirectory validates all files in a directory
func ValidateDirectory(dirPath string, runTests bool, verbose bool) ([]ValidationReport, error) {
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
		// For directory validation, we need to find rule files and their corresponding test files
		// Since we don't track source files in rule metadata, we'll scan the directory for rule files
		ruleFiles, err := utils.CollectFiles(dirPath, utils.FileCollectionOptions{
			Recursive:   true,
			Extensions:  []string{".yaml", ".yml"},
			ExcludeTest: true,
		})
		if err != nil {
			if verbose {
				fmt.Printf("Warning: Failed to collect rule files for testing: %v\n", err)
			}
		} else {
			// Run tests for each rule file that has a corresponding test file
			for _, ruleFile := range ruleFiles {
				testFilePath := parser.GetRuleTestFile(ruleFile)
				if _, err := os.Stat(testFilePath); err == nil {
					// Test file exists, load and run tests
					testSuite, err := parser.LoadTestCases(testFilePath)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: Failed to load test file %s: %v\n", testFilePath, err)
						}
						continue
					}

					// Load rules from this specific file for testing
					fileLoadResult, err := parser.LoadFromFile(ruleFile)
					if err != nil {
						if verbose {
							fmt.Printf("Warning: Failed to load rules from %s: %v\n", ruleFile, err)
						}
						continue
					}

					testRunner, err := testing.NewRuleTestRunner()
					if err != nil {
						if verbose {
							fmt.Printf("Warning: Failed to create test runner: %v\n", err)
						}
						continue
					}

					// Run tests for each rule in the file
					for _, rule := range fileLoadResult.Rules {
						testResult, err := testRunner.RunTestSuite(rule, testSuite)
						if err != nil {
							if verbose {
								fmt.Printf("Warning: Failed to run tests for rule %s: %v\n", rule.GetID(), err)
							}
							continue
						}
						report.TestResults = append(report.TestResults, *testResult)
						report.TestsRun = true
					}
				}
			}
		}
	}

	reports = append(reports, report)
	return reports, nil
}

// ValidateFile validates a single file
func ValidateFile(filePath string, runTests bool, verbose bool) (*ValidationReport, error) {
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
			// For single file validation, check if there's a corresponding test file
			// The test file should be named the same as the rule file but with "-test" suffix
			testFilePath := parser.GetRuleTestFile(filePath)
			if _, err := os.Stat(testFilePath); err == nil {
				// Test file exists, load and run tests
				testSuite, err := parser.LoadTestCases(testFilePath)
				if err != nil {
					if verbose {
						fmt.Printf("Warning: failed to load test cases from %s: %v\n", testFilePath, err)
					}
				} else {
					// Run tests for each rule in the file
					for _, rule := range result.Rules {
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
			} else if verbose {
				fmt.Printf("Info: no test file found for %s (expected: %s)\n", filePath, testFilePath)
			}
		}
	}

	return report, nil
}

// OutputResults outputs validation results in the specified format
func OutputResults(reports []ValidationReport, format string) error {
	switch format {
	case "json":
		return OutputJSON(reports)
	case "text":
		return OutputText(reports)
	default:
		return fmt.Errorf("unsupported output format: %s", format)
	}
}

// OutputJSON outputs results in JSON format
func OutputJSON(reports []ValidationReport) error {
	data, err := json.MarshalIndent(reports, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal JSON: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

// OutputText outputs results in human-readable text format
func OutputText(reports []ValidationReport) error {
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