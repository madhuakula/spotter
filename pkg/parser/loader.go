package parser

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/madhuakula/spotter/pkg/models"
	"github.com/madhuakula/spotter/pkg/validation"
)

// LoadResult represents the result of loading rules or rule packs
type LoadResult struct {
	Rules     []*models.SpotterRule     `json:"rules"`
	RulePacks []*models.SpotterRulePack `json:"rulePacks"`
	Errors    []error                   `json:"errors"`
}

// LoadFromFile loads a SpotterRule or SpotterRulePack from a YAML file
func LoadFromFile(filePath string) (*LoadResult, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return LoadFromBytes(data)
}

// LoadFromReader loads a SpotterRule or SpotterRulePack from an io.Reader
func LoadFromReader(reader io.Reader) (*LoadResult, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read data: %w", err)
	}

	return LoadFromBytes(data)
}

// LoadFromBytes loads a SpotterRule or SpotterRulePack from YAML bytes
func LoadFromBytes(data []byte) (*LoadResult, error) {
	result := &LoadResult{
		Rules:     []*models.SpotterRule{},
		RulePacks: []*models.SpotterRulePack{},
		Errors:    []error{},
	}

	// Split YAML documents if multiple are present
	documents := strings.Split(string(data), "\n---\n")

	for i, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		// First, determine the kind
		var metadata struct {
			Kind string `yaml:"kind"`
		}

		if err := yaml.Unmarshal([]byte(doc), &metadata); err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("document %d: failed to parse metadata: %w", i, err))
			continue
		}

		switch metadata.Kind {
		case "SpotterRule":
			rule, err := parseSpotterRule([]byte(doc))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("document %d: %w", i, err))
				continue
			}
			result.Rules = append(result.Rules, rule)

		case "SpotterRulePack":
			rulePack, err := parseSpotterRulePack([]byte(doc))
			if err != nil {
				result.Errors = append(result.Errors, fmt.Errorf("document %d: %w", i, err))
				continue
			}
			result.RulePacks = append(result.RulePacks, rulePack)

		default:
			result.Errors = append(result.Errors, fmt.Errorf("document %d: unsupported kind '%s'", i, metadata.Kind))
		}
	}

	return result, nil
}

// LoadFromDirectory recursively loads all YAML files from a directory
func LoadFromDirectory(dirPath string) (*LoadResult, error) {
	result := &LoadResult{
		Rules:     []*models.SpotterRule{},
		RulePacks: []*models.SpotterRulePack{},
		Errors:    []error{},
	}

	err := filepath.Walk(dirPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if info.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		// Skip test files
		if strings.Contains(path, "-test.") || strings.Contains(path, "_test.") {
			return nil
		}

		fileResult, err := LoadFromFile(path)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("file %s: %w", path, err))
			return nil // Continue processing other files
		}

		// Merge results
		result.Rules = append(result.Rules, fileResult.Rules...)
		result.RulePacks = append(result.RulePacks, fileResult.RulePacks...)
		result.Errors = append(result.Errors, fileResult.Errors...)

		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	return result, nil
}

// ValidateAndLoad loads and validates rules/rulepacks from a file
func ValidateAndLoad(filePath string) (*LoadResult, []validation.ValidationResult, error) {
	result, err := LoadFromFile(filePath)
	if err != nil {
		return nil, nil, err
	}

	var validationResults []validation.ValidationResult

	// Validate all loaded rules
	for _, rule := range result.Rules {
		validationResult := validation.ValidateSpotterRule(rule)
		validationResults = append(validationResults, validationResult)
	}

	// Validate all loaded rule packs
	for _, rulePack := range result.RulePacks {
		validationResult := validation.ValidateSpotterRulePack(rulePack)
		validationResults = append(validationResults, validationResult)
	}

	return result, validationResults, nil
}

// parseSpotterRule parses YAML data into a SpotterRule
func parseSpotterRule(data []byte) (*models.SpotterRule, error) {
	var rule models.SpotterRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to parse SpotterRule: %w", err)
	}
	return &rule, nil
}

// parseSpotterRulePack parses YAML data into a SpotterRulePack
func parseSpotterRulePack(data []byte) (*models.SpotterRulePack, error) {
	var rulePack models.SpotterRulePack
	if err := yaml.Unmarshal(data, &rulePack); err != nil {
		return nil, fmt.Errorf("failed to parse SpotterRulePack: %w", err)
	}
	return &rulePack, nil
}

// LoadTestCases loads test cases for a rule from a test file
func LoadTestCases(testFilePath string) (models.RuleTestSuite, error) {
	data, err := os.ReadFile(testFilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read test file %s: %w", testFilePath, err)
	}

	var testCases models.RuleTestSuite
	if err := yaml.Unmarshal(data, &testCases); err != nil {
		return nil, fmt.Errorf("failed to parse test cases: %w", err)
	}

	return testCases, nil
}

// GetRuleTestFile returns the expected test file path for a given rule file
func GetRuleTestFile(ruleFilePath string) string {
	dir := filepath.Dir(ruleFilePath)
	base := filepath.Base(ruleFilePath)
	ext := filepath.Ext(base)
	name := strings.TrimSuffix(base, ext)
	return filepath.Join(dir, name+"-test"+ext)
}