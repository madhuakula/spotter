package parser

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
	"gopkg.in/yaml.v3"
)

var logger = slog.Default()

// YAMLParser implements RuleParser for YAML files
type YAMLParser struct {
	validateSchema bool
}

// NewYAMLParser creates a new YAML parser
func NewYAMLParser(validateSchema bool) *YAMLParser {
	return &YAMLParser{
		validateSchema: validateSchema,
	}
}

// ParseRule parses a single security rule from a reader
func (p *YAMLParser) ParseRule(ctx context.Context, reader io.Reader) (*models.SpotterRule, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read rule data: %w", err)
	}

	var rule models.SpotterRule
	if err := yaml.Unmarshal(data, &rule); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %w", err)
	}

	if p.validateSchema {
		if err := p.ValidateRule(ctx, &rule); err != nil {
			return nil, fmt.Errorf("rule validation failed: %w", err)
		}
	}

	return &rule, nil
}

// ParseRules parses multiple security rules from a reader (YAML documents separated by ---)
func (p *YAMLParser) ParseRules(ctx context.Context, reader io.Reader) ([]*models.SpotterRule, error) {
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, fmt.Errorf("failed to read rules data: %w", err)
	}

	// Split YAML documents
	documents := strings.Split(string(data), "\n---\n")
	rules := make([]*models.SpotterRule, 0, len(documents))

	for i, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" {
			continue
		}

		var rule models.SpotterRule
		if err := yaml.Unmarshal([]byte(doc), &rule); err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML document %d: %w", i+1, err)
		}

		if p.validateSchema {
			if err := p.ValidateRule(ctx, &rule); err != nil {
				return nil, fmt.Errorf("rule validation failed for document %d: %w", i+1, err)
			}
		}

		rules = append(rules, &rule)
	}

	return rules, nil
}

// ParseRuleFromFile parses a security rule from a file path
func (p *YAMLParser) ParseRuleFromFile(ctx context.Context, filePath string) (*models.SpotterRule, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", filePath, err)
	}
	defer func() {
		if err := file.Close(); err != nil {
			logger.Error("Failed to close file", "path", filePath, "error", err)
		}
	}()

	rule, err := p.ParseRule(ctx, file)
	if err != nil {
		return nil, fmt.Errorf("failed to parse rule from file %s: %w", filePath, err)
	}

	return rule, nil
}

// ParseRulesFromDirectory parses all security rules from a directory
func (p *YAMLParser) ParseRulesFromDirectory(ctx context.Context, dirPath string) ([]*models.SpotterRule, error) {
	var rules []*models.SpotterRule

	err := filepath.WalkDir(dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories and non-YAML files
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		rule, err := p.ParseRuleFromFile(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to parse rule from %s: %w", path, err)
		}

		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk directory %s: %w", dirPath, err)
	}

	return rules, nil
}

// ParseRulesFromFS parses all security rules from an embedded filesystem
func (p *YAMLParser) ParseRulesFromFS(ctx context.Context, fsys fs.FS, dirPath string) ([]*models.SpotterRule, error) {
	var rules []*models.SpotterRule

	err := fs.WalkDir(fsys, dirPath, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip directories, non-YAML files, and test files
		if d.IsDir() || (!strings.HasSuffix(path, ".yaml") && !strings.HasSuffix(path, ".yml")) {
			return nil
		}

		// Skip test files (files ending with -test.yaml or -test.yml)
		baseName := filepath.Base(path)
		if strings.HasSuffix(baseName, "-test.yaml") || strings.HasSuffix(baseName, "-test.yml") {
			return nil
		}

		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read file from embedded filesystem
		file, err := fsys.Open(path)
		if err != nil {
			return fmt.Errorf("failed to open embedded file %s: %w", path, err)
		}
		defer func() {
			if err := file.Close(); err != nil {
				logger.Error("Failed to close embedded file", "path", path, "error", err)
			}
		}()

		rule, err := p.ParseRule(ctx, file)
		if err != nil {
			return fmt.Errorf("failed to parse rule from embedded file %s: %w", path, err)
		}

		rules = append(rules, rule)
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk embedded directory %s: %w", dirPath, err)
	}

	return rules, nil
}

// ValidateRule validates a security rule against the schema
func (p *YAMLParser) ValidateRule(ctx context.Context, rule *models.SpotterRule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}

	// Validate required fields
	if rule.APIVersion == "" {
		return fmt.Errorf("apiVersion is required")
	}
	if rule.APIVersion != "rules.spotter.dev/v1alpha1" {
		return fmt.Errorf("unsupported apiVersion: %s", rule.APIVersion)
	}

	if rule.Kind == "" {
		return fmt.Errorf("kind is required")
	}
	if rule.Kind != "SpotterRule" {
		return fmt.Errorf("unsupported kind: %s", rule.Kind)
	}

	// Validate metadata
	if err := p.validateMetadata(&rule.Metadata); err != nil {
		return fmt.Errorf("metadata validation failed: %w", err)
	}

	// Validate spec
	if err := p.validateSpec(&rule.Spec); err != nil {
		return fmt.Errorf("spec validation failed: %w", err)
	}

	return nil
}

func (p *YAMLParser) validateMetadata(metadata *models.RuleMetadata) error {
	if metadata.Name == "" {
		return fmt.Errorf("metadata.name is required")
	}

	// Validate name format (Kubernetes naming convention)
	nameRegex := regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	if !nameRegex.MatchString(metadata.Name) {
		return fmt.Errorf("metadata.name must match pattern ^[a-z0-9]([-a-z0-9]*[a-z0-9])?$")
	}

	if len(metadata.Name) > 253 {
		return fmt.Errorf("metadata.name must be at most 253 characters")
	}

	return nil
}

func (p *YAMLParser) validateSpec(spec *models.RuleSpec) error {
	// Validate required fields
	if spec.CEL == "" {
		return fmt.Errorf("spec.cel is required")
	}

	// Validate match criteria
	if err := p.validateMatchCriteria(&spec.Match); err != nil {
		return fmt.Errorf("match criteria validation failed: %w", err)
	}

	return nil
}

func (p *YAMLParser) validateMatchCriteria(match *models.MatchCriteria) error {
	kubernetes := &match.Resources.Kubernetes

	if len(kubernetes.APIGroups) == 0 {
		return fmt.Errorf("at least one apiGroup is required")
	}

	if len(kubernetes.Versions) == 0 {
		return fmt.Errorf("at least one version is required")
	}

	if len(kubernetes.Kinds) == 0 {
		return fmt.Errorf("at least one kind is required")
	}

	return nil
}
