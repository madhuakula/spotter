package parser

import (
	"context"
	"io"

	"github.com/madhuakula/spotter/pkg/models"
)

// RuleParser defines the interface for parsing security rules
type RuleParser interface {
	// ParseRule parses a single security rule from a reader
	ParseRule(ctx context.Context, reader io.Reader) (*models.SpotterRule, error)

	// ParseRules parses multiple security rules from a reader
	ParseRules(ctx context.Context, reader io.Reader) ([]*models.SpotterRule, error)

	// ParseRuleFromFile parses a security rule from a file path
	ParseRuleFromFile(ctx context.Context, filePath string) (*models.SpotterRule, error)

	// ParseRulesFromDirectory parses all security rules from a directory
	ParseRulesFromDirectory(ctx context.Context, dirPath string) ([]*models.SpotterRule, error)

	// ValidateRule validates a security rule against the schema
	ValidateRule(ctx context.Context, rule *models.SpotterRule) error
}

// RuleLoader defines the interface for loading rules from various sources
type RuleLoader interface {
	// LoadFromFile loads rules from a file
	LoadFromFile(ctx context.Context, filePath string) ([]*models.SpotterRule, error)

	// LoadFromDirectory loads rules from a directory recursively
	LoadFromDirectory(ctx context.Context, dirPath string) ([]*models.SpotterRule, error)

	// LoadFromURL loads rules from a remote URL
	LoadFromURL(ctx context.Context, url string) ([]*models.SpotterRule, error)

	// LoadFromGit loads rules from a Git repository
	LoadFromGit(ctx context.Context, repoURL, branch, path string) ([]*models.SpotterRule, error)
}
