package parser

import (
	"context"
	"io"

	"github.com/madhuakula/spotter/pkg/models"
)

// RuleParser defines the interface for parsing security rules
type RuleParser interface {
	// ParseRule parses a single security rule from a reader
	ParseRule(ctx context.Context, reader io.Reader) (*models.SecurityRule, error)

	// ParseRules parses multiple security rules from a reader
	ParseRules(ctx context.Context, reader io.Reader) ([]*models.SecurityRule, error)

	// ParseRuleFromFile parses a security rule from a file path
	ParseRuleFromFile(ctx context.Context, filePath string) (*models.SecurityRule, error)

	// ParseRulesFromDirectory parses all security rules from a directory
	ParseRulesFromDirectory(ctx context.Context, dirPath string) ([]*models.SecurityRule, error)

	// ValidateRule validates a security rule against the schema
	ValidateRule(ctx context.Context, rule *models.SecurityRule) error
}

// RuleLoader defines the interface for loading rules from various sources
type RuleLoader interface {
	// LoadFromFile loads rules from a file
	LoadFromFile(ctx context.Context, filePath string) ([]*models.SecurityRule, error)

	// LoadFromDirectory loads rules from a directory recursively
	LoadFromDirectory(ctx context.Context, dirPath string) ([]*models.SecurityRule, error)

	// LoadFromURL loads rules from a remote URL
	LoadFromURL(ctx context.Context, url string) ([]*models.SecurityRule, error)

	// LoadFromGit loads rules from a Git repository
	LoadFromGit(ctx context.Context, repoURL, branch, path string) ([]*models.SecurityRule, error)
}
