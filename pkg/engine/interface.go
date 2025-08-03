package engine

import (
	"context"

	"github.com/google/cel-go/cel"
	"github.com/madhuakula/spotter/pkg/models"
)

// EvaluationEngine defines the interface for evaluating security rules
type EvaluationEngine interface {
	// EvaluateRule evaluates a single rule against a Kubernetes resource
	EvaluateRule(ctx context.Context, rule *models.SecurityRule, resource map[string]interface{}) (*models.ValidationResult, error)

	// EvaluateRules evaluates multiple rules against a Kubernetes resource
	EvaluateRules(ctx context.Context, rules []*models.SecurityRule, resource map[string]interface{}) ([]*models.ValidationResult, error)

	// EvaluateRulesAgainstResources evaluates multiple rules against multiple resources
	EvaluateRulesAgainstResources(ctx context.Context, rules []*models.SecurityRule, resources []map[string]interface{}) (*models.ScanResult, error)

	// EvaluateRulesAgainstResourcesConcurrent evaluates multiple rules against multiple resources with specified parallelism
	EvaluateRulesAgainstResourcesConcurrent(ctx context.Context, rules []*models.SecurityRule, resources []map[string]interface{}, parallelism int) (*models.ScanResult, error)

	// CompileRule pre-compiles a rule's CEL expression for better performance
	CompileRule(ctx context.Context, rule *models.SecurityRule) error

	// ValidateCELExpression validates a CEL expression without executing it
	ValidateCELExpression(ctx context.Context, expression string) error
}

// ResourceMatcher defines the interface for matching resources against rule criteria
type ResourceMatcher interface {
	// MatchesRule checks if a resource matches the rule's match criteria
	MatchesRule(ctx context.Context, rule *models.SecurityRule, resource map[string]interface{}) (bool, error)

	// MatchesNamespace checks if a resource's namespace matches the namespace selector
	MatchesNamespace(ctx context.Context, namespace string, selector *models.NamespaceSelector) (bool, error)

	// MatchesLabels checks if a resource's labels match the label selector
	MatchesLabels(ctx context.Context, labels map[string]string, selector *models.LabelSelector) (bool, error)

	// MatchesKind checks if a resource kind matches the rule criteria
	MatchesKind(ctx context.Context, apiVersion, kind string, criteria *models.KubernetesResourceCriteria) (bool, error)
}

// RuleCompiler defines the interface for compiling and caching CEL expressions
type RuleCompiler interface {
	// Compile compiles a CEL program and caches it
	Compile(ctx context.Context, ruleID string, program cel.Program) error

	// GetCompiled retrieves a compiled CEL program
	GetCompiled(ctx context.Context, ruleID string) (interface{}, bool)

	// ClearCache clears the compilation cache
	ClearCache(ctx context.Context)

	// GetCacheStats returns cache statistics
	GetCacheStats(ctx context.Context) map[string]interface{}
}
