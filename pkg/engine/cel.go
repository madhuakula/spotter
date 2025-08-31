package engine

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	"github.com/google/cel-go/ext"
	"github.com/madhuakula/spotter/pkg/models"
)

// CELEngine implements EvaluationEngine using Google's CEL (Common Expression Language)
type CELEngine struct {
	env      *cel.Env
	matcher  ResourceMatcher
	compiler RuleCompiler
}

// NewCELEngine creates a new CEL evaluation engine with Kubernetes-specific extensions
func NewCELEngine() (*CELEngine, error) {
	// Create CEL environment with Kubernetes object support and standard extensions
	env, err := cel.NewEnv(
		// Core variables for Kubernetes resource evaluation
		cel.Variable("object", cel.DynType),       // Primary Kubernetes resource
		cel.Variable("oldObject", cel.DynType),    // Previous state (for updates)
		cel.Variable("request", cel.DynType),      // Admission request context
		cel.Variable("authorizer", cel.DynType),   // Authorization context
		cel.Variable("namespace", cel.StringType), // Current namespace context
		cel.Variable("cluster", cel.DynType),      // Cluster information

		// Enable standard CEL extensions for enhanced functionality
		ext.Strings(),  // String manipulation functions
		ext.Encoders(), // Base64, URL encoding functions
		ext.Math(),     // Mathematical functions
		ext.Lists(),    // List manipulation functions
		ext.Sets(),     // Set operations

		// Enhanced Kubernetes-specific functions
		cel.Function("hasLabel",
			cel.Overload("hasLabel_string", []*cel.Type{cel.StringType}, cel.BoolType),
			cel.SingletonUnaryBinding(func(value ref.Val) ref.Val {
				_ = value.(types.String) // labelKey for future implementation
				// This would be implemented to check if object has the label
				return types.Bool(true) // Placeholder
			})),

		cel.Function("hasAnnotation",
			cel.Overload("hasAnnotation_string", []*cel.Type{cel.StringType}, cel.BoolType),
			cel.SingletonUnaryBinding(func(value ref.Val) ref.Val {
				_ = value.(types.String) // annotationKey for future implementation
				// This would be implemented to check if object has the annotation
				return types.Bool(true) // Placeholder
			})),

		cel.Function("isSystemNamespace",
			cel.Overload("isSystemNamespace_string", []*cel.Type{cel.StringType}, cel.BoolType),
			cel.SingletonUnaryBinding(func(value ref.Val) ref.Val {
				ns := string(value.(types.String))
				systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease", "default"}
				for _, sysNs := range systemNamespaces {
					if ns == sysNs || strings.HasPrefix(ns, "kube-") {
						return types.Bool(true)
					}
				}
				return types.Bool(false)
			})),

		cel.Function("hasSecurityContext",
			cel.Overload("hasSecurityContext_map", []*cel.Type{cel.DynType}, cel.BoolType),
			cel.SingletonUnaryBinding(func(value ref.Val) ref.Val {
				// Check if container has securityContext
				return types.Bool(true) // Placeholder
			})),

		// Enable homogeneous aggregate literals for better type safety
		cel.HomogeneousAggregateLiterals(),

		// Enable eager validation for better error reporting
		cel.EagerlyValidateDeclarations(true),

		// Set default UTC timezone for consistent time operations
		cel.DefaultUTCTimeZone(true),

		// Enable optimizations
		cel.OptionalTypes(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	return &CELEngine{
		env:      env,
		matcher:  NewResourceMatcher(),
		compiler: NewRuleCompiler(),
	}, nil
}

// quickResourceMatch performs a fast pre-filter to check if a resource might match a rule
// This avoids expensive CEL compilation and evaluation for obviously non-matching resources
func (e *CELEngine) quickResourceMatch(rule *models.SpotterRule, resource map[string]interface{}) bool {
	// Extract resource metadata
	apiVersion, _ := resource["apiVersion"].(string)
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]interface{})

	// Get the kubernetes criteria
	kubernetesCriteria := rule.Spec.Match.Resources.Kubernetes

	// Check kind match if specified
	if len(kubernetesCriteria.Kinds) > 0 {
		kindMatches := false
		for _, allowedKind := range kubernetesCriteria.Kinds {
			if allowedKind == "*" || allowedKind == kind {
				kindMatches = true
				break
			}
		}
		if !kindMatches {
			return false
		}
	}

	// Check API version match if specified
	if len(kubernetesCriteria.Versions) > 0 {
		versionMatches := false
		for _, allowedVersion := range kubernetesCriteria.Versions {
			if allowedVersion == "*" || apiVersion == allowedVersion {
				versionMatches = true
				break
			}
			// Also check if the apiVersion contains the version (e.g., "apps/v1" contains "v1")
			if apiVersion != "" && len(apiVersion) > len(allowedVersion) {
				if apiVersion[len(apiVersion)-len(allowedVersion):] == allowedVersion {
					versionMatches = true
					break
				}
			}
		}
		if !versionMatches {
			return false
		}
	}

	// Check API group match if specified
	if len(kubernetesCriteria.APIGroups) > 0 {
		groupMatches := false
		for _, allowedGroup := range kubernetesCriteria.APIGroups {
			if allowedGroup == "*" {
				groupMatches = true
				break
			}
			// Core API group is represented as empty string
			if allowedGroup == "" && (apiVersion == "v1" || !strings.Contains(apiVersion, "/")) {
				groupMatches = true
				break
			}
			// Check if apiVersion starts with the group
			if apiVersion != "" && strings.HasPrefix(apiVersion, allowedGroup+"/") {
				groupMatches = true
				break
			}
		}
		if !groupMatches {
			return false
		}
	}

	// Quick namespace check if specified and metadata exists
	if kubernetesCriteria.Namespaces != nil && metadata != nil {
		namespace, _ := metadata["namespace"].(string)
		// Simple include/exclude check - full logic is in MatchesNamespace
		if len(kubernetesCriteria.Namespaces.Include) > 0 {
			included := false
			for _, includePattern := range kubernetesCriteria.Namespaces.Include {
				if includePattern == "*" || includePattern == namespace {
					included = true
					break
				}
			}
			if !included {
				return false
			}
		}
		if len(kubernetesCriteria.Namespaces.Exclude) > 0 {
			for _, excludePattern := range kubernetesCriteria.Namespaces.Exclude {
				if excludePattern == namespace {
					return false
				}
			}
		}
	}

	return true
}

// EvaluateRule evaluates a single security rule against a single resource
func (e *CELEngine) EvaluateRule(ctx context.Context, rule *models.SpotterRule, resource map[string]interface{}) (*models.ValidationResult, error) {
	result := &models.ValidationResult{
		RuleID:    rule.GetID(),
		RuleName:  rule.GetTitle(),
		Resource:  resource,
		Severity:  rule.GetSeverityLevel(),
		Category:  rule.GetCategory(),
		Timestamp: time.Now(),
		Passed:    true, // Default to passed
	}

	// Check if resource matches rule criteria
	matches, err := e.matcher.MatchesRule(ctx, rule, resource)
	if err != nil {
		return nil, fmt.Errorf("failed to match resource against rule: %w", err)
	}

	if !matches {
		// Resource doesn't match rule criteria, return nil to skip evaluation
		return nil, nil
	}

	// Get compiled program from cache, compile if not cached
	program, exists := e.compiler.GetCompiled(ctx, rule.GetID())
	if !exists {
		// Compile CEL expression if not already compiled
		if err := e.CompileRule(ctx, rule); err != nil {
			return nil, fmt.Errorf("failed to compile rule: %w", err)
		}
		// Retrieve compiled program after compilation
		program, exists = e.compiler.GetCompiled(ctx, rule.GetID())
		if !exists {
			return nil, fmt.Errorf("failed to retrieve compiled program for rule %s after compilation", rule.GetID())
		}
	}

	celProgram, ok := program.(cel.Program)
	if !ok {
		return nil, fmt.Errorf("invalid compiled program type for rule %s", rule.GetID())
	}

	// Prepare evaluation context with comprehensive variable set
	vars := map[string]interface{}{
		"object":     resource,
		"oldObject":  nil, // Will be set for update operations
		"request":    nil, // Will be set for admission controller context
		"authorizer": nil, // Will be set for authorization context
	}

	// Evaluate CEL expression
	eval, _, err := celProgram.Eval(vars)
	if err != nil {
		result.Passed = false
		result.Message = fmt.Sprintf("CEL evaluation error: %v", err)
		return result, nil
	}

	// Check if evaluation result is a boolean
	boolResult, ok := eval.Value().(bool)
	if !ok {
		result.Passed = false
		result.Message = fmt.Sprintf("CEL expression must return a boolean value, got %T", eval.Value())
		return result, nil
	}

	// If CEL expression returns true, it means the rule failed (security issue found)
	result.Passed = !boolResult
	if !result.Passed {
		result.Message = fmt.Sprintf("Security rule violation: %s", rule.GetDescription())
		if rule.GetRemediation() != "" {
			result.Remediation = rule.GetRemediation()
		}
	}

	return result, nil
}

// EvaluateRules evaluates multiple rules against a Kubernetes resource
func (e *CELEngine) EvaluateRules(ctx context.Context, rules []*models.SpotterRule, resource map[string]interface{}) ([]*models.ValidationResult, error) {
	results := make([]*models.ValidationResult, 0, len(rules))

	for _, rule := range rules {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		result, err := e.EvaluateRule(ctx, rule, resource)
		if err != nil {
			return nil, fmt.Errorf("failed to evaluate rule %s: %w", rule.GetID(), err)
		}

		// Only append results where the resource matches the rule criteria
		if result != nil {
			results = append(results, result)
		}
	}

	return results, nil
}

// EvaluateRulesAgainstResources evaluates multiple rules against multiple resources
func (e *CELEngine) EvaluateRulesAgainstResources(ctx context.Context, rules []*models.SpotterRule, resources []map[string]interface{}) (*models.ScanResult, error) {
	// Default parallelism
	return e.EvaluateRulesAgainstResourcesConcurrent(ctx, rules, resources, 10)
}

// EvaluateRulesAgainstResourcesConcurrent evaluates multiple rules against multiple resources with optimized parallelism
func (e *CELEngine) EvaluateRulesAgainstResourcesConcurrent(ctx context.Context, rules []*models.SpotterRule, resources []map[string]interface{}, parallelism int) (*models.ScanResult, error) {
	startTime := time.Now()
	allResults := make([]models.ValidationResult, 0)
	severityBreakdown := make(map[string]int)
	categoryBreakdown := make(map[string]int)
	passed := 0
	failed := 0

	// Optimize parallelism based on workload
	numWorkers := parallelism
	if numWorkers <= 0 {
		numWorkers = 10 // Default fallback
	}

	// Limit workers to avoid over-parallelization for small workloads
	maxUsefulWorkers := len(rules)
	if len(resources) < len(rules) {
		maxUsefulWorkers = len(resources)
	}
	if numWorkers > maxUsefulWorkers {
		numWorkers = maxUsefulWorkers
	}
	if numWorkers < 1 {
		numWorkers = 1
	}

	// Pre-filter and batch jobs for better efficiency
	type ruleResourceBatch struct {
		rule      *models.SpotterRule
		resources []map[string]interface{}
	}

	type batchResult struct {
		results []models.ValidationResult
		err     error
	}

	// Group resources by rule for more efficient processing
	batches := make([]ruleResourceBatch, 0, len(rules))
	for _, rule := range rules {
		// Pre-filter resources that might match this rule to reduce unnecessary work
		matchingResources := make([]map[string]interface{}, 0)
		for _, resource := range resources {
			// Quick pre-check based on resource kind/apiVersion if available
			if e.quickResourceMatch(rule, resource) {
				matchingResources = append(matchingResources, resource)
			}
		}
		if len(matchingResources) > 0 {
			batches = append(batches, ruleResourceBatch{
				rule:      rule,
				resources: matchingResources,
			})
		}
	}

	// Use buffered channels sized appropriately
	batchJobs := make(chan ruleResourceBatch, len(batches))
	batchResults := make(chan batchResult, len(batches))

	// Start workers
	for i := 0; i < numWorkers; i++ {
		go func() {
			for batch := range batchJobs {
				select {
				case <-ctx.Done():
					return
				default:
				}

				batchRes := batchResult{results: make([]models.ValidationResult, 0)}
				for _, resource := range batch.resources {
					vr, err := e.EvaluateRule(ctx, batch.rule, resource)
					if err != nil {
						batchRes.err = err
						break
					}
					if vr != nil {
						batchRes.results = append(batchRes.results, *vr)
					}
				}
				batchResults <- batchRes
			}
		}()
	}

	// Send batch jobs
	go func() {
		defer close(batchJobs)
		for _, batch := range batches {
			select {
			case <-ctx.Done():
				return
			case batchJobs <- batch:
			}
		}
	}()

	// Collect results
	for i := 0; i < len(batches); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case batchRes := <-batchResults:
			if batchRes.err != nil {
				return nil, batchRes.err
			}

			for _, result := range batchRes.results {
				allResults = append(allResults, result)
				if result.Passed {
					passed++
				} else {
					failed++
					severityBreakdown[string(result.Severity)]++
					categoryBreakdown[result.Category]++
				}
			}
		}
	}

	return &models.ScanResult{
		TotalResources:    len(resources),
		TotalRules:        len(rules),
		Passed:            passed,
		Failed:            failed,
		Results:           allResults,
		SeverityBreakdown: severityBreakdown,
		CategoryBreakdown: categoryBreakdown,
		Timestamp:         startTime,
		Duration:          time.Since(startTime),
	}, nil
}

// CompileRule pre-compiles a rule's CEL expression for better performance
func (e *CELEngine) CompileRule(ctx context.Context, rule *models.SpotterRule) error {
	// Check if already compiled
	if _, exists := e.compiler.GetCompiled(ctx, rule.GetID()); exists {
		return nil
	}

	// Parse CEL expression
	ast, issues := e.env.Parse(rule.GetCELExpression())
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("failed to parse CEL expression: %w", issues.Err())
	}

	// Check the AST
	checked, issues := e.env.Check(ast)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("failed to check CEL expression: %w", issues.Err())
	}

	// Compile the checked expression to a program
	program, err := e.env.Program(checked)
	if err != nil {
		return fmt.Errorf("failed to compile CEL expression: %w", err)
	}

	// Cache compiled program
	return e.compiler.Compile(ctx, rule.GetID(), program)
}

// ValidateCELExpression validates a CEL expression without caching
// This method provides comprehensive validation including syntax, type checking, and semantic analysis
func (e *CELEngine) ValidateCELExpression(ctx context.Context, expression string) error {
	if strings.TrimSpace(expression) == "" {
		return fmt.Errorf("CEL expression cannot be empty")
	}

	// Parse the expression
	ast, issues := e.env.Parse(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("syntax error in CEL expression: %w", issues.Err())
	}

	// Type-check the expression
	checked, issues := e.env.Check(ast)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("type checking failed for CEL expression: %w", issues.Err())
	}

	// Validate return type - must be boolean for rule evaluation
	if !checked.OutputType().IsExactType(cel.BoolType) {
		return fmt.Errorf("CEL expression must return boolean type for rule evaluation, got %s", checked.OutputType())
	}

	// Attempt to compile to catch any compilation issues
	_, err := e.env.Program(checked)
	if err != nil {
		return fmt.Errorf("compilation failed for CEL expression: %w", err)
	}

	return nil
}

// ResourceMatcher implementation
type resourceMatcher struct{}

// NewResourceMatcher creates a new resource matcher
func NewResourceMatcher() ResourceMatcher {
	return &resourceMatcher{}
}

// MatchesRule checks if a resource matches the rule's match criteria
func (m *resourceMatcher) MatchesRule(ctx context.Context, rule *models.SpotterRule, resource map[string]interface{}) (bool, error) {
	// Extract resource metadata
	apiVersion, _ := resource["apiVersion"].(string)
	kind, _ := resource["kind"].(string)
	metadata, _ := resource["metadata"].(map[string]interface{})

	if metadata == nil {
		return false, fmt.Errorf("resource metadata is missing")
	}

	namespace, _ := metadata["namespace"].(string)
	labels := make(map[string]string)
	if labelMap, ok := metadata["labels"].(map[string]interface{}); ok {
		for k, v := range labelMap {
			if strVal, ok := v.(string); ok {
				labels[k] = strVal
			}
		}
	}

	// Check kind match
	matches, err := m.MatchesKind(ctx, apiVersion, kind, &rule.Spec.Match.Resources.Kubernetes)
	if err != nil || !matches {
		return matches, err
	}

	// Check namespace match
	if rule.Spec.Match.Resources.Kubernetes.Namespaces != nil {
		matches, err = m.MatchesNamespace(ctx, namespace, rule.Spec.Match.Resources.Kubernetes.Namespaces)
		if err != nil || !matches {
			return matches, err
		}
	}

	// Check label match
	if rule.Spec.Match.Resources.Kubernetes.Labels != nil {
		matches, err = m.MatchesLabels(ctx, labels, rule.Spec.Match.Resources.Kubernetes.Labels)
		if err != nil || !matches {
			return matches, err
		}
	}

	return true, nil
}

// MatchesNamespace checks if a resource's namespace matches the namespace selector
func (m *resourceMatcher) MatchesNamespace(ctx context.Context, namespace string, selector *models.NamespaceSelector) (bool, error) {
	// Check exclusions first
	for _, exclude := range selector.Exclude {
		if matched, _ := filepath.Match(exclude, namespace); matched {
			return false, nil
		}
	}

	// Check inclusions
	if len(selector.Include) == 0 {
		return true, nil // No inclusions means all namespaces are included
	}

	for _, include := range selector.Include {
		if include == "*" || include == namespace {
			return true, nil
		}
		if matched, _ := filepath.Match(include, namespace); matched {
			return true, nil
		}
	}

	return false, nil
}

// MatchesLabels checks if a resource's labels match the label selector
func (m *resourceMatcher) MatchesLabels(ctx context.Context, labels map[string]string, selector *models.LabelSelector) (bool, error) {
	// Check exclusions first
	for key, values := range selector.Exclude {
		if labelValue, exists := labels[key]; exists {
			for _, value := range values {
				if value == labelValue {
					return false, nil
				}
			}
		}
	}

	// Check inclusions
	for key, values := range selector.Include {
		labelValue, exists := labels[key]
		if !exists {
			return false, nil
		}

		found := false
		for _, value := range values {
			if value == labelValue {
				found = true
				break
			}
		}
		if !found {
			return false, nil
		}
	}

	return true, nil
}

// MatchesKind checks if a resource kind matches the rule criteria
func (m *resourceMatcher) MatchesKind(ctx context.Context, apiVersion, kind string, criteria *models.KubernetesResourceCriteria) (bool, error) {
	// Parse API version
	parts := strings.Split(apiVersion, "/")
	var group, version string
	if len(parts) == 1 {
		group = ""
		version = parts[0]
	} else {
		group = parts[0]
		version = parts[1]
	}

	// Check API group
	groupMatches := false
	for _, allowedGroup := range criteria.APIGroups {
		if allowedGroup == group {
			groupMatches = true
			break
		}
	}
	if !groupMatches {
		return false, nil
	}

	// Check version
	versionMatches := false
	for _, allowedVersion := range criteria.Versions {
		if allowedVersion == version {
			versionMatches = true
			break
		}
	}
	if !versionMatches {
		return false, nil
	}

	// Check kind
	kindMatches := false
	for _, allowedKind := range criteria.Kinds {
		if allowedKind == kind {
			kindMatches = true
			break
		}
	}

	return kindMatches, nil
}

// RuleCompiler implementation
type ruleCompiler struct {
	cache map[string]cel.Program
	mu    sync.RWMutex
}

// NewRuleCompiler creates a new rule compiler
func NewRuleCompiler() RuleCompiler {
	return &ruleCompiler{
		cache: make(map[string]cel.Program),
	}
}

// Compile compiles a CEL expression and caches the compiled program
func (c *ruleCompiler) Compile(ctx context.Context, ruleID string, program cel.Program) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache[ruleID] = program
	return nil
}

// GetCompiled retrieves a compiled CEL program
func (c *ruleCompiler) GetCompiled(ctx context.Context, ruleID string) (interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	program, exists := c.cache[ruleID]
	return program, exists
}

// ClearCache clears the compilation cache
func (c *ruleCompiler) ClearCache(ctx context.Context) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache = make(map[string]cel.Program)
}

// GetCacheStats returns cache statistics
func (c *ruleCompiler) GetCacheStats(ctx context.Context) map[string]interface{} {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return map[string]interface{}{
		"size": len(c.cache),
	}
}
