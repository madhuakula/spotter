package validation

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/google/cel-go/cel"
	"github.com/madhuakula/spotter/pkg/models"
)

// ValidationError represents a validation error
type ValidationError struct {
	Field   string `json:"field"`
	Message string `json:"message"`
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// ValidationResult represents the result of validation
type ValidationResult struct {
	Valid  bool              `json:"valid"`
	Errors []ValidationError `json:"errors,omitempty"`
}

// ValidateSpotterRule validates a SpotterRule struct
func ValidateSpotterRule(rule *models.SpotterRule) ValidationResult {
	var errors []ValidationError

	// Validate APIVersion
	if rule.APIVersion != "rules.spotter.dev/v1alpha1" {
		errors = append(errors, ValidationError{
			Field:   "apiVersion",
			Message: "must be 'rules.spotter.dev/v1alpha1'",
		})
	}

	// Validate Kind
	if rule.Kind != "SpotterRule" {
		errors = append(errors, ValidationError{
			Field:   "kind",
			Message: "must be 'SpotterRule'",
		})
	}

	// Validate metadata
	if rule.Metadata.Name == "" {
		errors = append(errors, ValidationError{
			Field:   "metadata.name",
			Message: "name is required",
		})
	} else if !isValidRuleName(rule.Metadata.Name) {
		errors = append(errors, ValidationError{
			Field:   "metadata.name",
			Message: "name must match pattern: spotter-[category]-[number] (e.g., spotter-workload-001)",
		})
	}

	// Validate required annotations
	if rule.Metadata.Annotations == nil {
		errors = append(errors, ValidationError{
			Field:   "metadata.annotations",
			Message: "annotations are required",
		})
	} else {
		if rule.GetTitle() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/title']",
				Message: "title annotation is required",
			})
		}
		if rule.GetVersion() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/version']",
				Message: "version annotation is required",
			})
		}
		if rule.GetDescription() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/description']",
				Message: "description annotation is required",
			})
		}
	}

	// Validate required labels
	if rule.Metadata.Labels == nil {
		errors = append(errors, ValidationError{
			Field:   "metadata.labels",
			Message: "labels are required",
		})
	} else {
		if rule.GetSeverity() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.labels['rules.spotter.dev/severity']",
				Message: "severity label is required",
			})
		} else if !models.SeverityLevel(rule.GetSeverity()).IsValid() {
			errors = append(errors, ValidationError{
				Field:   "metadata.labels['rules.spotter.dev/severity']",
				Message: "severity must be one of: low, medium, high, critical",
			})
		}
		if rule.GetCategory() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.labels['rules.spotter.dev/category']",
				Message: "category label is required",
			})
		}
	}

	// Validate spec
	if rule.Spec.CEL == "" {
		errors = append(errors, ValidationError{
			Field:   "spec.cel",
			Message: "CEL expression is required",
		})
	} else {
		// Validate CEL expression syntax
		if err := validateCELExpression(rule.Spec.CEL); err != nil {
			errors = append(errors, ValidationError{
				Field:   "spec.cel",
				Message: fmt.Sprintf("invalid CEL expression: %v", err),
			})
		}
	}

	// Validate match criteria
	if len(rule.Spec.Match.Resources.Kubernetes.Kinds) == 0 {
		errors = append(errors, ValidationError{
			Field:   "spec.match.resources.kubernetes.kinds",
			Message: "at least one Kubernetes kind must be specified",
		})
	}

	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

// ValidateSpotterRulePack validates a SpotterRulePack struct
func ValidateSpotterRulePack(rulePack *models.SpotterRulePack) ValidationResult {
	var errors []ValidationError

	// Validate APIVersion
	if rulePack.APIVersion != "rules.spotter.dev/v1alpha1" {
		errors = append(errors, ValidationError{
			Field:   "apiVersion",
			Message: "must be 'rules.spotter.dev/v1alpha1'",
		})
	}

	// Validate Kind
	if rulePack.Kind != "SpotterRulePack" {
		errors = append(errors, ValidationError{
			Field:   "kind",
			Message: "must be 'SpotterRulePack'",
		})
	}

	// Validate metadata
	if rulePack.Metadata.Name == "" {
		errors = append(errors, ValidationError{
			Field:   "metadata.name",
			Message: "name is required",
		})
	} else if !isValidRulePackName(rulePack.Metadata.Name) {
		errors = append(errors, ValidationError{
			Field:   "metadata.name",
			Message: "name must end with '-pack' (e.g., spotter-cis-kubernetes-benchmark-pack)",
		})
	}

	// Validate required annotations
	if rulePack.Metadata.Annotations == nil {
		errors = append(errors, ValidationError{
			Field:   "metadata.annotations",
			Message: "annotations are required",
		})
	} else {
		if rulePack.GetTitle() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/title']",
				Message: "title annotation is required",
			})
		}
		if rulePack.GetVersion() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/version']",
				Message: "version annotation is required",
			})
		}
		if rulePack.GetDescription() == "" {
			errors = append(errors, ValidationError{
				Field:   "metadata.annotations['rules.spotter.dev/description']",
				Message: "description annotation is required",
			})
		}
	}

	// Validate spec
	if len(rulePack.Spec.Rules) == 0 {
		errors = append(errors, ValidationError{
			Field:   "spec.rules",
			Message: "at least one rule must be specified",
		})
	} else {
		// Validate each rule ID format
		for i, ruleID := range rulePack.Spec.Rules {
			if !isValidRuleName(ruleID) {
				errors = append(errors, ValidationError{
					Field:   fmt.Sprintf("spec.rules[%d]", i),
					Message: fmt.Sprintf("rule ID '%s' must match pattern: spotter-[category]-[number]", ruleID),
				})
			}
		}
	}

	return ValidationResult{
		Valid:  len(errors) == 0,
		Errors: errors,
	}
}

// isValidRuleName validates rule name format: spotter-[category]-[number]
func isValidRuleName(name string) bool {
	pattern := `^spotter-[a-z]+(-[a-z]+)*-\d{3}$`
	matched, _ := regexp.MatchString(pattern, name)
	return matched
}

// isValidRulePackName validates rule pack name format: must end with '-pack'
func isValidRulePackName(name string) bool {
	return strings.HasSuffix(name, "-pack")
}

// validateCELExpression validates CEL expression syntax
func validateCELExpression(expression string) error {
	// Create a CEL environment with basic types
	env, err := cel.NewEnv(
		cel.Variable("object", cel.DynType),
		cel.Variable("oldObject", cel.DynType),
		cel.Variable("request", cel.DynType),
	)
	if err != nil {
		return fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Parse the expression
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return fmt.Errorf("CEL compilation error: %w", issues.Err())
	}

	// Check that the expression returns a boolean
	if !ast.OutputType().IsExactType(cel.BoolType) {
		return fmt.Errorf("CEL expression must return a boolean, got %s", ast.OutputType())
	}

	return nil
}