package vap

import (
	"fmt"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExportOptions contains options for exporting to ValidatingAdmissionPolicy
type ExportOptions struct {
	// Namespace for the policy binding (empty for cluster-wide)
	Namespace string
	// ValidationActions specifies how validation failures are handled
	ValidationActions []admissionregistrationv1.ValidationAction
	// FailurePolicy specifies how failures are handled
	FailurePolicy *admissionregistrationv1.FailurePolicyType
	// NamespaceSelector for scoping the policy
	NamespaceSelector *metav1.LabelSelector
	// ObjectSelector for additional resource filtering
	ObjectSelector *metav1.LabelSelector
}

// DefaultExportOptions returns default export options
func DefaultExportOptions() *ExportOptions {
	failurePolicy := admissionregistrationv1.Fail
	return &ExportOptions{
		ValidationActions: []admissionregistrationv1.ValidationAction{
			admissionregistrationv1.Deny,
		},
		FailurePolicy: &failurePolicy,
	}
}

// ExportRuleToVAP converts a SpotterRule to ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding
func ExportRuleToVAP(rule *models.SpotterRule, options *ExportOptions) (*admissionregistrationv1.ValidatingAdmissionPolicy, *admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	if rule == nil {
		return nil, nil, fmt.Errorf("rule cannot be nil")
	}

	if options == nil {
		options = DefaultExportOptions()
	}

	// Create ValidatingAdmissionPolicy
	vap := &admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: generateVAPName(rule),
			Annotations: map[string]string{
				"spotter.dev/rule-id":          rule.GetID(),
				"spotter.dev/rule-title":       rule.GetTitle(),
				"spotter.dev/rule-version":     rule.GetVersion(),
				"spotter.dev/rule-description": rule.GetDescription(),
				"spotter.dev/rule-severity":    rule.GetSeverity(),
				"spotter.dev/rule-category":    rule.GetCategory(),
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy: options.FailurePolicy,
			MatchConstraints: convertMatchConstraints(rule.Spec.Match),
			Validations: []admissionregistrationv1.Validation{
				{
					Expression: convertCELExpression(rule.Spec.CEL),
					Message:    generateValidationMessage(rule),
				},
			},
		},
	}

	// Add CWE annotation if present
	if cwe := rule.GetCWE(); cwe != "" {
		vap.Annotations["spotter.dev/rule-cwe"] = cwe
	}

	// Create ValidatingAdmissionPolicyBinding
	vapb := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicyBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: generateVAPBindingName(rule),
			Annotations: map[string]string{
				"spotter.dev/rule-id": rule.GetID(),
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        vap.Name,
			ValidationActions: options.ValidationActions,
		},
	}

	// Set namespace if specified
	if options.Namespace != "" {
		vapb.Namespace = options.Namespace
	}

	// Configure match resources
	matchResources := &admissionregistrationv1.MatchResources{}
	
	// Set namespace selector
	if options.NamespaceSelector != nil {
		matchResources.NamespaceSelector = options.NamespaceSelector
	} else if rule.Spec.Match.Resources.Kubernetes.Namespaces != nil {
		matchResources.NamespaceSelector = convertNamespaceSelector(rule.Spec.Match.Resources.Kubernetes.Namespaces)
	}

	// Set object selector
	if options.ObjectSelector != nil {
		matchResources.ObjectSelector = options.ObjectSelector
	} else if rule.Spec.Match.Resources.Kubernetes.Labels != nil {
		matchResources.ObjectSelector = convertLabelSelector(rule.Spec.Match.Resources.Kubernetes.Labels)
	}

	// Set resource rules (same as match constraints in VAP)
	matchResources.ResourceRules = convertMatchConstraints(rule.Spec.Match).ResourceRules

	vapb.Spec.MatchResources = matchResources

	return vap, vapb, nil
}

// generateVAPName generates a ValidatingAdmissionPolicy name from a rule
func generateVAPName(rule *models.SpotterRule) string {
	// Use rule ID as base, ensure it's a valid Kubernetes name
	name := strings.ToLower(rule.GetID())
	name = strings.ReplaceAll(name, "_", "-")
	return fmt.Sprintf("%s.spotter.dev", name)
}

// generateVAPBindingName generates a ValidatingAdmissionPolicyBinding name from a rule
func generateVAPBindingName(rule *models.SpotterRule) string {
	return fmt.Sprintf("%s-binding.spotter.dev", strings.ToLower(rule.GetID()))
}

// generateValidationMessage generates a validation message for the rule
func generateValidationMessage(rule *models.SpotterRule) string {
	title := rule.GetTitle()
	if title == "" {
		title = rule.GetID()
	}
	return fmt.Sprintf("Spotter rule '%s' validation failed", title)
}

// convertMatchConstraints converts Spotter match criteria to VAP match constraints
func convertMatchConstraints(match models.MatchCriteria) *admissionregistrationv1.MatchResources {
	k8sMatch := match.Resources.Kubernetes
	
	resourceRules := []admissionregistrationv1.NamedRuleWithOperations{}
	
	// Convert API groups, versions, and kinds
	for _, kind := range k8sMatch.Kinds {
		rule := admissionregistrationv1.NamedRuleWithOperations{
			RuleWithOperations: admissionregistrationv1.RuleWithOperations{
				Operations: []admissionregistrationv1.OperationType{
					admissionregistrationv1.Create,
					admissionregistrationv1.Update,
				},
				Rule: admissionregistrationv1.Rule{
					APIGroups:   k8sMatch.APIGroups,
					APIVersions: k8sMatch.Versions,
					Resources:   []string{strings.ToLower(kind) + "s"}, // Pluralize resource name
				},
			},
		}
		resourceRules = append(resourceRules, rule)
	}

	return &admissionregistrationv1.MatchResources{
		ResourceRules: resourceRules,
	}
}

// convertNamespaceSelector converts Spotter namespace selector to Kubernetes label selector
func convertNamespaceSelector(ns *models.NamespaceSelector) *metav1.LabelSelector {
	if ns == nil {
		return nil
	}

	selector := &metav1.LabelSelector{}

	// Handle include patterns
	if len(ns.Include) > 0 {
		// If includes contain wildcard, don't add restrictions
		hasWildcard := false
		for _, include := range ns.Include {
			if include == "*" {
				hasWildcard = true
				break
			}
		}
		
		if !hasWildcard {
			// Create matchExpressions for included namespaces
			selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      "kubernetes.io/metadata.name",
				Operator: metav1.LabelSelectorOpIn,
				Values:   ns.Include,
			})
		}
	}

	// Handle exclude patterns
	if len(ns.Exclude) > 0 {
		selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{
			Key:      "kubernetes.io/metadata.name",
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   ns.Exclude,
		})
	}

	return selector
}

// convertLabelSelector converts Spotter label selector to Kubernetes label selector
func convertLabelSelector(ls *models.LabelSelector) *metav1.LabelSelector {
	if ls == nil {
		return nil
	}

	selector := &metav1.LabelSelector{
		MatchLabels: make(map[string]string),
	}

	// Handle include labels
	for key, values := range ls.Include {
		if len(values) == 1 {
			// Single value - use matchLabels
			selector.MatchLabels[key] = values[0]
		} else if len(values) > 1 {
			// Multiple values - use matchExpressions
			selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{
				Key:      key,
				Operator: metav1.LabelSelectorOpIn,
				Values:   values,
			})
		}
	}

	// Handle exclude labels
	for key, values := range ls.Exclude {
		selector.MatchExpressions = append(selector.MatchExpressions, metav1.LabelSelectorRequirement{
			Key:      key,
			Operator: metav1.LabelSelectorOpNotIn,
			Values:   values,
		})
	}

	return selector
}

// convertCELExpression converts Spotter CEL expression to VAP-compatible CEL
func convertCELExpression(celExpr string) string {
	// Spotter CEL expressions should be mostly compatible with VAP CEL
	// The main difference is that VAP uses 'object' and 'oldObject' variables
	// while Spotter uses 'object' primarily
	
	// For now, return the expression as-is since Spotter already uses
	// the 'object' variable which is compatible with VAP
	// Future enhancements could include more sophisticated transformations
	return celExpr
}