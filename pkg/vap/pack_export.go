package vap

import (
	"fmt"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// PackExportResult contains the result of exporting a rule pack to VAP
type PackExportResult struct {
	Policies []admissionregistrationv1.ValidatingAdmissionPolicy
	Bindings []admissionregistrationv1.ValidatingAdmissionPolicyBinding
	Errors   []error
}

// PackExportOptions contains options for exporting rule packs to VAP
type PackExportOptions struct {
	// Base export options applied to all rules
	BaseOptions *ExportOptions
	// RuleSpecificOptions allows customizing options per rule ID
	RuleSpecificOptions map[string]*ExportOptions
	// GroupByCategory creates separate policies for each category
	GroupByCategory bool
	// GroupBySeverity creates separate policies for each severity level
	GroupBySeverity bool
	// NamePrefix adds a prefix to all generated policy names
	NamePrefix string
}

// DefaultPackExportOptions returns default pack export options
func DefaultPackExportOptions() *PackExportOptions {
	return &PackExportOptions{
		BaseOptions:         DefaultExportOptions(),
		RuleSpecificOptions: make(map[string]*ExportOptions),
		GroupByCategory:     false,
		GroupBySeverity:     false,
	}
}

// ExportRulePackToVAP converts a SpotterRulePack and its rules to ValidatingAdmissionPolicy resources
func ExportRulePackToVAP(pack *models.SpotterRulePack, rules []*models.SpotterRule, options *PackExportOptions) (*PackExportResult, error) {
	if pack == nil {
		return nil, fmt.Errorf("rule pack cannot be nil")
	}

	if options == nil {
		options = DefaultPackExportOptions()
	}

	result := &PackExportResult{
		Policies: []admissionregistrationv1.ValidatingAdmissionPolicy{},
		Bindings: []admissionregistrationv1.ValidatingAdmissionPolicyBinding{},
		Errors:   []error{},
	}

	// Create a map of rule ID to rule for quick lookup
	ruleMap := make(map[string]*models.SpotterRule)
	for _, rule := range rules {
		ruleMap[rule.GetID()] = rule
	}

	// Group rules based on options
	if options.GroupByCategory || options.GroupBySeverity {
		return exportGroupedRules(pack, ruleMap, options)
	}

	// Export each rule individually
	for _, ruleID := range pack.Spec.Rules {
		rule, exists := ruleMap[ruleID]
		if !exists {
			result.Errors = append(result.Errors, fmt.Errorf("rule %s not found", ruleID))
			continue
		}

		// Get options for this specific rule
		ruleOptions := options.BaseOptions
		if specificOptions, exists := options.RuleSpecificOptions[ruleID]; exists {
			ruleOptions = specificOptions
		}

		// Export the rule
		vap, vapb, err := ExportRuleToVAP(rule, ruleOptions)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to export rule %s: %w", ruleID, err))
			continue
		}

		// Apply name prefix if specified
		if options.NamePrefix != "" {
			vap.Name = fmt.Sprintf("%s-%s", options.NamePrefix, vap.Name)
			vapb.Name = fmt.Sprintf("%s-%s", options.NamePrefix, vapb.Name)
			vapb.Spec.PolicyName = vap.Name
		}

		// Add pack metadata to annotations
		if vap.Annotations == nil {
			vap.Annotations = make(map[string]string)
		}
		vap.Annotations["spotter.dev/pack-id"] = pack.GetID()
		vap.Annotations["spotter.dev/pack-title"] = pack.GetTitle()
		vap.Annotations["spotter.dev/pack-version"] = pack.GetVersion()

		if vapb.Annotations == nil {
			vapb.Annotations = make(map[string]string)
		}
		vapb.Annotations["spotter.dev/pack-id"] = pack.GetID()

		result.Policies = append(result.Policies, *vap)
		result.Bindings = append(result.Bindings, *vapb)
	}

	return result, nil
}

// exportGroupedRules exports rules grouped by category or severity
func exportGroupedRules(pack *models.SpotterRulePack, ruleMap map[string]*models.SpotterRule, options *PackExportOptions) (*PackExportResult, error) {
	result := &PackExportResult{
		Policies: []admissionregistrationv1.ValidatingAdmissionPolicy{},
		Bindings: []admissionregistrationv1.ValidatingAdmissionPolicyBinding{},
		Errors:   []error{},
	}

	// Group rules
	groups := make(map[string][]*models.SpotterRule)
	for _, ruleID := range pack.Spec.Rules {
		rule, exists := ruleMap[ruleID]
		if !exists {
			result.Errors = append(result.Errors, fmt.Errorf("rule %s not found", ruleID))
			continue
		}

		var groupKey string
		if options.GroupByCategory {
			groupKey = rule.GetCategory()
		} else if options.GroupBySeverity {
			groupKey = rule.GetSeverity()
		}

		if groupKey == "" {
			groupKey = "default"
		}

		groups[groupKey] = append(groups[groupKey], rule)
	}

	// Create policies for each group
	for groupKey, groupRules := range groups {
		vap, vapb, err := createGroupedPolicy(pack, groupKey, groupRules, options)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("failed to create grouped policy for %s: %w", groupKey, err))
			continue
		}

		result.Policies = append(result.Policies, *vap)
		result.Bindings = append(result.Bindings, *vapb)
	}

	return result, nil
}

// createGroupedPolicy creates a single VAP that combines multiple rules
func createGroupedPolicy(pack *models.SpotterRulePack, groupKey string, rules []*models.SpotterRule, options *PackExportOptions) (*admissionregistrationv1.ValidatingAdmissionPolicy, *admissionregistrationv1.ValidatingAdmissionPolicyBinding, error) {
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("no rules in group %s", groupKey)
	}

	// Generate names for the grouped policy
	groupName := strings.ToLower(strings.ReplaceAll(groupKey, " ", "-"))
	packName := strings.ToLower(pack.GetID())
	policyName := fmt.Sprintf("%s-%s.spotter.dev", packName, groupName)
	bindingName := fmt.Sprintf("%s-%s-binding.spotter.dev", packName, groupName)

	// Apply name prefix if specified
	if options.NamePrefix != "" {
		policyName = fmt.Sprintf("%s-%s", options.NamePrefix, policyName)
		bindingName = fmt.Sprintf("%s-%s", options.NamePrefix, bindingName)
	}

	// Collect all validations from rules in the group
	validations := []admissionregistrationv1.Validation{}
	ruleIDs := []string{}
	for _, rule := range rules {
		validation := admissionregistrationv1.Validation{
			Expression: convertCELExpression(rule.Spec.CEL),
			Message:    fmt.Sprintf("Spotter rule '%s' validation failed", rule.GetTitle()),
		}
		validations = append(validations, validation)
		ruleIDs = append(ruleIDs, rule.GetID())
	}

	// Merge match constraints from all rules
	matchConstraints := mergeMatchConstraints(rules)

	// Create the grouped policy
	vap := &admissionregistrationv1.ValidatingAdmissionPolicy{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicy",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: policyName,
			Annotations: map[string]string{
				"spotter.dev/pack-id":          pack.GetID(),
				"spotter.dev/pack-title":       pack.GetTitle(),
				"spotter.dev/pack-version":     pack.GetVersion(),
				"spotter.dev/group-key":        groupKey,
				"spotter.dev/rule-ids":         strings.Join(ruleIDs, ","),
				"spotter.dev/rule-count":       fmt.Sprintf("%d", len(rules)),
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicySpec{
			FailurePolicy:    options.BaseOptions.FailurePolicy,
			MatchConstraints: matchConstraints,
			Validations:      validations,
		},
	}

	// Create the binding
	vapb := &admissionregistrationv1.ValidatingAdmissionPolicyBinding{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "admissionregistration.k8s.io/v1",
			Kind:       "ValidatingAdmissionPolicyBinding",
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: bindingName,
			Annotations: map[string]string{
				"spotter.dev/pack-id":   pack.GetID(),
				"spotter.dev/group-key": groupKey,
			},
		},
		Spec: admissionregistrationv1.ValidatingAdmissionPolicyBindingSpec{
			PolicyName:        vap.Name,
			ValidationActions: options.BaseOptions.ValidationActions,
		},
	}

	// Configure match resources for the binding
	matchResources := &admissionregistrationv1.MatchResources{
		ResourceRules: matchConstraints.ResourceRules,
	}

	// Set namespace selector if specified in options
	if options.BaseOptions.NamespaceSelector != nil {
		matchResources.NamespaceSelector = options.BaseOptions.NamespaceSelector
	}

	// Set object selector if specified in options
	if options.BaseOptions.ObjectSelector != nil {
		matchResources.ObjectSelector = options.BaseOptions.ObjectSelector
	}

	vapb.Spec.MatchResources = matchResources

	return vap, vapb, nil
}

// mergeMatchConstraints merges match constraints from multiple rules
func mergeMatchConstraints(rules []*models.SpotterRule) *admissionregistrationv1.MatchResources {
	// Collect all unique resource rules
	resourceRulesMap := make(map[string]admissionregistrationv1.NamedRuleWithOperations)

	for _, rule := range rules {
		matchConstraints := convertMatchConstraints(rule.Spec.Match)
		for _, resourceRule := range matchConstraints.ResourceRules {
			// Create a unique key for the resource rule
			key := fmt.Sprintf("%v-%v-%v",
				resourceRule.APIGroups,
				resourceRule.APIVersions,
				resourceRule.Resources,
			)
			resourceRulesMap[key] = resourceRule
		}
	}

	// Convert map back to slice
	resourceRules := make([]admissionregistrationv1.NamedRuleWithOperations, 0, len(resourceRulesMap))
	for _, rule := range resourceRulesMap {
		resourceRules = append(resourceRules, rule)
	}

	return &admissionregistrationv1.MatchResources{
		ResourceRules: resourceRules,
	}
}