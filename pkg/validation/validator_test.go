package validation

import (
	"strings"
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
)

func TestValidateSpotterRule(t *testing.T) {
	tests := []struct {
		name       string
		rule       *models.SpotterRule
		wantValid  bool
		wantErrors []string
	}{
		{
			name: "valid rule",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Labels: map[string]string{
						"severity": "high",
						"category": "workload",
					},
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Container is privileged",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Checks if container is running in privileged mode",
					},
				},
				Spec: models.RuleSpec{
					Match: models.MatchCriteria{
						Resources: models.ResourceCriteria{
							Kubernetes: models.KubernetesResourceCriteria{
								APIGroups: []string{""},
								Versions:  []string{"v1"},
								Kinds:     []string{"Pod"},
							},
						},
					},
					CEL: "object.spec.containers.exists(c, has(c.securityContext) && has(c.securityContext.privileged) && c.securityContext.privileged == true)",
				},
			},
			wantValid:  true,
			wantErrors: nil,
		},
		{
			name: "invalid apiVersion",
			rule: &models.SpotterRule{
				APIVersion: "v1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
				},
			},
			wantValid: false,
			wantErrors: []string{
				"apiVersion: must be 'rules.spotter.dev/v1alpha1'",
				"metadata.annotations: annotations are required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "invalid kind",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "Rule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
				},
			},
			wantValid: false,
			wantErrors: []string{
				"kind: must be 'SpotterRule'",
				"metadata.annotations: annotations are required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "missing name",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata:   models.RuleMetadata{},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.name: name is required",
				"metadata.annotations: annotations are required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "invalid name format",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "invalid-name",
				},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.name: name must match pattern: spotter-[category]-[number] (e.g., spotter-workload-001)",
				"metadata.annotations: annotations are required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "missing annotations",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
				},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.annotations: annotations are required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "missing required annotations",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name:        "spotter-workload-001",
					Annotations: map[string]string{},
				},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.annotations['rules.spotter.dev/title']: title annotation is required",
				"metadata.annotations['rules.spotter.dev/version']: version annotation is required",
				"metadata.annotations['rules.spotter.dev/description']: description annotation is required",
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "missing labels",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.labels: labels are required",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "invalid severity",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Labels: map[string]string{
						"severity": "invalid",
						"category": "workload",
					},
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
			},
			wantValid: false,
			wantErrors: []string{
				"metadata.labels.severity: severity must be one of: low, medium, high, critical",
				"spec.cel: CEL expression is required",
				"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified",
			},
		},
		{
			name: "missing CEL expression",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Labels: map[string]string{
						"severity": "high",
						"category": "workload",
					},
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
				Spec: models.RuleSpec{
					Match: models.MatchCriteria{
						Resources: models.ResourceCriteria{
							Kubernetes: models.KubernetesResourceCriteria{
								Kinds: []string{"Pod"},
							},
						},
					},
				},
			},
			wantValid:  false,
			wantErrors: []string{"spec.cel: CEL expression is required"},
		},
		{
			name: "invalid CEL expression",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Labels: map[string]string{
						"severity": "high",
						"category": "workload",
					},
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
				Spec: models.RuleSpec{
					Match: models.MatchCriteria{
						Resources: models.ResourceCriteria{
							Kubernetes: models.KubernetesResourceCriteria{
								Kinds: []string{"Pod"},
							},
						},
					},
					CEL: "invalid syntax (",
				},
			},
			wantValid:  false,
			wantErrors: []string{"spec.cel: invalid CEL expression"},
		},
		{
			name: "missing kubernetes kinds",
			rule: &models.SpotterRule{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRule",
				Metadata: models.RuleMetadata{
					Name: "spotter-workload-001",
					Labels: map[string]string{
						"severity": "high",
						"category": "workload",
					},
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
				Spec: models.RuleSpec{
					CEL: "true",
					Match: models.MatchCriteria{
						Resources: models.ResourceCriteria{
							Kubernetes: models.KubernetesResourceCriteria{},
						},
					},
				},
			},
			wantValid:  false,
			wantErrors: []string{"spec.match.resources.kubernetes.kinds: at least one Kubernetes kind must be specified"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSpotterRule(tt.rule)
			if result.Valid != tt.wantValid {
				t.Errorf("ValidateSpotterRule() valid = %v, want %v", result.Valid, tt.wantValid)
			}

			if tt.wantErrors != nil {
				if len(result.Errors) != len(tt.wantErrors) {
					t.Errorf("ValidateSpotterRule() errors count = %d, want %d", len(result.Errors), len(tt.wantErrors))
					return
				}

				for i, wantError := range tt.wantErrors {
					if i < len(result.Errors) {
						gotError := result.Errors[i].Error()
						if !contains(gotError, wantError) {
							t.Errorf("ValidateSpotterRule() error[%d] = %v, want to contain %v", i, gotError, wantError)
						}
					}
				}
			}
		})
	}
}

func TestValidateSpotterRulePack(t *testing.T) {
	tests := []struct {
		name       string
		rulePack   *models.SpotterRulePack
		wantValid  bool
		wantErrors []string
	}{
		{
			name: "valid rule pack",
			rulePack: &models.SpotterRulePack{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRulePack",
				Metadata: models.RuleMetadata{
					Name: "spotter-cis-kubernetes-benchmark-pack",
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "CIS Kubernetes Benchmark",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "CIS Kubernetes Benchmark rules",
					},
				},
				Spec: models.RulePackSpec{
					Rules: []string{"spotter-workload-001", "spotter-platform-001"},
				},
			},
			wantValid:  true,
			wantErrors: nil,
		},
		{
			name: "invalid apiVersion",
			rulePack: &models.SpotterRulePack{
				APIVersion: "v1",
				Kind:       "SpotterRulePack",
			},
			wantValid:  false,
			wantErrors: []string{"apiVersion: must be 'rules.spotter.dev/v1alpha1'"},
		},
		{
			name: "invalid kind",
			rulePack: &models.SpotterRulePack{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "RulePack",
			},
			wantValid:  false,
			wantErrors: []string{"kind: must be 'SpotterRulePack'"},
		},
		{
			name: "invalid name format",
			rulePack: &models.SpotterRulePack{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRulePack",
				Metadata: models.RuleMetadata{
					Name: "invalid-name",
				},
			},
			wantValid:  false,
			wantErrors: []string{"metadata.name: name must end with '-pack'"},
		},
		{
			name: "missing rules",
			rulePack: &models.SpotterRulePack{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRulePack",
				Metadata: models.RuleMetadata{
					Name: "test-pack",
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
				Spec: models.RulePackSpec{
					Rules: []string{},
				},
			},
			wantValid:  false,
			wantErrors: []string{"spec.rules: at least one rule must be specified"},
		},
		{
			name: "invalid rule ID format",
			rulePack: &models.SpotterRulePack{
				APIVersion: "rules.spotter.dev/v1alpha1",
				Kind:       "SpotterRulePack",
				Metadata: models.RuleMetadata{
					Name: "test-pack",
					Annotations: map[string]string{
						"rules.spotter.dev/title":       "Test",
						"rules.spotter.dev/version":     "1.0.0",
						"rules.spotter.dev/description": "Test description",
					},
				},
				Spec: models.RulePackSpec{
					Rules: []string{"invalid-rule-id"},
				},
			},
			wantValid:  false,
			wantErrors: []string{"spec.rules[0]: rule ID 'invalid-rule-id' must match pattern: spotter-[category]-[number]"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidateSpotterRulePack(tt.rulePack)
			if result.Valid != tt.wantValid {
				t.Errorf("ValidateSpotterRulePack() valid = %v, want %v", result.Valid, tt.wantValid)
			}

			if tt.wantErrors != nil {
				if len(result.Errors) < len(tt.wantErrors) {
					t.Errorf("ValidateSpotterRulePack() errors count = %d, want at least %d", len(result.Errors), len(tt.wantErrors))
					return
				}

				for i, wantError := range tt.wantErrors {
					if i < len(result.Errors) {
						gotError := result.Errors[i].Error()
						if !contains(gotError, wantError) {
							t.Errorf("ValidateSpotterRulePack() error[%d] = %v, want to contain %v", i, gotError, wantError)
						}
					}
				}
			}
		})
	}
}

func TestValidateCELExpression(t *testing.T) {
	tests := []struct {
		name       string
		expression string
		wantError  bool
	}{
		{
			name:       "valid boolean expression",
			expression: "true",
			wantError:  false,
		},
		{
			name:       "valid object access",
			expression: "has(object.spec)",
			wantError:  false,
		},
		{
			name:       "valid complex expression",
			expression: "object.spec.containers.exists(c, has(c.securityContext) && c.securityContext.privileged == true)",
			wantError:  false,
		},
		{
			name:       "invalid syntax",
			expression: "invalid syntax (",
			wantError:  true,
		},
		{
			name:       "non-boolean return type",
			expression: "'string'",
			wantError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateCELExpression(tt.expression)
			if (err != nil) != tt.wantError {
				t.Errorf("validateCELExpression() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

func TestIsValidRuleName(t *testing.T) {
	tests := []struct {
		name     string
		ruleName string
		want     bool
	}{
		{"valid single category", "spotter-workload-001", true},
		{"valid multi category", "spotter-network-security-001", true},
		{"valid platform", "spotter-platform-001", true},
		{"invalid no prefix", "workload-001", false},
		{"invalid no number", "spotter-workload", false},
		{"invalid wrong format", "spotter-workload-abc", false},
		{"invalid uppercase", "spotter-Workload-001", false},
		{"invalid short number", "spotter-workload-01", false},
		{"invalid long number", "spotter-workload-0001", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidRuleName(tt.ruleName); got != tt.want {
				t.Errorf("isValidRuleName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsValidRulePackName(t *testing.T) {
	tests := []struct {
		name         string
		rulePackName string
		want         bool
	}{
		{"valid pack name", "spotter-cis-kubernetes-benchmark-pack", true},
		{"valid simple pack", "test-pack", true},
		{"invalid no pack suffix", "spotter-cis-kubernetes-benchmark", false},
		{"invalid empty", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isValidRulePackName(tt.rulePackName); got != tt.want {
				t.Errorf("isValidRulePackName() = %v, want %v", got, tt.want)
			}
		})
	}
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr ||
		(len(s) > len(substr) &&
			(s[:len(substr)] == substr ||
				s[len(s)-len(substr):] == substr ||
				strings.Contains(s, substr))))
}
