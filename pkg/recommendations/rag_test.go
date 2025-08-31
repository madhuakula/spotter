package recommendations

import (
	"context"
	"strings"
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
)

func TestLoadRuleContexts_EmptyRules(t *testing.T) {
	ctx := context.Background()
	m, err := LoadRuleContexts(ctx, []*models.SpotterRule{})
	if err != nil {
		t.Fatalf("LoadRuleContexts error: %v", err)
	}
	if len(m) != 0 {
		t.Fatalf("expected empty map for empty rules, got %d", len(m))
	}
}

func TestLoadRuleContexts_WithRules(t *testing.T) {
	ctx := context.Background()

	// Create test rules
	rules := []*models.SpotterRule{
		{
			Metadata: models.RuleMetadata{
				Name: "test-rule-1",
				Labels: map[string]string{
					"category": "workload",
				},
				Annotations: map[string]string{
					"rules.spotter.dev/description": "Test rule description",
				},
			},
			Spec: models.RuleSpec{
				Remediation: &models.Remediation{
					Manual: "Fix this issue manually",
				},
			},
		},
		{
			Metadata: models.RuleMetadata{
				Name: "test-rule-2",
				Labels: map[string]string{
					"category": "config",
				},
				Annotations: map[string]string{
					"rules.spotter.dev/description": "Another test rule",
				},
			},
			Spec: models.RuleSpec{
				Remediation: nil, // Test case with no remediation
			},
		},
	}

	m, err := LoadRuleContexts(ctx, rules)
	if err != nil {
		t.Fatalf("LoadRuleContexts error: %v", err)
	}

	if len(m) != 2 {
		t.Fatalf("expected 2 rules in map, got %d", len(m))
	}

	// Test first rule
	rule1, exists := m["test-rule-1"]
	if !exists {
		t.Fatalf("expected rule test-rule-1 to exist in map")
	}
	if rule1.ID != "test-rule-1" {
		t.Errorf("expected ID test-rule-1, got %s", rule1.ID)
	}
	if rule1.Name != "test-rule-1" {
		t.Errorf("expected Name test-rule-1, got %s", rule1.Name)
	}
	if rule1.Category != "workload" {
		t.Errorf("expected Category workload, got %s", rule1.Category)
	}
	if rule1.Description != "Test rule description" {
		t.Errorf("expected Description 'Test rule description', got %s", rule1.Description)
	}
	if rule1.Remediation != "Fix this issue manually" {
		t.Errorf("expected Remediation 'Fix this issue manually', got %s", rule1.Remediation)
	}

	// Test second rule (no remediation)
	rule2, exists := m["test-rule-2"]
	if !exists {
		t.Fatalf("expected rule test-rule-2 to exist in map")
	}
	if rule2.Remediation != "" {
		t.Errorf("expected empty Remediation, got %s", rule2.Remediation)
	}
}

func TestLoadRuleContexts_WithNilRules(t *testing.T) {
	ctx := context.Background()

	// Create test rules with nil entries
	rules := []*models.SpotterRule{
		{
			Metadata: models.RuleMetadata{
				Name: "valid-rule",
				Labels: map[string]string{
					"category": "workload",
				},
			},
		},
		nil, // This should be skipped
		{
			Metadata: models.RuleMetadata{
				Name: "another-valid-rule",
				Labels: map[string]string{
					"category": "config",
				},
			},
		},
	}

	m, err := LoadRuleContexts(ctx, rules)
	if err != nil {
		t.Fatalf("LoadRuleContexts error: %v", err)
	}

	// Should only have 2 rules (nil rule should be skipped)
	if len(m) != 2 {
		t.Fatalf("expected 2 rules in map (nil should be skipped), got %d", len(m))
	}

	if _, exists := m["valid-rule"]; !exists {
		t.Errorf("expected valid-rule to exist")
	}
	if _, exists := m["another-valid-rule"]; !exists {
		t.Errorf("expected another-valid-rule to exist")
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		limit    int
		expected string
	}{
		{
			name:     "empty string",
			input:    "",
			limit:    10,
			expected: "",
		},
		{
			name:     "zero limit",
			input:    "test string",
			limit:    0,
			expected: "test string",
		},
		{
			name:     "negative limit",
			input:    "test string",
			limit:    -5,
			expected: "test string",
		},
		{
			name:     "string shorter than limit",
			input:    "short",
			limit:    10,
			expected: "short",
		},
		{
			name:     "string equal to limit",
			input:    "exactly10c",
			limit:    10,
			expected: "exactly10c",
		},
		{
			name:     "string longer than limit - word boundary",
			input:    "this is a long string that needs truncation",
			limit:    20,
			expected: "this is a long…",
		},
		{
			name:     "string longer than limit - no spaces",
			input:    "verylongstringwithoutspaces",
			limit:    10,
			expected: "verylongst…",
		},
		{
			name:     "string longer than limit - space at end",
			input:    "this is exactly twenty characters",
			limit:    20,
			expected: "this is exactly…",
		},
		{
			name:     "string with no word boundary within limit",
			input:    "supercalifragilisticexpialidocious",
			limit:    15,
			expected: "supercalifragil…",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := truncate(tt.input, tt.limit)
			if result != tt.expected {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.input, tt.limit, result, tt.expected)
			}
		})
	}
}

func TestLoadRuleContexts_LongDescriptionTruncation(t *testing.T) {
	ctx := context.Background()

	longDescription := "This is a very long description that should be truncated because it exceeds the 600 character limit. " +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. " +
		"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam."

	longRemediation := "This is a very long remediation text that should also be truncated because it exceeds the 600 character limit. " +
		"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. " +
		"Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. " +
		"Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. " +
		"Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. " +
		"Sed ut perspiciatis unde omnis iste natus error sit voluptatem accusantium doloremque laudantium, totam rem aperiam."

	rules := []*models.SpotterRule{
		{
			Metadata: models.RuleMetadata{
				Name: "long-text-rule",
				Annotations: map[string]string{
					"rules.spotter.dev/description": longDescription,
				},
			},
			Spec: models.RuleSpec{
				Remediation: &models.Remediation{
					Manual: longRemediation,
				},
			},
		},
	}

	m, err := LoadRuleContexts(ctx, rules)
	if err != nil {
		t.Fatalf("LoadRuleContexts error: %v", err)
	}

	rule, exists := m["long-text-rule"]
	if !exists {
		t.Fatalf("expected rule long-text-rule to exist")
	}

	// Check that description was truncated (should be <= 600 + ellipsis)
	if len(rule.Description) > 605 { // Allow some margin for the ellipsis and word boundary
		t.Errorf("expected description to be truncated to reasonable length, got %d", len(rule.Description))
	}
	if len(rule.Description) >= len(longDescription) {
		t.Errorf("expected description to be shorter than original, got %d vs %d", len(rule.Description), len(longDescription))
	}
	if !strings.HasSuffix(rule.Description, "…") {
		t.Errorf("expected truncated description to end with ellipsis")
	}

	// Check that remediation was truncated (should be <= 600 + ellipsis)
	if len(rule.Remediation) > 605 { // Allow some margin for the ellipsis and word boundary
		t.Errorf("expected remediation to be truncated to reasonable length, got %d", len(rule.Remediation))
	}
	if len(rule.Remediation) >= len(longRemediation) {
		t.Errorf("expected remediation to be shorter than original, got %d vs %d", len(rule.Remediation), len(longRemediation))
	}
	if !strings.HasSuffix(rule.Remediation, "…") {
		t.Errorf("expected truncated remediation to end with ellipsis")
	}
}
