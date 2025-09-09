package graphstore

import (
	"testing"

	"github.com/madhuakula/spotter/pkg/models"
)

func TestFactExtractor_ExtractPodFacts(t *testing.T) {
	extractor := NewFactExtractor()

	// Test pod resource
	podResource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      "test-pod",
			"namespace": "default",
		},
		"spec": map[string]interface{}{
			"serviceAccountName": "test-sa",
			"volumes": []interface{}{
				map[string]interface{}{
					"name": "secret-vol",
					"secret": map[string]interface{}{
						"secretName": "test-secret",
					},
				},
			},
		},
	}

	facts := &models.GraphFacts{}
	err := extractor.extractFromResource(podResource, facts)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check pod fact
	if len(facts.Pods) != 1 {
		t.Fatalf("Expected 1 pod fact, got %d", len(facts.Pods))
	}

	pod := facts.Pods[0]
	if pod.ID != "default/test-pod" {
		t.Errorf("Expected pod ID 'default/test-pod', got '%s'", pod.ID)
	}
	if pod.Namespace != "default" {
		t.Errorf("Expected pod namespace 'default', got '%s'", pod.Namespace)
	}

	// Check relationships
	hasSecretRelation := false
	hasSARelation := false

	for _, rel := range facts.Relationships {
		if rel.Type == models.RelationshipUsesSecret && rel.FromID == "default/test-pod" && rel.ToID == "default/test-secret" {
			hasSecretRelation = true
		}
		if rel.Type == models.RelationshipUsesSA && rel.FromID == "default/test-pod" && rel.ToID == "default/test-sa" {
			hasSARelation = true
		}
	}

	if !hasSecretRelation {
		t.Error("Expected secret relationship not found")
	}
	if !hasSARelation {
		t.Error("Expected service account relationship not found")
	}
}

func TestFactExtractor_ExtractSecretFacts(t *testing.T) {
	extractor := NewFactExtractor()

	// Test credential-like secret
	secretResource := map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"type":       "kubernetes.io/service-account-token",
		"metadata": map[string]interface{}{
			"name":      "test-secret",
			"namespace": "default",
		},
	}

	facts := &models.GraphFacts{}
	err := extractor.extractFromResource(secretResource, facts)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check secret fact
	if len(facts.Secrets) != 1 {
		t.Fatalf("Expected 1 secret fact, got %d", len(facts.Secrets))
	}

	secret := facts.Secrets[0]
	if secret.ID != "default/test-secret" {
		t.Errorf("Expected secret ID 'default/test-secret', got '%s'", secret.ID)
	}
	if !secret.CredLike {
		t.Error("Expected secret to be credential-like")
	}
	if secret.Reason == "" {
		t.Error("Expected reason to be set for credential-like secret")
	}
}

func TestFactExtractor_ExtractRoleFacts(t *testing.T) {
	extractor := NewFactExtractor()

	// Test role resource
	roleResource := map[string]interface{}{
		"apiVersion": "rbac.authorization.k8s.io/v1",
		"kind":       "Role",
		"metadata": map[string]interface{}{
			"name":      "test-role",
			"namespace": "default",
		},
		"rules": []interface{}{
			map[string]interface{}{
				"resources": []interface{}{"secrets"},
				"verbs":     []interface{}{"get", "list"},
			},
		},
	}

	facts := &models.GraphFacts{}
	err := extractor.extractFromResource(roleResource, facts)

	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Check role fact
	if len(facts.Roles) != 1 {
		t.Fatalf("Expected 1 role fact, got %d", len(facts.Roles))
	}

	role := facts.Roles[0]
	if role.ID != "default/test-role" {
		t.Errorf("Expected role ID 'default/test-role', got '%s'", role.ID)
	}

	// Check API permissions
	if len(facts.ApiPermissions) != 2 { // get and list
		t.Fatalf("Expected 2 API permissions, got %d", len(facts.ApiPermissions))
	}

	// Check relationships between role and permissions
	permRelationCount := 0
	for _, rel := range facts.Relationships {
		if rel.Type == models.RelationshipAllows && rel.FromID == "default/test-role" {
			permRelationCount++
		}
	}

	if permRelationCount != 2 {
		t.Errorf("Expected 2 role-permission relationships, got %d", permRelationCount)
	}
}

func TestFactExtractor_IsCredentialLike(t *testing.T) {
	extractor := NewFactExtractor()

	testCases := []struct {
		secretType string
		metadata   map[string]interface{}
		expected   bool
	}{
		{
			secretType: "kubernetes.io/service-account-token",
			metadata:   map[string]interface{}{},
			expected:   true,
		},
		{
			secretType: "Opaque",
			metadata:   map[string]interface{}{},
			expected:   true,
		},
		{
			secretType: "kubernetes.io/dockerconfigjson",
			metadata:   map[string]interface{}{},
			expected:   true,
		},
		{
			secretType: "custom-type",
			metadata: map[string]interface{}{
				"annotations": map[string]interface{}{
					"credential-type": "password",
				},
			},
			expected: true,
		},
		{
			secretType: "custom-type",
			metadata:   map[string]interface{}{},
			expected:   false,
		},
	}

	for _, tc := range testCases {
		credLike, _ := extractor.isCredentialLike(tc.secretType, tc.metadata)
		if credLike != tc.expected {
			t.Errorf("For secret type '%s', expected credential-like=%v, got %v",
				tc.secretType, tc.expected, credLike)
		}
	}
}

func TestFactExtractor_HasInternetAccess(t *testing.T) {
	extractor := NewFactExtractor()

	testCases := []struct {
		namespace string
		expected  bool
	}{
		{"default", true},
		{"production", true},
		{"kube-system", false},
		{"kube-public", false},
		{"kube-node-lease", false},
	}

	for _, tc := range testCases {
		resource := map[string]interface{}{
			"metadata": map[string]interface{}{
				"namespace": tc.namespace,
			},
		}

		hasInternet := extractor.hasInternetAccess(resource)
		if hasInternet != tc.expected {
			t.Errorf("For namespace '%s', expected internet access=%v, got %v",
				tc.namespace, tc.expected, hasInternet)
		}
	}
}
