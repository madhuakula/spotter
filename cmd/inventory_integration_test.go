package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/madhuakula/spotter/pkg/graphstore"
	"github.com/madhuakula/spotter/pkg/models"
)

// IntegrationTestStore is a simple file-based graph store for integration testing
type IntegrationTestStore struct {
	dbPath string
	facts  *models.GraphFacts
}

func NewIntegrationTestStore() *IntegrationTestStore {
	return &IntegrationTestStore{
		facts: &models.GraphFacts{
			Pods:            []models.PodFact{},
			Secrets:         []models.SecretFact{},
			ConfigMaps:      []models.ConfigMapFact{},
			ServiceAccounts: []models.ServiceAccountFact{},
			Roles:           []models.RoleFact{},
			ApiPermissions:  []models.ApiPermissionFact{},
			Relationships:   []models.RelationshipFact{},
		},
	}
}

func (i *IntegrationTestStore) Open(path string) error {
	i.dbPath = path
	// Create directory if it doesn't exist
	return os.MkdirAll(path, 0755)
}

func (i *IntegrationTestStore) Close() error {
	return nil
}

func (i *IntegrationTestStore) EnsureSchema(ctx context.Context) error {
	return nil
}

func (i *IntegrationTestStore) UpsertFacts(ctx context.Context, facts *models.GraphFacts) error {
	i.facts = facts

	// Save facts to a JSON file for verification
	factsFile := filepath.Join(i.dbPath, "facts.json")
	data, err := json.MarshalIndent(facts, "", "  ")
	if err != nil {
		return err
	}

	return os.WriteFile(factsFile, data, 0644)
}

func (i *IntegrationTestStore) RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error) {
	return []models.AttackPathFinding{}, nil
}

func (i *IntegrationTestStore) Invalidate() error {
	if i.dbPath != "" {
		return os.RemoveAll(i.dbPath)
	}
	return nil
}

func (i *IntegrationTestStore) IsStale(ttl time.Duration) (bool, error) {
	return false, nil
}

func (i *IntegrationTestStore) GetLastModified() (time.Time, error) {
	return time.Now(), nil
}

// Test the inventory command end-to-end with file system operations
func TestInventoryCommand_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Create temporary directory for test
	tempDir, err := os.MkdirTemp("", "spotter-inventory-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	// Setup test environment
	viper.Set("timeout", "30s")
	viper.Set("log-level", "debug")
	defer viper.Reset()

	// Create test database path
	dbPath := filepath.Join(tempDir, "test-inventory.db")

	// Create test resources
	testResources := []map[string]interface{}{
		{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      "test-app",
				"namespace": "default",
				"labels": map[string]interface{}{
					"app": "test",
				},
			},
			"spec": map[string]interface{}{
				"serviceAccountName": "test-sa",
				"containers": []map[string]interface{}{
					{
						"name":  "app",
						"image": "nginx:latest",
						"env": []map[string]interface{}{
							{
								"name": "DB_PASSWORD",
								"valueFrom": map[string]interface{}{
									"secretKeyRef": map[string]interface{}{
										"name": "db-secret",
										"key":  "password",
									},
								},
							},
						},
					},
				},
			},
		},
		{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      "db-secret",
				"namespace": "default",
			},
			"type": "Opaque",
			"data": map[string]interface{}{
				"username": "YWRtaW4=", // base64 encoded "admin"
				"password": "c2VjcmV0", // base64 encoded "secret"
			},
		},
		{
			"apiVersion": "v1",
			"kind":       "ServiceAccount",
			"metadata": map[string]interface{}{
				"name":      "test-sa",
				"namespace": "default",
			},
		},
		{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "Role",
			"metadata": map[string]interface{}{
				"name":      "test-role",
				"namespace": "default",
			},
			"rules": []map[string]interface{}{
				{
					"apiGroups": []string{""},
					"resources": []string{"secrets"},
					"verbs":     []string{"get", "list"},
				},
			},
		},
	}

	// Test fact extraction
	extractor := graphstore.NewFactExtractor()
	facts, err := extractor.ExtractFacts(testResources)
	if err != nil {
		t.Fatalf("Failed to extract facts: %v", err)
	}

	// Verify extracted facts
	if len(facts.Pods) != 1 {
		t.Errorf("Expected 1 pod, got %d", len(facts.Pods))
	}

	if len(facts.Secrets) != 1 {
		t.Errorf("Expected 1 secret, got %d", len(facts.Secrets))
	}

	if len(facts.ServiceAccounts) != 1 {
		t.Errorf("Expected 1 service account, got %d", len(facts.ServiceAccounts))
	}

	if len(facts.Roles) != 1 {
		t.Errorf("Expected 1 role, got %d", len(facts.Roles))
	}

	// Test integration store
	store := NewIntegrationTestStore()
	if err := store.Open(dbPath); err != nil {
		t.Fatalf("Failed to open integration store: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()
	if err := store.EnsureSchema(ctx); err != nil {
		t.Fatalf("Failed to ensure schema: %v", err)
	}

	if err := store.UpsertFacts(ctx, facts); err != nil {
		t.Fatalf("Failed to upsert facts: %v", err)
	}

	// Verify facts were saved to file
	factsFile := filepath.Join(dbPath, "facts.json")
	if _, err := os.Stat(factsFile); os.IsNotExist(err) {
		t.Errorf("Facts file was not created: %s", factsFile)
	}

	// Read and verify the saved facts
	data, err := os.ReadFile(factsFile)
	if err != nil {
		t.Fatalf("Failed to read facts file: %v", err)
	}

	var savedFacts models.GraphFacts
	if err := json.Unmarshal(data, &savedFacts); err != nil {
		t.Fatalf("Failed to unmarshal saved facts: %v", err)
	}

	if len(savedFacts.Pods) != 1 {
		t.Errorf("Expected 1 saved pod, got %d", len(savedFacts.Pods))
	}

	if savedFacts.Pods[0].ID != "default/test-app" {
		t.Errorf("Expected pod ID 'default/test-app', got %s", savedFacts.Pods[0].ID)
	}

	if len(savedFacts.Secrets) != 1 {
		t.Errorf("Expected 1 saved secret, got %d", len(savedFacts.Secrets))
	}

	if savedFacts.Secrets[0].ID != "default/db-secret" {
		t.Errorf("Expected secret ID 'default/db-secret', got %s", savedFacts.Secrets[0].ID)
	}

	t.Logf("Integration test completed successfully")
	t.Logf("Database path: %s", dbPath)
	t.Logf("Extracted %d pods, %d secrets, %d service accounts, %d roles",
		len(facts.Pods), len(facts.Secrets), len(facts.ServiceAccounts), len(facts.Roles))
}

// Test demonstrating various inventory command options
func TestInventoryCommand_OptionsDemo(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping demo test in short mode")
	}

	tests := []struct {
		name          string
		args          []string
		description   string
		expectSuccess bool
	}{
		{
			name:          "basic_inventory",
			args:          []string{"--path=/tmp/test-basic.db", "--no-cache"},
			description:   "Basic inventory creation with no cache",
			expectSuccess: true,
		},
		{
			name:          "custom_cache_ttl",
			args:          []string{"--path=/tmp/test-cache.db", "--cache-ttl=30m"},
			description:   "Inventory with custom cache TTL",
			expectSuccess: true,
		},
		{
			name:          "exclude_system_namespaces",
			args:          []string{"--path=/tmp/test-exclude.db", "--exclude-system-namespaces"},
			description:   "Inventory excluding system namespaces",
			expectSuccess: true,
		},
		{
			name:          "specific_namespaces",
			args:          []string{"--path=/tmp/test-ns.db", "--namespace=default", "--namespace=app"},
			description:   "Inventory for specific namespaces",
			expectSuccess: true,
		},
		{
			name:          "force_refresh",
			args:          []string{"--path=/tmp/test-refresh.db", "--force-refresh"},
			description:   "Inventory with forced cache refresh",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)

			// Create a temporary directory for each test
			tempDir, err := os.MkdirTemp("", fmt.Sprintf("spotter-demo-%s-*", tt.name))
			if err != nil {
				t.Fatalf("Failed to create temp directory: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Update path to use temp directory
			for i, arg := range tt.args {
				if strings.HasPrefix(arg, "--path=") {
					tt.args[i] = fmt.Sprintf("--path=%s", filepath.Join(tempDir, "inventory.db"))
				}
			}

			// Create a mock command for testing flags
			cmd := &cobra.Command{
				Use: "inventory",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Just validate flags without running actual inventory
					path, _ := cmd.Flags().GetString("path")
					if path == "" {
						return fmt.Errorf("path is required")
					}

					t.Logf("Would create inventory at: %s", path)
					return nil
				},
			}

			// Add flags
			cmd.Flags().String("path", "", "path where to create the graph database (required)")
			cmd.Flags().String("cache-ttl", "1h", "cache time-to-live")
			cmd.Flags().Bool("no-cache", false, "disable caching")
			cmd.Flags().Bool("force-refresh", false, "force cache refresh")
			cmd.Flags().StringSliceP("namespace", "n", []string{}, "namespaces to scan")
			cmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces")
			_ = cmd.MarkFlagRequired("path")

			cmd.SetArgs(tt.args)
			err = cmd.Execute()

			if tt.expectSuccess && err != nil {
				t.Errorf("Expected success but got error: %v", err)
			} else if !tt.expectSuccess && err == nil {
				t.Errorf("Expected error but got success")
			}

			if err == nil {
				t.Logf("✓ Command executed successfully with args: %v", tt.args)
			}
		})
	}
}

// Benchmark realistic inventory operations
func BenchmarkInventoryCommand_RealisticWorkload(b *testing.B) {
	// Create realistic test data
	resources := make([]map[string]interface{}, 500)

	// 200 pods
	for i := 0; i < 200; i++ {
		ns := "default"
		if i%5 == 0 {
			ns = "kube-system"
		} else if i%7 == 0 {
			ns = "monitoring"
		}

		resources[i] = map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Pod",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("pod-%d", i),
				"namespace": ns,
			},
			"spec": map[string]interface{}{
				"serviceAccountName": fmt.Sprintf("sa-%d", i%10),
				"containers": []map[string]interface{}{
					{
						"name":  "container",
						"image": "nginx:latest",
					},
				},
			},
		}
	}

	// 150 secrets
	for i := 200; i < 350; i++ {
		ns := "default"
		if i%3 == 0 {
			ns = "kube-system"
		}

		resources[i] = map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "Secret",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("secret-%d", i-200),
				"namespace": ns,
			},
			"type": "Opaque",
			"data": map[string]interface{}{
				"key": "dmFsdWU=", // base64 encoded "value"
			},
		}
	}

	// 100 service accounts
	for i := 350; i < 450; i++ {
		resources[i] = map[string]interface{}{
			"apiVersion": "v1",
			"kind":       "ServiceAccount",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("sa-%d", i-350),
				"namespace": "default",
			},
		}
	}

	// 50 roles
	for i := 450; i < 500; i++ {
		resources[i] = map[string]interface{}{
			"apiVersion": "rbac.authorization.k8s.io/v1",
			"kind":       "Role",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("role-%d", i-450),
				"namespace": "default",
			},
			"rules": []map[string]interface{}{
				{
					"apiGroups": []string{""},
					"resources": []string{"secrets"},
					"verbs":     []string{"get"},
				},
			},
		}
	}

	extractor := graphstore.NewFactExtractor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		facts, err := extractor.ExtractFacts(resources)
		if err != nil {
			b.Fatalf("Failed to extract facts: %v", err)
		}

		// Simulate some processing
		_ = len(facts.Pods) + len(facts.Secrets) + len(facts.ServiceAccounts) + len(facts.Roles)
	}
}
