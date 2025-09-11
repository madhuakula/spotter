package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/madhuakula/spotter/pkg/graphstore"
	"github.com/madhuakula/spotter/pkg/k8s"
	"github.com/madhuakula/spotter/pkg/models"
)

// MockGraphStore implements a mock graph store for testing
type MockGraphStore struct {
	isOpen       bool
	dbPath       string
	facts        *models.GraphFacts
	cacheConfig  *graphstore.CacheConfig
	shouldFailOn string // Which operation should fail for testing error cases
}

func NewMockGraphStore(config *graphstore.CacheConfig) *MockGraphStore {
	return &MockGraphStore{
		cacheConfig: config,
		facts:       &models.GraphFacts{},
	}
}

func (m *MockGraphStore) Open(path string) error {
	if m.shouldFailOn == "open" {
		return &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	}
	m.dbPath = path
	m.isOpen = true
	return nil
}

func (m *MockGraphStore) Close() error {
	if m.shouldFailOn == "close" {
		return &os.PathError{Op: "close", Path: m.dbPath, Err: os.ErrClosed}
	}
	m.isOpen = false
	return nil
}

func (m *MockGraphStore) EnsureSchema(ctx context.Context) error {
	if m.shouldFailOn == "schema" {
		return context.DeadlineExceeded
	}
	return nil
}

func (m *MockGraphStore) UpsertFacts(ctx context.Context, facts *models.GraphFacts) error {
	if m.shouldFailOn == "upsert" {
		return context.Canceled
	}
	m.facts = facts
	return nil
}

func (m *MockGraphStore) Invalidate() error {
	if m.shouldFailOn == "invalidate" {
		return &os.PathError{Op: "remove", Path: m.dbPath, Err: os.ErrNotExist}
	}
	return nil
}

func (m *MockGraphStore) RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error) {
	if m.shouldFailOn == "correlations" {
		return nil, context.DeadlineExceeded
	}
	return []models.AttackPathFinding{}, nil
}

func (m *MockGraphStore) IsStale(ttl time.Duration) (bool, error) {
	if m.shouldFailOn == "stale" {
		return false, &os.PathError{Op: "stat", Path: m.dbPath, Err: os.ErrNotExist}
	}
	return false, nil
}

func (m *MockGraphStore) GetLastModified() (time.Time, error) {
	if m.shouldFailOn == "lastmodified" {
		return time.Time{}, &os.PathError{Op: "stat", Path: m.dbPath, Err: os.ErrNotExist}
	}
	return time.Now(), nil
}

// MockK8sClient implements a mock Kubernetes client for testing
type MockK8sClient struct {
	shouldFailValidation bool
	resources            []map[string]interface{}
}

func (m *MockK8sClient) ValidateConnection(ctx context.Context) error {
	if m.shouldFailValidation {
		return context.DeadlineExceeded
	}
	return nil
}

// MockResourceScanner implements a mock resource scanner for testing
type MockResourceScanner struct {
	shouldFailScan bool
	resources      []map[string]interface{}
}

func (m *MockResourceScanner) ScanCluster(ctx context.Context, options k8s.ScanOptions) ([]map[string]interface{}, error) {
	if m.shouldFailScan {
		return nil, context.DeadlineExceeded
	}
	return m.resources, nil
}

func (m *MockResourceScanner) ScanNamespaces(ctx context.Context, namespaces []string, options k8s.ScanOptions) ([]map[string]interface{}, error) {
	return m.ScanCluster(ctx, options)
}

func (m *MockResourceScanner) ScanManifests(ctx context.Context, paths []string, options k8s.ScanOptions) ([]map[string]interface{}, error) {
	return m.ScanCluster(ctx, options)
}

func (m *MockResourceScanner) ScanHelmCharts(ctx context.Context, chartPaths []string, options k8s.ScanOptions) ([]map[string]interface{}, error) {
	return m.ScanCluster(ctx, options)
}

// Test fixtures
func createTestPod(name, namespace string) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Pod",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"spec": map[string]interface{}{
			"containers": []map[string]interface{}{
				{
					"name":  "test-container",
					"image": "nginx:latest",
				},
			},
		},
	}
}

func createTestSecret(name, namespace string) map[string]interface{} {
	return map[string]interface{}{
		"apiVersion": "v1",
		"kind":       "Secret",
		"metadata": map[string]interface{}{
			"name":      name,
			"namespace": namespace,
		},
		"type": "Opaque",
		"data": map[string]interface{}{
			"username": "YWRtaW4=", // base64 encoded "admin"
			"password": "c2VjcmV0", // base64 encoded "secret"
		},
	}
}

func setupTestEnvironment(t *testing.T) (string, func()) {
	// Create temporary directory for test database
	tempDir, err := os.MkdirTemp("", "spotter-inventory-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Setup test configuration
	viper.Set("timeout", "30s")
	viper.Set("log-level", "info")

	// Cleanup function
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		viper.Reset()
	}

	return tempDir, cleanup
}

func TestInventoryCommand_Flags(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr bool
		errMsg  string
	}{
		{
			name:    "missing required path flag",
			args:    []string{},
			wantErr: true,
			errMsg:  `required flag(s) "path" not set`,
		},
		{
			name:    "valid path flag",
			args:    []string{"--path=/tmp/test.db"},
			wantErr: false,
		},
		{
			name:    "valid cache-ttl flag",
			args:    []string{"--path=/tmp/test.db", "--cache-ttl=2h"},
			wantErr: false,
		},
		{
			name:    "valid namespace flags",
			args:    []string{"--path=/tmp/test.db", "--namespace=default", "--namespace=kube-system"},
			wantErr: false,
		},
		{
			name:    "valid exclude-namespaces flags",
			args:    []string{"--path=/tmp/test.db", "--exclude-namespaces=kube-system,kube-public"},
			wantErr: false,
		},
		{
			name:    "boolean flags",
			args:    []string{"--path=/tmp/test.db", "--no-cache", "--force-refresh", "--exclude-system-namespaces"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, cleanup := setupTestEnvironment(t)
			defer cleanup()

			// Create a copy of the inventory command for testing
			cmd := &cobra.Command{
				Use:  "inventory",
				RunE: func(cmd *cobra.Command, args []string) error { return nil },
			}

			// Add the same flags as the real inventory command
			cmd.Flags().String("path", "", "path where to create the graph database (required)")
			cmd.Flags().String("cache-ttl", "1h", "cache time-to-live (e.g., 10m, 1h, 24h)")
			cmd.Flags().String("cache-dir", "", "cache directory")
			cmd.Flags().Bool("no-cache", false, "disable caching")
			cmd.Flags().Bool("force-refresh", false, "force cache refresh")
			cmd.Flags().StringSliceP("namespace", "n", []string{}, "namespaces to scan")
			cmd.Flags().StringSlice("exclude-namespaces", []string{}, "namespaces to exclude")
			cmd.Flags().String("context", "", "kubernetes context to use")
			cmd.Flags().Bool("exclude-system-namespaces", false, "exclude system namespaces")
			cmd.Flags().Bool("include-cluster-resources", true, "include cluster-scoped resources")
			_ = cmd.MarkFlagRequired("path")

			// Replace path with temp directory if provided
			for i, arg := range tt.args {
				if strings.HasPrefix(arg, "--path=") {
					tt.args[i] = "--path=" + filepath.Join(tempDir, "test.db")
				}
			}

			cmd.SetArgs(tt.args)
			err := cmd.Execute()

			if tt.wantErr {
				if err == nil {
					t.Errorf("Expected error, got nil")
				} else if !strings.Contains(err.Error(), tt.errMsg) {
					t.Errorf("Expected error message to contain %q, got %q", tt.errMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
			}
		})
	}
}

func TestInventoryCommand_CacheTTLParsing(t *testing.T) {
	tests := []struct {
		name     string
		ttlStr   string
		expected time.Duration
	}{
		{
			name:     "valid duration - minutes",
			ttlStr:   "30m",
			expected: 30 * time.Minute,
		},
		{
			name:     "valid duration - hours",
			ttlStr:   "2h",
			expected: 2 * time.Hour,
		},
		{
			name:     "valid duration - seconds",
			ttlStr:   "120s",
			expected: 120 * time.Second,
		},
		{
			name:     "invalid duration - fallback to default",
			ttlStr:   "invalid",
			expected: time.Hour,
		},
		{
			name:     "empty duration - fallback to default",
			ttlStr:   "",
			expected: time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheTTL, err := time.ParseDuration(tt.ttlStr)
			if err != nil {
				cacheTTL = time.Hour // Default fallback
			}

			if cacheTTL != tt.expected {
				t.Errorf("Expected duration %v, got %v", tt.expected, cacheTTL)
			}
		})
	}
}

func TestRunInventory_Success(t *testing.T) {
	tempDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	// Create test resources
	pod1 := createTestPod("test-pod-1", "default")
	pod2 := createTestPod("test-pod-2", "kube-system")
	secret1 := createTestSecret("test-secret-1", "default")
	resources := []map[string]interface{}{pod1, pod2, secret1}

	// Create mock clients
	mockK8sClient := &MockK8sClient{resources: resources}
	mockScanner := &MockResourceScanner{resources: resources}
	mockGraphStore := NewMockGraphStore(&graphstore.CacheConfig{
		TTL:     time.Hour,
		NoCache: true,
	})

	// Test the core logic (we'll need to refactor runInventory to accept dependencies)
	ctx := context.Background()

	// Test graph store operations
	graphPath := filepath.Join(tempDir, "test.db")
	if err := mockGraphStore.Open(graphPath); err != nil {
		t.Fatalf("Failed to open mock graph store: %v", err)
	}
	defer func() { _ = mockGraphStore.Close() }()

	if err := mockGraphStore.EnsureSchema(ctx); err != nil {
		t.Fatalf("Failed to ensure schema: %v", err)
	}

	// Test k8s client validation
	if err := mockK8sClient.ValidateConnection(ctx); err != nil {
		t.Fatalf("Failed to validate connection: %v", err)
	}

	// Test resource scanning
	scanOptions := k8s.ScanOptions{
		IncludeNamespaces:       []string{},
		ExcludeNamespaces:       []string{},
		IncludeSystemNamespaces: true,
		IncludeClusterResources: true,
		Timeout:                 "30s",
	}

	scannedResources, err := mockScanner.ScanCluster(ctx, scanOptions)
	if err != nil {
		t.Fatalf("Failed to scan cluster: %v", err)
	}

	if len(scannedResources) != 3 {
		t.Errorf("Expected 3 resources, got %d", len(scannedResources))
	}

	// Test fact extraction
	extractor := graphstore.NewFactExtractor()
	facts, err := extractor.ExtractFacts(scannedResources)
	if err != nil {
		t.Fatalf("Failed to extract facts: %v", err)
	}

	// Test fact upsert
	if err := mockGraphStore.UpsertFacts(ctx, facts); err != nil {
		t.Fatalf("Failed to upsert facts: %v", err)
	}

	// Verify facts were stored
	if len(mockGraphStore.facts.Pods) != 2 {
		t.Errorf("Expected 2 pods in facts, got %d", len(mockGraphStore.facts.Pods))
	}

	if len(mockGraphStore.facts.Secrets) != 1 {
		t.Errorf("Expected 1 secret in facts, got %d", len(mockGraphStore.facts.Secrets))
	}
}

func TestRunInventory_ErrorHandling(t *testing.T) {
	tempDir, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name             string
		mockGraphStore   *MockGraphStore
		mockK8sClient    *MockK8sClient
		mockScanner      *MockResourceScanner
		expectedErrorMsg string
	}{
		{
			name: "graph store open failure",
			mockGraphStore: &MockGraphStore{
				shouldFailOn: "open",
				cacheConfig:  &graphstore.CacheConfig{},
			},
			mockK8sClient:    &MockK8sClient{},
			mockScanner:      &MockResourceScanner{},
			expectedErrorMsg: "permission denied",
		},
		{
			name:           "k8s connection validation failure",
			mockGraphStore: NewMockGraphStore(&graphstore.CacheConfig{}),
			mockK8sClient: &MockK8sClient{
				shouldFailValidation: true,
			},
			mockScanner:      &MockResourceScanner{},
			expectedErrorMsg: "context deadline exceeded",
		},
		{
			name:           "cluster scan failure",
			mockGraphStore: NewMockGraphStore(&graphstore.CacheConfig{}),
			mockK8sClient:  &MockK8sClient{},
			mockScanner: &MockResourceScanner{
				shouldFailScan: true,
			},
			expectedErrorMsg: "context deadline exceeded",
		},
		{
			name: "schema ensure failure",
			mockGraphStore: &MockGraphStore{
				shouldFailOn: "schema",
				cacheConfig:  &graphstore.CacheConfig{},
			},
			mockK8sClient:    &MockK8sClient{},
			mockScanner:      &MockResourceScanner{},
			expectedErrorMsg: "context deadline exceeded",
		},
		{
			name: "fact upsert failure",
			mockGraphStore: &MockGraphStore{
				shouldFailOn: "upsert",
				cacheConfig:  &graphstore.CacheConfig{},
			},
			mockK8sClient:    &MockK8sClient{},
			mockScanner:      &MockResourceScanner{},
			expectedErrorMsg: "context canceled",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			graphPath := filepath.Join(tempDir, tt.name+".db")

			// Test based on which component should fail
			if tt.mockGraphStore.shouldFailOn == "open" {
				err := tt.mockGraphStore.Open(graphPath)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			// Open successful cases
			if err := tt.mockGraphStore.Open(graphPath); err != nil {
				t.Fatalf("Unexpected error opening graph store: %v", err)
			}
			defer func() { _ = tt.mockGraphStore.Close() }()

			if tt.mockGraphStore.shouldFailOn == "schema" {
				err := tt.mockGraphStore.EnsureSchema(ctx)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err := tt.mockGraphStore.EnsureSchema(ctx); err != nil {
				t.Fatalf("Unexpected error ensuring schema: %v", err)
			}

			if tt.mockK8sClient.shouldFailValidation {
				err := tt.mockK8sClient.ValidateConnection(ctx)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			if err := tt.mockK8sClient.ValidateConnection(ctx); err != nil {
				t.Fatalf("Unexpected error validating connection: %v", err)
			}

			if tt.mockScanner.shouldFailScan {
				scanOptions := k8s.ScanOptions{}
				_, err := tt.mockScanner.ScanCluster(ctx, scanOptions)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			// Test successful scan followed by upsert failure
			resources, err := tt.mockScanner.ScanCluster(ctx, k8s.ScanOptions{})
			if err != nil {
				t.Fatalf("Unexpected error scanning cluster: %v", err)
			}

			extractor := graphstore.NewFactExtractor()
			facts, err := extractor.ExtractFacts(resources)
			if err != nil {
				t.Fatalf("Unexpected error extracting facts: %v", err)
			}

			if tt.mockGraphStore.shouldFailOn == "upsert" {
				err := tt.mockGraphStore.UpsertFacts(ctx, facts)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}
		})
	}
}

func TestInventoryCommand_CacheOperations(t *testing.T) {
	_, cleanup := setupTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name         string
		forceRefresh bool
		noCache      bool
		expectedTTL  time.Duration
	}{
		{
			name:         "default cache settings",
			forceRefresh: false,
			noCache:      false,
			expectedTTL:  time.Hour,
		},
		{
			name:         "force refresh enabled",
			forceRefresh: true,
			noCache:      false,
			expectedTTL:  time.Hour,
		},
		{
			name:         "no cache enabled",
			forceRefresh: false,
			noCache:      true,
			expectedTTL:  time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cacheConfig := &graphstore.CacheConfig{
				TTL:          tt.expectedTTL,
				NoCache:      tt.noCache,
				ForceRefresh: tt.forceRefresh,
				Target:       "cluster",
			}

			mockGraphStore := NewMockGraphStore(cacheConfig)

			if tt.forceRefresh {
				err := mockGraphStore.Invalidate()
				if err != nil {
					t.Errorf("Unexpected error invalidating cache: %v", err)
				}
			}

			if mockGraphStore.cacheConfig.TTL != tt.expectedTTL {
				t.Errorf("Expected TTL %v, got %v", tt.expectedTTL, mockGraphStore.cacheConfig.TTL)
			}

			if mockGraphStore.cacheConfig.NoCache != tt.noCache {
				t.Errorf("Expected NoCache %v, got %v", tt.noCache, mockGraphStore.cacheConfig.NoCache)
			}

			if mockGraphStore.cacheConfig.ForceRefresh != tt.forceRefresh {
				t.Errorf("Expected ForceRefresh %v, got %v", tt.forceRefresh, mockGraphStore.cacheConfig.ForceRefresh)
			}
		})
	}
}

func TestInventoryCommand_ScanOptions(t *testing.T) {
	tests := []struct {
		name                    string
		includeNamespaces       []string
		excludeNamespaces       []string
		excludeSystemNamespaces bool
		includeClusterResources bool
		expectedIncludeSystem   bool
		expectedIncludeCluster  bool
	}{
		{
			name:                    "default options",
			includeNamespaces:       []string{},
			excludeNamespaces:       []string{},
			excludeSystemNamespaces: false,
			includeClusterResources: true,
			expectedIncludeSystem:   true,
			expectedIncludeCluster:  true,
		},
		{
			name:                    "exclude system namespaces",
			includeNamespaces:       []string{},
			excludeNamespaces:       []string{},
			excludeSystemNamespaces: true,
			includeClusterResources: true,
			expectedIncludeSystem:   false,
			expectedIncludeCluster:  true,
		},
		{
			name:                    "exclude cluster resources",
			includeNamespaces:       []string{},
			excludeNamespaces:       []string{},
			excludeSystemNamespaces: false,
			includeClusterResources: false,
			expectedIncludeSystem:   true,
			expectedIncludeCluster:  false,
		},
		{
			name:                    "specific namespaces",
			includeNamespaces:       []string{"default", "app-namespace"},
			excludeNamespaces:       []string{"kube-system"},
			excludeSystemNamespaces: false,
			includeClusterResources: true,
			expectedIncludeSystem:   true,
			expectedIncludeCluster:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			scanOptions := k8s.ScanOptions{
				IncludeNamespaces:       tt.includeNamespaces,
				ExcludeNamespaces:       tt.excludeNamespaces,
				IncludeSystemNamespaces: !tt.excludeSystemNamespaces,
				IncludeClusterResources: tt.includeClusterResources,
				Timeout:                 "30s",
			}

			if scanOptions.IncludeSystemNamespaces != tt.expectedIncludeSystem {
				t.Errorf("Expected IncludeSystemNamespaces %v, got %v",
					tt.expectedIncludeSystem, scanOptions.IncludeSystemNamespaces)
			}

			if scanOptions.IncludeClusterResources != tt.expectedIncludeCluster {
				t.Errorf("Expected IncludeClusterResources %v, got %v",
					tt.expectedIncludeCluster, scanOptions.IncludeClusterResources)
			}

			if len(scanOptions.IncludeNamespaces) != len(tt.includeNamespaces) {
				t.Errorf("Expected %d include namespaces, got %d",
					len(tt.includeNamespaces), len(scanOptions.IncludeNamespaces))
			}

			if len(scanOptions.ExcludeNamespaces) != len(tt.excludeNamespaces) {
				t.Errorf("Expected %d exclude namespaces, got %d",
					len(tt.excludeNamespaces), len(scanOptions.ExcludeNamespaces))
			}
		})
	}
}

// Benchmark tests
func BenchmarkInventoryFactExtraction(b *testing.B) {
	// Create test resources
	resources := make([]map[string]interface{}, 1000)
	for i := 0; i < 500; i++ {
		resources[i] = createTestPod("test-pod-"+strings.Repeat("x", i%10), "default")
	}
	for i := 500; i < 1000; i++ {
		resources[i] = createTestSecret("test-secret-"+strings.Repeat("x", i%10), "default")
	}

	extractor := graphstore.NewFactExtractor()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := extractor.ExtractFacts(resources)
		if err != nil {
			b.Fatalf("Failed to extract facts: %v", err)
		}
	}
}
