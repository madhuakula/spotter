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
	"github.com/madhuakula/spotter/pkg/models"
)

// MockAttackPathGraphStore implements a mock graph store specifically for attack path testing
type MockAttackPathGraphStore struct {
	isOpen         bool
	dbPath         string
	shouldFailOpen bool
	shouldFailCorr bool
	findings       []models.AttackPathFinding
	cacheConfig    *graphstore.CacheConfig
}

func NewMockAttackPathGraphStore(config *graphstore.CacheConfig) *MockAttackPathGraphStore {
	return &MockAttackPathGraphStore{
		cacheConfig: config,
		findings:    []models.AttackPathFinding{},
	}
}

func (m *MockAttackPathGraphStore) Open(path string) error {
	if m.shouldFailOpen {
		return &os.PathError{Op: "open", Path: path, Err: os.ErrPermission}
	}
	m.dbPath = path
	m.isOpen = true
	return nil
}

func (m *MockAttackPathGraphStore) Close() error {
	m.isOpen = false
	return nil
}

func (m *MockAttackPathGraphStore) EnsureSchema(ctx context.Context) error {
	return nil
}

func (m *MockAttackPathGraphStore) UpsertFacts(ctx context.Context, facts *models.GraphFacts) error {
	return nil
}

func (m *MockAttackPathGraphStore) RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error) {
	if m.shouldFailCorr {
		return nil, context.DeadlineExceeded
	}
	return m.findings, nil
}

func (m *MockAttackPathGraphStore) Invalidate() error {
	return nil
}

func (m *MockAttackPathGraphStore) IsStale(ttl time.Duration) (bool, error) {
	return false, nil
}

func (m *MockAttackPathGraphStore) GetLastModified() (time.Time, error) {
	return time.Now(), nil
}

// Test fixtures for attack path findings
func createCredentialExfilFinding() models.AttackPathFinding {
	return models.AttackPathFinding{
		CorrelationID: "cred-exfil-001",
		Type:          models.AttackPathTypeCredentialExfil,
		Path:          "Pod[app-pod] -> Uses Secret[db-credentials] -> Contains[passwords]",
		Impact:        "Attacker can extract database credentials from pod environment variables",
		FixHint:       "Use Kubernetes secrets mounted as volumes instead of environment variables",
		Entities: []models.AttackPathEntity{
			{
				ID:        "default/app-pod",
				Type:      "Pod",
				Namespace: "default",
				Properties: map[string]string{
					"serviceAccount": "app-sa",
					"hasInternet":    "true",
				},
			},
			{
				ID:        "default/db-credentials",
				Type:      "Secret",
				Namespace: "default",
				Properties: map[string]string{
					"type":     "Opaque",
					"credLike": "true",
				},
			},
		},
		Metadata: map[string]interface{}{
			"risk_score":   8.5,
			"cwe":          "CWE-312",
			"attack_stage": "lateral_movement",
		},
		Timestamp: time.Now(),
	}
}

func createRBACPivotFinding() models.AttackPathFinding {
	return models.AttackPathFinding{
		CorrelationID: "rbac-pivot-001",
		Type:          models.AttackPathTypeRBACPivot,
		Path:          "ServiceAccount[app-sa] -> Bound to Role[secret-reader] -> Can access[all secrets]",
		Impact:        "Service account has excessive permissions to read all secrets in namespace",
		FixHint:       "Apply principle of least privilege - restrict role to specific secrets needed",
		Entities: []models.AttackPathEntity{
			{
				ID:        "default/app-sa",
				Type:      "ServiceAccount",
				Namespace: "default",
				Properties: map[string]string{
					"automountToken": "true",
				},
			},
			{
				ID:        "default/secret-reader",
				Type:      "Role",
				Namespace: "default",
				Properties: map[string]string{
					"apiGroups": "",
					"resources": "secrets",
					"verbs":     "get,list",
				},
			},
		},
		Metadata: map[string]interface{}{
			"risk_score":   7.2,
			"cwe":          "CWE-269",
			"attack_stage": "privilege_escalation",
		},
		Timestamp: time.Now(),
	}
}

func setupAttackPathTestEnvironment(t *testing.T) (string, func()) {
	// Create temporary directory for test database
	tempDir, err := os.MkdirTemp("", "spotter-attackpath-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	// Setup test configuration
	viper.Set("timeout", "30s")
	viper.Set("log-level", "info")
	viper.Set("output", "table")
	viper.Set("output-file", "")

	// Cleanup function
	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		viper.Reset()
	}

	return tempDir, cleanup
}

func TestAttackPathCommand_Flags(t *testing.T) {
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
			name:    "path flag with existing directory",
			args:    []string{"--path=/tmp"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, cleanup := setupAttackPathTestEnvironment(t)
			defer cleanup()

			// Create a copy of the attack-path command for testing
			cmd := &cobra.Command{
				Use:  "attack-path",
				RunE: func(cmd *cobra.Command, args []string) error { return nil },
			}

			// Add the same flags as the real attack-path command
			cmd.Flags().String("path", "", "path to the graph database (required)")
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

func TestAttackPathCommand_DatabaseExistenceCheck(t *testing.T) {
	tests := []struct {
		name           string
		createDB       bool
		createFile     bool
		expectedExists bool
	}{
		{
			name:           "database directory exists",
			createDB:       true,
			createFile:     false,
			expectedExists: true,
		},
		{
			name:           "database file exists",
			createDB:       false,
			createFile:     true,
			expectedExists: true,
		},
		{
			name:           "database does not exist",
			createDB:       false,
			createFile:     false,
			expectedExists: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, cleanup := setupAttackPathTestEnvironment(t)
			defer cleanup()

			dbPath := filepath.Join(tempDir, "test.db")

			if tt.createDB {
				err := os.MkdirAll(dbPath, 0755)
				if err != nil {
					t.Fatalf("Failed to create database directory: %v", err)
				}
			}

			if tt.createFile {
				err := os.WriteFile(dbPath, []byte("fake db"), 0644)
				if err != nil {
					t.Fatalf("Failed to create database file: %v", err)
				}
			}

			// Check if database exists
			_, err := os.Stat(dbPath)
			exists := !os.IsNotExist(err)

			if exists != tt.expectedExists {
				t.Errorf("Expected database exists: %v, got: %v", tt.expectedExists, exists)
			}
		})
	}
}

func TestRunAttackPath_Success(t *testing.T) {
	tempDir, cleanup := setupAttackPathTestEnvironment(t)
	defer cleanup()

	// Create mock findings
	credFinding := createCredentialExfilFinding()
	rbacFinding := createRBACPivotFinding()
	findings := []models.AttackPathFinding{credFinding, rbacFinding}

	// Create mock graph store
	mockStore := NewMockAttackPathGraphStore(&graphstore.CacheConfig{
		Target: "existing",
	})
	mockStore.findings = findings

	// Test the core logic components
	ctx := context.Background()
	dbPath := filepath.Join(tempDir, "test.db")

	// Create a fake database directory
	err := os.MkdirAll(dbPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test database directory: %v", err)
	}

	// Test graph store operations
	if err := mockStore.Open(dbPath); err != nil {
		t.Fatalf("Failed to open mock graph store: %v", err)
	}
	defer func() { _ = mockStore.Close() }()

	// Test correlation queries
	correlationTypes := []string{"credential-exfil", "rbac-pivot"}
	results, err := mockStore.RunCorrelations(ctx, correlationTypes)
	if err != nil {
		t.Fatalf("Failed to run correlations: %v", err)
	}

	if len(results) != 2 {
		t.Errorf("Expected 2 findings, got %d", len(results))
	}

	// Test result processing
	pathsByType := make(map[string]int)
	for _, finding := range results {
		pathsByType[string(finding.Type)]++
	}

	expectedCredExfil := 1
	expectedRBACPivot := 1

	if pathsByType[string(models.AttackPathTypeCredentialExfil)] != expectedCredExfil {
		t.Errorf("Expected %d credential exfil findings, got %d",
			expectedCredExfil, pathsByType[string(models.AttackPathTypeCredentialExfil)])
	}

	if pathsByType[string(models.AttackPathTypeRBACPivot)] != expectedRBACPivot {
		t.Errorf("Expected %d RBAC pivot findings, got %d",
			expectedRBACPivot, pathsByType[string(models.AttackPathTypeRBACPivot)])
	}

	// Test attack path result structure
	startTime := time.Now()
	result := &models.AttackPathResult{
		Findings:         results,
		TotalPaths:       len(results),
		PathsByType:      pathsByType,
		CacheHit:         true,
		AnalysisDuration: time.Since(startTime),
		Timestamp:        time.Now(),
	}

	if result.TotalPaths != 2 {
		t.Errorf("Expected total paths 2, got %d", result.TotalPaths)
	}

	if !result.CacheHit {
		t.Errorf("Expected cache hit to be true")
	}

	// Test scan result structure
	scanResult := &models.ScanResult{
		AttackPathResult: result,
		Timestamp:        time.Now(),
		Duration:         time.Since(startTime),
	}

	if scanResult.AttackPathResult == nil {
		t.Errorf("Expected attack path result to be populated")
	}

	if scanResult.AttackPathResult.TotalPaths != 2 {
		t.Errorf("Expected 2 total paths in scan result, got %d", scanResult.AttackPathResult.TotalPaths)
	}
}

func TestRunAttackPath_ErrorHandling(t *testing.T) {
	tempDir, cleanup := setupAttackPathTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name             string
		dbExists         bool
		mockStore        *MockAttackPathGraphStore
		expectedErrorMsg string
	}{
		{
			name:     "database does not exist",
			dbExists: false,
			mockStore: NewMockAttackPathGraphStore(&graphstore.CacheConfig{
				Target: "existing",
			}),
			expectedErrorMsg: "graph database not found",
		},
		{
			name:     "graph store open failure",
			dbExists: true,
			mockStore: &MockAttackPathGraphStore{
				shouldFailOpen: true,
				cacheConfig: &graphstore.CacheConfig{
					Target: "existing",
				},
			},
			expectedErrorMsg: "permission denied",
		},
		{
			name:     "correlation query failure",
			dbExists: true,
			mockStore: &MockAttackPathGraphStore{
				shouldFailCorr: true,
				cacheConfig: &graphstore.CacheConfig{
					Target: "existing",
				},
			},
			expectedErrorMsg: "context deadline exceeded",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := filepath.Join(tempDir, tt.name+".db")

			// Create database if needed
			if tt.dbExists {
				err := os.MkdirAll(dbPath, 0755)
				if err != nil {
					t.Fatalf("Failed to create test database: %v", err)
				}
			}

			// Test database existence check
			if !tt.dbExists {
				_, err := os.Stat(dbPath)
				if !os.IsNotExist(err) {
					t.Errorf("Expected database to not exist")
				}
				return // Skip further testing for non-existent database
			}

			// Test graph store operations
			ctx := context.Background()

			if tt.mockStore.shouldFailOpen {
				err := tt.mockStore.Open(dbPath)
				if err == nil {
					t.Errorf("Expected error for %s, got nil", tt.name)
				} else if !strings.Contains(err.Error(), tt.expectedErrorMsg) {
					t.Errorf("Expected error to contain %q, got %q", tt.expectedErrorMsg, err.Error())
				}
				return
			}

			// Open successful cases
			if err := tt.mockStore.Open(dbPath); err != nil {
				t.Fatalf("Unexpected error opening graph store: %v", err)
			}
			defer func() { _ = tt.mockStore.Close() }()

			if tt.mockStore.shouldFailCorr {
				correlationTypes := []string{"credential-exfil", "rbac-pivot"}
				_, err := tt.mockStore.RunCorrelations(ctx, correlationTypes)
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

func TestAttackPathCommand_FindingsProcessing(t *testing.T) {
	tests := []struct {
		name            string
		findings        []models.AttackPathFinding
		expectedTotal   int
		expectedCredExf int
		expectedRBAC    int
	}{
		{
			name:            "no findings",
			findings:        []models.AttackPathFinding{},
			expectedTotal:   0,
			expectedCredExf: 0,
			expectedRBAC:    0,
		},
		{
			name:            "only credential exfiltration",
			findings:        []models.AttackPathFinding{createCredentialExfilFinding()},
			expectedTotal:   1,
			expectedCredExf: 1,
			expectedRBAC:    0,
		},
		{
			name:            "only RBAC pivot",
			findings:        []models.AttackPathFinding{createRBACPivotFinding()},
			expectedTotal:   1,
			expectedCredExf: 0,
			expectedRBAC:    1,
		},
		{
			name: "mixed findings",
			findings: []models.AttackPathFinding{
				createCredentialExfilFinding(),
				createRBACPivotFinding(),
				createCredentialExfilFinding(),
			},
			expectedTotal:   3,
			expectedCredExf: 2,
			expectedRBAC:    1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Process findings like the actual command does
			pathsByType := make(map[string]int)
			for _, finding := range tt.findings {
				pathsByType[string(finding.Type)]++
			}

			totalPaths := len(tt.findings)
			credExfilCount := pathsByType[string(models.AttackPathTypeCredentialExfil)]
			rbacPivotCount := pathsByType[string(models.AttackPathTypeRBACPivot)]

			if totalPaths != tt.expectedTotal {
				t.Errorf("Expected total paths %d, got %d", tt.expectedTotal, totalPaths)
			}

			if credExfilCount != tt.expectedCredExf {
				t.Errorf("Expected credential exfil %d, got %d", tt.expectedCredExf, credExfilCount)
			}

			if rbacPivotCount != tt.expectedRBAC {
				t.Errorf("Expected RBAC pivot %d, got %d", tt.expectedRBAC, rbacPivotCount)
			}
		})
	}
}

func TestAttackPathCommand_OutputFormats(t *testing.T) {
	tempDir, cleanup := setupAttackPathTestEnvironment(t)
	defer cleanup()

	tests := []struct {
		name         string
		outputFormat string
		outputFile   string
		wantFileOut  bool
	}{
		{
			name:         "table output to stdout",
			outputFormat: "table",
			outputFile:   "",
			wantFileOut:  false,
		},
		{
			name:         "json output to stdout",
			outputFormat: "json",
			outputFile:   "",
			wantFileOut:  false,
		},
		{
			name:         "yaml output to stdout",
			outputFormat: "yaml",
			outputFile:   "",
			wantFileOut:  false,
		},
		{
			name:         "json output to file",
			outputFormat: "json",
			outputFile:   "attack-paths.json",
			wantFileOut:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set output configuration
			viper.Set("output", tt.outputFormat)
			if tt.outputFile != "" {
				viper.Set("output-file", filepath.Join(tempDir, tt.outputFile))
			} else {
				viper.Set("output-file", "")
			}

			// Test configuration
			outputFormat := viper.GetString("output")
			outputFile := viper.GetString("output-file")
			noColor := viper.GetBool("no-color")
			verbose := viper.GetBool("verbose")

			if outputFormat != tt.outputFormat {
				t.Errorf("Expected output format %s, got %s", tt.outputFormat, outputFormat)
			}

			if tt.wantFileOut {
				if outputFile == "" {
					t.Errorf("Expected output file to be set, got empty")
				}
				expectedPath := filepath.Join(tempDir, tt.outputFile)
				if outputFile != expectedPath {
					t.Errorf("Expected output file %s, got %s", expectedPath, outputFile)
				}
			} else {
				if outputFile != "" {
					t.Errorf("Expected output file to be empty, got %s", outputFile)
				}
			}

			// Test that we can configure these options
			_ = noColor
			_ = verbose
		})
	}
}

func TestAttackPathCommand_CorrelationTypes(t *testing.T) {
	tests := []struct {
		name             string
		correlationTypes []string
		expectedTypes    []string
	}{
		{
			name:             "default correlation types",
			correlationTypes: []string{"credential-exfil", "rbac-pivot"},
			expectedTypes:    []string{"credential-exfil", "rbac-pivot"},
		},
		{
			name:             "single correlation type",
			correlationTypes: []string{"credential-exfil"},
			expectedTypes:    []string{"credential-exfil"},
		},
		{
			name:             "empty correlation types",
			correlationTypes: []string{},
			expectedTypes:    []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir, cleanup := setupAttackPathTestEnvironment(t)
			defer cleanup()

			mockStore := NewMockAttackPathGraphStore(&graphstore.CacheConfig{
				Target: "existing",
			})

			ctx := context.Background()
			dbPath := filepath.Join(tempDir, "test.db")

			// Create and open mock store
			err := os.MkdirAll(dbPath, 0755)
			if err != nil {
				t.Fatalf("Failed to create test database: %v", err)
			}

			if err := mockStore.Open(dbPath); err != nil {
				t.Fatalf("Failed to open mock store: %v", err)
			}
			defer func() { _ = mockStore.Close() }()

			// Test correlation types
			_, err = mockStore.RunCorrelations(ctx, tt.correlationTypes)
			if err != nil {
				t.Fatalf("Failed to run correlations: %v", err)
			}

			// Verify the types match expected
			if len(tt.correlationTypes) != len(tt.expectedTypes) {
				t.Errorf("Expected %d correlation types, got %d",
					len(tt.expectedTypes), len(tt.correlationTypes))
			}

			for i, expected := range tt.expectedTypes {
				if i >= len(tt.correlationTypes) {
					t.Errorf("Missing correlation type at index %d", i)
					continue
				}
				if tt.correlationTypes[i] != expected {
					t.Errorf("Expected correlation type %s at index %d, got %s",
						expected, i, tt.correlationTypes[i])
				}
			}
		})
	}
}

func TestAttackPathCommand_ResultTimestamps(t *testing.T) {
	_, cleanup := setupAttackPathTestEnvironment(t)
	defer cleanup()

	// Test that timestamps are properly set
	startTime := time.Now()

	result := &models.AttackPathResult{
		Findings:         []models.AttackPathFinding{createCredentialExfilFinding()},
		TotalPaths:       1,
		PathsByType:      map[string]int{string(models.AttackPathTypeCredentialExfil): 1},
		CacheHit:         true,
		AnalysisDuration: time.Since(startTime),
		Timestamp:        time.Now(),
	}

	scanResult := &models.ScanResult{
		AttackPathResult: result,
		Timestamp:        time.Now(),
		Duration:         time.Since(startTime),
	}

	// Verify timestamps are reasonable
	now := time.Now()
	if result.Timestamp.After(now) {
		t.Errorf("Result timestamp is in the future")
	}

	if scanResult.Timestamp.After(now) {
		t.Errorf("Scan result timestamp is in the future")
	}

	if result.AnalysisDuration < 0 {
		t.Errorf("Analysis duration cannot be negative")
	}

	if scanResult.Duration < 0 {
		t.Errorf("Scan duration cannot be negative")
	}

	// Test that finding timestamps are set
	finding := result.Findings[0]
	if finding.Timestamp.After(now) {
		t.Errorf("Finding timestamp is in the future")
	}
}

// Benchmark tests
func BenchmarkAttackPathCommand_FindingsProcessing(b *testing.B) {
	// Create a large number of findings for benchmarking
	findings := make([]models.AttackPathFinding, 1000)
	for i := 0; i < 500; i++ {
		findings[i] = createCredentialExfilFinding()
		findings[i].CorrelationID = strings.Repeat("x", i%10) // Vary the ID
	}
	for i := 500; i < 1000; i++ {
		findings[i] = createRBACPivotFinding()
		findings[i].CorrelationID = strings.Repeat("y", i%10) // Vary the ID
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Process findings like the actual command does
		pathsByType := make(map[string]int)
		for _, finding := range findings {
			pathsByType[string(finding.Type)]++
		}

		// Simulate building result
		result := &models.AttackPathResult{
			Findings:         findings,
			TotalPaths:       len(findings),
			PathsByType:      pathsByType,
			CacheHit:         true,
			AnalysisDuration: time.Millisecond * 100,
			Timestamp:        time.Now(),
		}

		// Ensure the result is actually used
		_ = result.TotalPaths
	}
}

func BenchmarkAttackPathCommand_MockStoreOperations(b *testing.B) {
	mockStore := NewMockAttackPathGraphStore(&graphstore.CacheConfig{
		Target: "existing",
	})

	// Setup mock findings
	mockStore.findings = []models.AttackPathFinding{
		createCredentialExfilFinding(),
		createRBACPivotFinding(),
	}

	// Create temp directory
	tempDir, err := os.MkdirTemp("", "spotter-bench-*")
	if err != nil {
		b.Fatalf("Failed to create temp directory: %v", err)
	}
	defer func() { _ = os.RemoveAll(tempDir) }()

	dbPath := filepath.Join(tempDir, "benchmark.db")
	err = os.MkdirAll(dbPath, 0755)
	if err != nil {
		b.Fatalf("Failed to create test database: %v", err)
	}

	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Open store
		if err := mockStore.Open(dbPath); err != nil {
			b.Fatalf("Failed to open store: %v", err)
		}

		// Run correlations
		correlationTypes := []string{"credential-exfil", "rbac-pivot"}
		findings, err := mockStore.RunCorrelations(ctx, correlationTypes)
		if err != nil {
			b.Fatalf("Failed to run correlations: %v", err)
		}

		// Process findings
		pathsByType := make(map[string]int)
		for _, finding := range findings {
			pathsByType[string(finding.Type)]++
		}

		// Close store
		_ = mockStore.Close()

		// Ensure results are used
		_ = len(findings)
		_ = pathsByType
	}
}
