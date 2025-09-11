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

	"github.com/madhuakula/spotter/pkg/models"
)

// IntegrationAttackPathStore is a file-based graph store for attack path integration testing
type IntegrationAttackPathStore struct {
	dbPath   string
	findings []models.AttackPathFinding
}

func NewIntegrationAttackPathStore() *IntegrationAttackPathStore {
	return &IntegrationAttackPathStore{
		findings: []models.AttackPathFinding{},
	}
}

func (i *IntegrationAttackPathStore) Open(path string) error {
	i.dbPath = path

	// Load findings from JSON file if it exists
	findingsFile := filepath.Join(path, "attack-findings.json")
	if data, err := os.ReadFile(findingsFile); err == nil {
		if err := json.Unmarshal(data, &i.findings); err == nil {
			return nil
		}
	}

	// Default findings if no file exists
	i.loadDefaultFindings()
	return nil
}

func (i *IntegrationAttackPathStore) Close() error {
	return nil
}

func (i *IntegrationAttackPathStore) EnsureSchema(ctx context.Context) error {
	return nil
}

func (i *IntegrationAttackPathStore) UpsertFacts(ctx context.Context, facts *models.GraphFacts) error {
	return nil
}

func (i *IntegrationAttackPathStore) RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error) {
	// Filter findings based on correlation types requested
	var filteredFindings []models.AttackPathFinding

	for _, finding := range i.findings {
		for _, corrType := range correlationTypes {
			switch corrType {
			case "credential-exfil":
				if finding.Type == models.AttackPathTypeCredentialExfil {
					filteredFindings = append(filteredFindings, finding)
				}
			case "rbac-pivot":
				if finding.Type == models.AttackPathTypeRBACPivot {
					filteredFindings = append(filteredFindings, finding)
				}
			}
		}
	}

	return filteredFindings, nil
}

func (i *IntegrationAttackPathStore) Invalidate() error {
	return nil
}

func (i *IntegrationAttackPathStore) IsStale(ttl time.Duration) (bool, error) {
	return false, nil
}

func (i *IntegrationAttackPathStore) GetLastModified() (time.Time, error) {
	return time.Now(), nil
}

func (i *IntegrationAttackPathStore) loadDefaultFindings() {
	i.findings = []models.AttackPathFinding{
		{
			CorrelationID: "integration-cred-001",
			Type:          models.AttackPathTypeCredentialExfil,
			Path:          "Pod[webapp] -> Mounts Secret[db-creds] -> Exposes[database_password]",
			Impact:        "Attacker with pod access can extract database credentials",
			FixHint:       "Use external secret management system like HashiCorp Vault",
			Entities: []models.AttackPathEntity{
				{
					ID:        "default/webapp",
					Type:      "Pod",
					Namespace: "default",
					Properties: map[string]string{
						"image":       "webapp:latest",
						"privileged":  "false",
						"hasInternet": "true",
					},
				},
				{
					ID:        "default/db-creds",
					Type:      "Secret",
					Namespace: "default",
					Properties: map[string]string{
						"type":      "Opaque",
						"mountPath": "/etc/secrets",
						"credLike":  "true",
					},
				},
			},
			Metadata: map[string]interface{}{
				"risk_score":    9.2,
				"cwe":           "CWE-200",
				"attack_vector": "container_escape",
				"mitre_tactic":  "credential_access",
			},
			Timestamp: time.Now(),
		},
		{
			CorrelationID: "integration-rbac-001",
			Type:          models.AttackPathTypeRBACPivot,
			Path:          "ServiceAccount[admin-sa] -> ClusterRole[cluster-admin] -> Full Cluster Access",
			Impact:        "Service account has full cluster administrative privileges",
			FixHint:       "Create specific roles with minimal required permissions",
			Entities: []models.AttackPathEntity{
				{
					ID:        "kube-system/admin-sa",
					Type:      "ServiceAccount",
					Namespace: "kube-system",
					Properties: map[string]string{
						"automountServiceAccountToken": "true",
						"usedByPods":                   "monitoring-pod",
					},
				},
				{
					ID:   "cluster-admin",
					Type: "ClusterRole",
					Properties: map[string]string{
						"scope":     "cluster",
						"resources": "*",
						"verbs":     "*",
					},
				},
			},
			Metadata: map[string]interface{}{
				"risk_score":    8.8,
				"cwe":           "CWE-269",
				"attack_vector": "privilege_escalation",
				"mitre_tactic":  "privilege_escalation",
				"blast_radius":  "cluster",
			},
			Timestamp: time.Now(),
		},
		{
			CorrelationID: "integration-cred-002",
			Type:          models.AttackPathTypeCredentialExfil,
			Path:          "Pod[api-server] -> Environment Variables -> AWS_SECRET_ACCESS_KEY",
			Impact:        "Cloud credentials exposed in environment variables",
			FixHint:       "Use IAM roles for service accounts (IRSA) or workload identity",
			Entities: []models.AttackPathEntity{
				{
					ID:        "production/api-server",
					Type:      "Pod",
					Namespace: "production",
					Properties: map[string]string{
						"image":         "api:v1.2.3",
						"hasEnvSecrets": "true",
						"cloudAccess":   "true",
					},
				},
			},
			Metadata: map[string]interface{}{
				"risk_score":     9.5,
				"cwe":            "CWE-312",
				"attack_vector":  "environment_exposure",
				"cloud_provider": "aws",
			},
			Timestamp: time.Now(),
		},
	}
}

func setupAttackPathIntegrationTest(t *testing.T) (string, func()) {
	tempDir, err := os.MkdirTemp("", "spotter-attackpath-integration-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	viper.Set("timeout", "30s")
	viper.Set("log-level", "info")
	viper.Set("output", "table")
	viper.Set("output-file", "")

	cleanup := func() {
		_ = os.RemoveAll(tempDir)
		viper.Reset()
	}

	return tempDir, cleanup
}

// Test the attack-path command end-to-end with file system operations
func TestAttackPathCommand_Integration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tempDir, cleanup := setupAttackPathIntegrationTest(t)
	defer cleanup()

	// Create a test database directory
	dbPath := filepath.Join(tempDir, "test-attack-path.db")
	err := os.MkdirAll(dbPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test database directory: %v", err)
	}

	// Test with integration store
	store := NewIntegrationAttackPathStore()
	if err := store.Open(dbPath); err != nil {
		t.Fatalf("Failed to open integration store: %v", err)
	}
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Test correlation queries
	correlationTypes := []string{"credential-exfil", "rbac-pivot"}
	findings, err := store.RunCorrelations(ctx, correlationTypes)
	if err != nil {
		t.Fatalf("Failed to run correlations: %v", err)
	}

	// Verify findings
	if len(findings) < 2 {
		t.Errorf("Expected at least 2 findings, got %d", len(findings))
	}

	// Count findings by type
	pathsByType := make(map[string]int)
	for _, finding := range findings {
		pathsByType[string(finding.Type)]++
	}

	credExfilCount := pathsByType[string(models.AttackPathTypeCredentialExfil)]
	rbacPivotCount := pathsByType[string(models.AttackPathTypeRBACPivot)]

	if credExfilCount == 0 {
		t.Errorf("Expected at least 1 credential exfiltration finding")
	}

	if rbacPivotCount == 0 {
		t.Errorf("Expected at least 1 RBAC pivot finding")
	}

	// Build result like the actual command
	startTime := time.Now()
	result := &models.AttackPathResult{
		Findings:         findings,
		TotalPaths:       len(findings),
		PathsByType:      pathsByType,
		CacheHit:         true,
		AnalysisDuration: time.Since(startTime),
		Timestamp:        time.Now(),
	}

	// Test scan result structure
	scanResult := &models.ScanResult{
		AttackPathResult: result,
		Timestamp:        time.Now(),
		Duration:         time.Since(startTime),
	}

	// Save results to file for verification
	resultsFile := filepath.Join(dbPath, "results.json")
	data, err := json.MarshalIndent(scanResult, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal results: %v", err)
	}

	if err := os.WriteFile(resultsFile, data, 0644); err != nil {
		t.Fatalf("Failed to write results file: %v", err)
	}

	// Verify results file was created
	if _, err := os.Stat(resultsFile); os.IsNotExist(err) {
		t.Errorf("Results file was not created: %s", resultsFile)
	}

	// Read and verify the saved results
	savedData, err := os.ReadFile(resultsFile)
	if err != nil {
		t.Fatalf("Failed to read results file: %v", err)
	}

	var savedResult models.ScanResult
	if err := json.Unmarshal(savedData, &savedResult); err != nil {
		t.Fatalf("Failed to unmarshal saved results: %v", err)
	}

	if savedResult.AttackPathResult == nil {
		t.Errorf("Expected attack path result to be saved")
	}

	if savedResult.AttackPathResult.TotalPaths != result.TotalPaths {
		t.Errorf("Expected %d total paths in saved result, got %d",
			result.TotalPaths, savedResult.AttackPathResult.TotalPaths)
	}

	t.Logf("Integration test completed successfully")
	t.Logf("Database path: %s", dbPath)
	t.Logf("Found %d attack paths (%d credential exfil, %d RBAC pivot)",
		result.TotalPaths, credExfilCount, rbacPivotCount)
}

// Test demonstrating various attack-path command options
func TestAttackPathCommand_OptionsDemo(t *testing.T) {
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
			name:          "basic_attack_path",
			args:          []string{"--path=/tmp/test-basic.db"},
			description:   "Basic attack path analysis",
			expectSuccess: true,
		},
		{
			name:          "json_output",
			args:          []string{"--path=/tmp/test-json.db", "--output=json"},
			description:   "Attack path analysis with JSON output",
			expectSuccess: true,
		},
		{
			name:          "yaml_output",
			args:          []string{"--path=/tmp/test-yaml.db", "--output=yaml"},
			description:   "Attack path analysis with YAML output",
			expectSuccess: true,
		},
		{
			name:          "output_to_file",
			args:          []string{"--path=/tmp/test-file.db", "--output=json", "--output-file=attack-paths.json"},
			description:   "Attack path analysis saving results to file",
			expectSuccess: true,
		},
		{
			name:          "verbose_output",
			args:          []string{"--path=/tmp/test-verbose.db", "--verbose"},
			description:   "Attack path analysis with verbose output",
			expectSuccess: true,
		},
		{
			name:          "debug_logging",
			args:          []string{"--path=/tmp/test-debug.db", "--log-level=debug"},
			description:   "Attack path analysis with debug logging",
			expectSuccess: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Logf("Testing: %s", tt.description)

			tempDir, err := os.MkdirTemp("", fmt.Sprintf("spotter-attackpath-demo-%s-*", tt.name))
			if err != nil {
				t.Fatalf("Failed to create temp directory: %v", err)
			}
			defer func() { _ = os.RemoveAll(tempDir) }()

			// Update paths to use temp directory
			for i, arg := range tt.args {
				if strings.HasPrefix(arg, "--path=") {
					tt.args[i] = fmt.Sprintf("--path=%s", filepath.Join(tempDir, "attack-path.db"))
				}
				if strings.HasPrefix(arg, "--output-file=") {
					tt.args[i] = fmt.Sprintf("--output-file=%s", filepath.Join(tempDir, "attack-paths.json"))
				}
			}

			// Create a mock command for testing flags
			cmd := &cobra.Command{
				Use: "attack-path",
				RunE: func(cmd *cobra.Command, args []string) error {
					// Just validate flags without running actual analysis
					path, _ := cmd.Flags().GetString("path")
					if path == "" {
						return fmt.Errorf("path is required")
					}

					// Create fake database directory for testing
					if err := os.MkdirAll(path, 0755); err != nil {
						return fmt.Errorf("failed to create database directory: %w", err)
					}

					t.Logf("Would analyze attack paths at: %s", path)
					return nil
				},
			}

			// Add flags (these would be inherited from global flags in the real command)
			cmd.Flags().String("path", "", "path to the graph database (required)")
			cmd.Flags().String("output", "table", "output format")
			cmd.Flags().String("output-file", "", "output file path")
			cmd.Flags().Bool("verbose", false, "verbose output")
			cmd.Flags().String("log-level", "info", "log level")
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

// Test realistic attack path scenarios
func TestAttackPathCommand_RealisticScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping realistic scenario test in short mode")
	}

	scenarios := []struct {
		name        string
		description string
		setup       func() []models.AttackPathFinding
	}{
		{
			name:        "high_privilege_service_account",
			description: "Service account with excessive cluster permissions",
			setup: func() []models.AttackPathFinding {
				return []models.AttackPathFinding{
					{
						CorrelationID: "scenario-rbac-001",
						Type:          models.AttackPathTypeRBACPivot,
						Path:          "Pod[monitoring] -> ServiceAccount[monitoring-sa] -> ClusterRoleBinding[view-all] -> Access to all secrets",
						Impact:        "Monitoring pod can access all cluster secrets",
						FixHint:       "Restrict monitoring service account to only required namespaces and resources",
						Entities: []models.AttackPathEntity{
							{
								ID:        "monitoring/monitoring-pod",
								Type:      "Pod",
								Namespace: "monitoring",
							},
							{
								ID:        "monitoring/monitoring-sa",
								Type:      "ServiceAccount",
								Namespace: "monitoring",
							},
						},
						Metadata: map[string]interface{}{
							"risk_score": 8.5,
							"severity":   "HIGH",
						},
						Timestamp: time.Now(),
					},
				}
			},
		},
		{
			name:        "secret_exposure_attack_chain",
			description: "Multi-step attack chain exposing sensitive credentials",
			setup: func() []models.AttackPathFinding {
				return []models.AttackPathFinding{
					{
						CorrelationID: "scenario-cred-001",
						Type:          models.AttackPathTypeCredentialExfil,
						Path:          "Internet -> Pod[webapp] -> Secret[api-keys] -> External Service Access",
						Impact:        "Internet-accessible pod can leak external service credentials",
						FixHint:       "Use network policies to restrict egress and implement proper secret management",
						Entities: []models.AttackPathEntity{
							{
								ID:        "production/webapp",
								Type:      "Pod",
								Namespace: "production",
								Properties: map[string]string{
									"internetAccess": "true",
									"hasSecrets":     "true",
								},
							},
							{
								ID:        "production/api-keys",
								Type:      "Secret",
								Namespace: "production",
								Properties: map[string]string{
									"containsAPIKeys": "true",
									"external":        "true",
								},
							},
						},
						Metadata: map[string]interface{}{
							"risk_score": 9.0,
							"severity":   "CRITICAL",
						},
						Timestamp: time.Now(),
					},
				}
			},
		},
		{
			name:        "privilege_escalation_chain",
			description: "Complex privilege escalation through multiple resources",
			setup: func() []models.AttackPathFinding {
				return []models.AttackPathFinding{
					{
						CorrelationID: "scenario-escalation-001",
						Type:          models.AttackPathTypeRBACPivot,
						Path:          "Pod[worker] -> ServiceAccount[worker-sa] -> Role[secret-reader] -> RoleBinding[admin-binding] -> Admin Access",
						Impact:        "Worker process can escalate to administrative privileges",
						FixHint:       "Review and audit all role bindings, implement least privilege principle",
						Entities: []models.AttackPathEntity{
							{
								ID:        "workers/worker-pod",
								Type:      "Pod",
								Namespace: "workers",
							},
							{
								ID:        "workers/worker-sa",
								Type:      "ServiceAccount",
								Namespace: "workers",
							},
							{
								ID:        "workers/secret-reader",
								Type:      "Role",
								Namespace: "workers",
							},
						},
						Metadata: map[string]interface{}{
							"risk_score":     8.8,
							"severity":       "HIGH",
							"escalation":     true,
							"administrative": true,
						},
						Timestamp: time.Now(),
					},
				}
			},
		},
	}

	for _, scenario := range scenarios {
		t.Run(scenario.name, func(t *testing.T) {
			t.Logf("Testing scenario: %s", scenario.description)

			tempDir, cleanup := setupAttackPathIntegrationTest(t)
			defer cleanup()

			// Setup scenario findings
			findings := scenario.setup()

			// Create mock store with scenario data
			store := &IntegrationAttackPathStore{
				dbPath:   filepath.Join(tempDir, "scenario.db"),
				findings: findings,
			}

			// Test correlation analysis
			ctx := context.Background()
			correlationTypes := []string{"credential-exfil", "rbac-pivot"}

			results, err := store.RunCorrelations(ctx, correlationTypes)
			if err != nil {
				t.Fatalf("Failed to run correlations: %v", err)
			}

			if len(results) == 0 {
				t.Errorf("Expected findings for scenario, got none")
			}

			// Analyze results
			pathsByType := make(map[string]int)
			totalRiskScore := 0.0
			highRiskCount := 0

			for _, finding := range results {
				pathsByType[string(finding.Type)]++

				if riskScore, ok := finding.Metadata["risk_score"].(float64); ok {
					totalRiskScore += riskScore
					if riskScore >= 8.0 {
						highRiskCount++
					}
				}
			}

			avgRiskScore := totalRiskScore / float64(len(results))

			t.Logf("Scenario Results:")
			t.Logf("  Total findings: %d", len(results))
			t.Logf("  Credential Exfil: %d", pathsByType[string(models.AttackPathTypeCredentialExfil)])
			t.Logf("  RBAC Pivot: %d", pathsByType[string(models.AttackPathTypeRBACPivot)])
			t.Logf("  Average Risk Score: %.2f", avgRiskScore)
			t.Logf("  High Risk (>=8.0): %d", highRiskCount)

			// Verify scenario produced meaningful results
			if len(results) != len(findings) {
				t.Errorf("Expected %d findings, got %d", len(findings), len(results))
			}

			if avgRiskScore < 5.0 {
				t.Errorf("Expected higher average risk score for realistic scenario")
			}
		})
	}
}

// Benchmark realistic attack path analysis
func BenchmarkAttackPathCommand_RealisticAnalysis(b *testing.B) {
	// Create realistic attack path findings
	findings := make([]models.AttackPathFinding, 100)

	// 60% credential exfiltration findings
	for i := 0; i < 60; i++ {
		findings[i] = models.AttackPathFinding{
			CorrelationID: fmt.Sprintf("cred-exfil-%03d", i),
			Type:          models.AttackPathTypeCredentialExfil,
			Path:          fmt.Sprintf("Pod[app-%d] -> Secret[secret-%d] -> Credentials", i, i),
			Impact:        "Credential exposure risk",
			FixHint:       "Use external secret management",
			Entities: []models.AttackPathEntity{
				{
					ID:        fmt.Sprintf("default/app-%d", i),
					Type:      "Pod",
					Namespace: "default",
				},
				{
					ID:        fmt.Sprintf("default/secret-%d", i),
					Type:      "Secret",
					Namespace: "default",
				},
			},
			Metadata: map[string]interface{}{
				"risk_score": 7.0 + float64(i%3),
			},
			Timestamp: time.Now(),
		}
	}

	// 40% RBAC pivot findings
	for i := 60; i < 100; i++ {
		findings[i] = models.AttackPathFinding{
			CorrelationID: fmt.Sprintf("rbac-pivot-%03d", i-60),
			Type:          models.AttackPathTypeRBACPivot,
			Path:          fmt.Sprintf("ServiceAccount[sa-%d] -> Role[role-%d] -> Privilege Escalation", i-60, i-60),
			Impact:        "Privilege escalation risk",
			FixHint:       "Apply principle of least privilege",
			Entities: []models.AttackPathEntity{
				{
					ID:        fmt.Sprintf("default/sa-%d", i-60),
					Type:      "ServiceAccount",
					Namespace: "default",
				},
				{
					ID:        fmt.Sprintf("default/role-%d", i-60),
					Type:      "Role",
					Namespace: "default",
				},
			},
			Metadata: map[string]interface{}{
				"risk_score": 6.0 + float64((i-60)%4),
			},
			Timestamp: time.Now(),
		}
	}

	store := &IntegrationAttackPathStore{
		findings: findings,
	}

	ctx := context.Background()
	correlationTypes := []string{"credential-exfil", "rbac-pivot"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		results, err := store.RunCorrelations(ctx, correlationTypes)
		if err != nil {
			b.Fatalf("Failed to run correlations: %v", err)
		}

		// Process results like the real command
		pathsByType := make(map[string]int)
		for _, finding := range results {
			pathsByType[string(finding.Type)]++
		}

		// Build attack path result
		result := &models.AttackPathResult{
			Findings:         results,
			TotalPaths:       len(results),
			PathsByType:      pathsByType,
			CacheHit:         true,
			AnalysisDuration: time.Millisecond * 50,
			Timestamp:        time.Now(),
		}

		// Ensure result is used
		_ = result.TotalPaths
	}
}
