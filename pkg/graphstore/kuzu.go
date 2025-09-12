package graphstore

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	kuzu "github.com/kuzudb/go-kuzu"
	"github.com/madhuakula/spotter/pkg/models"
)

// KuzuGraphStore implements GraphStore using Kuzu embedded graph database
type KuzuGraphStore struct {
	database   *kuzu.Database
	connection *kuzu.Connection
	dbPath     string
	lockFile   *os.File
	config     *CacheConfig
}

// NewKuzuGraphStore creates a new Kuzu-based graph store
func NewKuzuGraphStore(config *CacheConfig) *KuzuGraphStore {
	return &KuzuGraphStore{
		config: config,
	}
}

// Open opens the graph database at the specified path
func (k *KuzuGraphStore) Open(path string) error {
	k.dbPath = path

	// Create directory if it doesn't exist
	if err := os.MkdirAll(path, 0700); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	// Acquire exclusive lock for database operations
	lockPath := filepath.Join(path, "LOCK")
	lockFile, err := os.OpenFile(lockPath, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return fmt.Errorf("failed to create lock file: %w", err)
	}

	// Use flock for file locking
	if err := syscall.Flock(int(lockFile.Fd()), syscall.LOCK_EX); err != nil {
		_ = lockFile.Close()
		return fmt.Errorf("failed to acquire exclusive lock: %w", err)
	}
	k.lockFile = lockFile

	// Initialize Kuzu database with custom system config
	systemConfig := kuzu.DefaultSystemConfig()
	// Try with reduced buffer pool size for compatibility
	systemConfig.BufferPoolSize = 256 * 1024 * 1024 // 256MB instead of default
	systemConfig.MaxNumThreads = 4                  // Reduce thread count
	systemConfig.EnableCompression = false          // Disable compression
	systemConfig.ReadOnly = false
	systemConfig.MaxDbSize = 1024 * 1024 * 1024 // 1GB max size
	database, err := kuzu.OpenDatabase(path, systemConfig)
	if err != nil {
		_ = k.ReleaseLock()
		return fmt.Errorf("failed to open Kuzu database: %w", err)
	}
	k.database = database

	// Create connection
	connection, err := kuzu.OpenConnection(database)
	if err != nil {
		k.database.Close()
		_ = k.ReleaseLock()
		return fmt.Errorf("failed to open Kuzu connection: %w", err)
	}
	k.connection = connection

	return nil
}

// Close closes the graph database connection
func (k *KuzuGraphStore) Close() error {
	var errs []error

	if k.connection != nil {
		k.connection.Close()
	}

	if k.database != nil {
		k.database.Close()
	}

	if err := k.ReleaseLock(); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("errors during close: %v", errs)
	}

	return nil
}

// ReleaseLock releases the file lock
func (k *KuzuGraphStore) ReleaseLock() error {
	if k.lockFile != nil {
		if err := syscall.Flock(int(k.lockFile.Fd()), syscall.LOCK_UN); err != nil {
			_ = k.lockFile.Close()
			return fmt.Errorf("failed to release lock: %w", err)
		}
		if err := k.lockFile.Close(); err != nil {
			return fmt.Errorf("failed to close lock file: %w", err)
		}
		k.lockFile = nil
	}
	return nil
}

// EnsureSchema creates the required node and relationship tables
func (k *KuzuGraphStore) EnsureSchema(ctx context.Context) error {
	schema := []string{
		"CREATE NODE TABLE IF NOT EXISTS Pod(id STRING PRIMARY KEY, ns STRING, internet_ok BOOL);",
		"CREATE NODE TABLE IF NOT EXISTS Secret(id STRING PRIMARY KEY, ns STRING, cred_like BOOL, reason STRING);",
		"CREATE NODE TABLE IF NOT EXISTS ConfigMap(id STRING PRIMARY KEY, ns STRING, cred_like BOOL, reason STRING);",
		"CREATE NODE TABLE IF NOT EXISTS ServiceAccount(id STRING PRIMARY KEY, ns STRING);",
		"CREATE NODE TABLE IF NOT EXISTS Role(id STRING PRIMARY KEY, ns STRING);",
		"CREATE NODE TABLE IF NOT EXISTS ApiPerm(id STRING PRIMARY KEY, resource STRING, verb STRING, scope STRING);",
		"CREATE REL TABLE IF NOT EXISTS UsesSecret(FROM Pod TO Secret);",
		"CREATE REL TABLE IF NOT EXISTS UsesConfigMap(FROM Pod TO ConfigMap);",
		"CREATE REL TABLE IF NOT EXISTS UsesSA(FROM Pod TO ServiceAccount);",
		"CREATE REL TABLE IF NOT EXISTS BoundTo(FROM ServiceAccount TO Role);",
		"CREATE REL TABLE IF NOT EXISTS Allows(FROM Role TO ApiPerm);",
	}

	for _, stmt := range schema {
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to execute schema statement '%s': %w", stmt, err)
		}
		result.Close()
	}

	return nil
}

// UpsertFacts inserts or updates facts in the graph
func (k *KuzuGraphStore) UpsertFacts(ctx context.Context, facts *models.GraphFacts) error {
	// Clear existing data first (for simplicity in MVP)
	// First clear all relationships, then nodes
	clearStatements := []string{
		"MATCH ()-[r:UsesSecret]-() DELETE r;",
		"MATCH ()-[r:UsesConfigMap]-() DELETE r;",
		"MATCH ()-[r:UsesSA]-() DELETE r;",
		"MATCH ()-[r:BoundTo]-() DELETE r;",
		"MATCH ()-[r:Allows]-() DELETE r;",
		"MATCH (n:Pod) DELETE n;",
		"MATCH (n:Secret) DELETE n;",
		"MATCH (n:ConfigMap) DELETE n;",
		"MATCH (n:ServiceAccount) DELETE n;",
		"MATCH (n:Role) DELETE n;",
		"MATCH (n:ApiPerm) DELETE n;",
	}

	for _, stmt := range clearStatements {
		result, err := k.connection.Query(stmt)
		if err != nil {
			// Ignore errors for non-existent tables
			continue
		}
		result.Close()
	}

	// Insert Pods
	for _, pod := range facts.Pods {
		stmt := fmt.Sprintf("CREATE (p:Pod {id: '%s', ns: '%s', internet_ok: %t});",
			escapeCypher(pod.ID), escapeCypher(pod.Namespace), pod.InternetOK)
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert pod %s: %w", pod.ID, err)
		}
		result.Close()
	}

	// Insert Secrets
	for _, secret := range facts.Secrets {
		stmt := fmt.Sprintf("CREATE (s:Secret {id: '%s', ns: '%s', cred_like: %t, reason: '%s'});",
			escapeCypher(secret.ID), escapeCypher(secret.Namespace), secret.CredLike, escapeCypher(secret.Reason))
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert secret %s: %w", secret.ID, err)
		}
		result.Close()
	}

	// Insert ConfigMaps
	for _, cm := range facts.ConfigMaps {
		stmt := fmt.Sprintf("CREATE (c:ConfigMap {id: '%s', ns: '%s', cred_like: %t, reason: '%s'});",
			escapeCypher(cm.ID), escapeCypher(cm.Namespace), cm.CredLike, escapeCypher(cm.Reason))
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert configmap %s: %w", cm.ID, err)
		}
		result.Close()
	}

	// Insert ServiceAccounts
	for _, sa := range facts.ServiceAccounts {
		stmt := fmt.Sprintf("CREATE (sa:ServiceAccount {id: '%s', ns: '%s'});",
			escapeCypher(sa.ID), escapeCypher(sa.Namespace))
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert service account %s: %w", sa.ID, err)
		}
		result.Close()
	}

	// Insert Roles
	for _, role := range facts.Roles {
		stmt := fmt.Sprintf("CREATE (r:Role {id: '%s', ns: '%s'});",
			escapeCypher(role.ID), escapeCypher(role.Namespace))
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert role %s: %w", role.ID, err)
		}
		result.Close()
	}

	// Insert API Permissions
	for _, perm := range facts.ApiPermissions {
		stmt := fmt.Sprintf("CREATE (ap:ApiPerm {id: '%s', resource: '%s', verb: '%s', scope: '%s'});",
			escapeCypher(perm.ID), escapeCypher(perm.Resource), escapeCypher(perm.Verb), escapeCypher(perm.Scope))
		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert api permission %s: %w", perm.ID, err)
		}
		result.Close()
	}

	// Insert Relationships
	for _, rel := range facts.Relationships {
		var stmt string
		switch rel.Type {
		case models.RelationshipUsesSecret:
			stmt = fmt.Sprintf("MATCH (p:Pod {id: '%s'}), (s:Secret {id: '%s'}) CREATE (p)-[:UsesSecret]->(s);",
				escapeCypher(rel.FromID), escapeCypher(rel.ToID))
		case models.RelationshipUsesConfigMap:
			stmt = fmt.Sprintf("MATCH (p:Pod {id: '%s'}), (c:ConfigMap {id: '%s'}) CREATE (p)-[:UsesConfigMap]->(c);",
				escapeCypher(rel.FromID), escapeCypher(rel.ToID))
		case models.RelationshipUsesSA:
			stmt = fmt.Sprintf("MATCH (p:Pod {id: '%s'}), (sa:ServiceAccount {id: '%s'}) CREATE (p)-[:UsesSA]->(sa);",
				escapeCypher(rel.FromID), escapeCypher(rel.ToID))
		case models.RelationshipBoundTo:
			stmt = fmt.Sprintf("MATCH (sa:ServiceAccount {id: '%s'}), (r:Role {id: '%s'}) CREATE (sa)-[:BoundTo]->(r);",
				escapeCypher(rel.FromID), escapeCypher(rel.ToID))
		case models.RelationshipAllows:
			stmt = fmt.Sprintf("MATCH (r:Role {id: '%s'}), (ap:ApiPerm {id: '%s'}) CREATE (r)-[:Allows]->(ap);",
				escapeCypher(rel.FromID), escapeCypher(rel.ToID))
		default:
			continue
		}

		result, err := k.connection.Query(stmt)
		if err != nil {
			return fmt.Errorf("failed to insert relationship %s->%s: %w", rel.FromID, rel.ToID, err)
		}
		result.Close()
	}

	return nil
}

// RunCorrelations executes correlation queries and returns findings
func (k *KuzuGraphStore) RunCorrelations(ctx context.Context, correlationTypes []string) ([]models.AttackPathFinding, error) {
	var findings []models.AttackPathFinding

	for _, corrType := range correlationTypes {
		switch corrType {
		case "credential-exfil":
			credFindings, err := k.runCredentialExfilQuery(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to run credential exfil query: %w", err)
			}
			findings = append(findings, credFindings...)

		case "rbac-pivot":
			rbacFindings, err := k.runRBACPivotQuery(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to run RBAC pivot query: %w", err)
			}
			findings = append(findings, rbacFindings...)
		}
	}

	return findings, nil
}

// runCredentialExfilQuery executes the credential exfiltration correlation query
func (k *KuzuGraphStore) runCredentialExfilQuery(ctx context.Context) ([]models.AttackPathFinding, error) {
	query := `
		MATCH (p:Pod)-[:UsesSecret|:UsesConfigMap]->(c)
		WHERE c.cred_like = true AND p.internet_ok = true
		RETURN DISTINCT p.id AS pod, p.ns AS ns, LABEL(c) AS cred_type, c.id AS cred_id;
	`

	result, err := k.connection.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute credential exfil query: %w", err)
	}
	defer result.Close()

	var findings []models.AttackPathFinding
	for result.HasNext() {
		row, err := result.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read query result: %w", err)
		}

		pod, err := row.GetValue(0)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod value: %w", err)
		}
		ns, err := row.GetValue(1)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespace value: %w", err)
		}
		credType, err := row.GetValue(2)
		if err != nil {
			return nil, fmt.Errorf("failed to get cred type value: %w", err)
		}
		credID, err := row.GetValue(3)
		if err != nil {
			return nil, fmt.Errorf("failed to get cred ID value: %w", err)
		}

		finding := models.AttackPathFinding{
			CorrelationID: "KZ-EXFIL-001",
			Type:          models.AttackPathTypeCredentialExfil,
			Path:          fmt.Sprintf("Pod %s → %s %s → Internet", pod.(string), credType.(string), credID.(string)),
			Impact:        "Potential credential exfiltration to external networks",
			FixHint:       "Remove internet access or use workload identity instead of mounted secrets",
			Entities: []models.AttackPathEntity{
				{ID: pod.(string), Type: "Pod", Namespace: ns.(string)},
				{ID: credID.(string), Type: credType.(string), Namespace: ns.(string)},
			},
			Timestamp: time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// runRBACPivotQuery executes the RBAC pivot correlation query
func (k *KuzuGraphStore) runRBACPivotQuery(ctx context.Context) ([]models.AttackPathFinding, error) {
	query := `
		MATCH (p:Pod)-[:UsesSA]->(sa:ServiceAccount)
		MATCH (sa)-[:BoundTo]->(r:Role)-[:Allows]->(perm:ApiPerm)
		WHERE (perm.resource = 'secrets' AND perm.verb IN ['get','list','watch'])
		   OR (perm.resource = 'pods/exec' AND perm.verb = 'create')
		RETURN DISTINCT p.id AS pod, p.ns AS ns, sa.id AS service_account, r.id AS role,
		       collect(distinct perm.resource + ':' + perm.verb) AS capabilities;
	`

	result, err := k.connection.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to execute RBAC pivot query: %w", err)
	}
	defer result.Close()

	var findings []models.AttackPathFinding
	for result.HasNext() {
		row, err := result.Next()
		if err != nil {
			return nil, fmt.Errorf("failed to read query result: %w", err)
		}

		pod, err := row.GetValue(0)
		if err != nil {
			return nil, fmt.Errorf("failed to get pod value: %w", err)
		}
		ns, err := row.GetValue(1)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespace value: %w", err)
		}
		sa, err := row.GetValue(2)
		if err != nil {
			return nil, fmt.Errorf("failed to get service account value: %w", err)
		}
		role, err := row.GetValue(3)
		if err != nil {
			return nil, fmt.Errorf("failed to get role value: %w", err)
		}
		capabilities, err := row.GetValue(4)
		if err != nil {
			return nil, fmt.Errorf("failed to get capabilities value: %w", err)
		}

		var capStrings []string
		if capList, ok := capabilities.([]interface{}); ok {
			for _, cap := range capList {
				if capStr, ok := cap.(string); ok {
					capStrings = append(capStrings, capStr)
				}
			}
		}

		finding := models.AttackPathFinding{
			CorrelationID: "KZ-RBAC-001",
			Type:          models.AttackPathTypeRBACPivot,
			Path:          fmt.Sprintf("Pod %s → SA %s → Role %s (%s)", pod.(string), sa.(string), role.(string), strings.Join(capStrings, ", ")),
			Impact:        "Potential privilege escalation through RBAC permissions",
			FixHint:       "Apply principle of least privilege to service account permissions",
			Entities: []models.AttackPathEntity{
				{ID: pod.(string), Type: "Pod", Namespace: ns.(string)},
				{ID: sa.(string), Type: "ServiceAccount", Namespace: ns.(string)},
				{ID: role.(string), Type: "Role", Namespace: ns.(string)},
			},
			Timestamp: time.Now(),
		}
		findings = append(findings, finding)
	}

	return findings, nil
}

// Invalidate deletes the database directory
func (k *KuzuGraphStore) Invalidate() error {
	if k.dbPath == "" {
		return nil
	}

	// Close connections first
	if err := k.Close(); err != nil {
		return fmt.Errorf("failed to close database before invalidation: %w", err)
	}

	// Remove the entire database directory
	if err := os.RemoveAll(k.dbPath); err != nil {
		return fmt.Errorf("failed to remove database directory: %w", err)
	}

	return nil
}

// IsStale checks if the database is stale based on TTL
func (k *KuzuGraphStore) IsStale(ttl time.Duration) (bool, error) {
	if k.dbPath == "" {
		return true, nil
	}

	info, err := os.Stat(k.dbPath)
	if os.IsNotExist(err) {
		return true, nil
	}
	if err != nil {
		return true, fmt.Errorf("failed to stat database directory: %w", err)
	}

	return time.Since(info.ModTime()) > ttl, nil
}

// GetLastModified returns the last modification time of the database
func (k *KuzuGraphStore) GetLastModified() (time.Time, error) {
	if k.dbPath == "" {
		return time.Time{}, fmt.Errorf("database path not set")
	}

	info, err := os.Stat(k.dbPath)
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to stat database directory: %w", err)
	}

	return info.ModTime(), nil
}

// escapeCypher escapes single quotes in Cypher string literals
func escapeCypher(s string) string {
	return strings.ReplaceAll(s, "'", "\\'")
}

// GenerateCacheKey generates a cache key based on target and schema version
func GenerateCacheKey(target, schemaVersion string) string {
	hash := sha256.Sum256([]byte(target + schemaVersion))
	return fmt.Sprintf("%x", hash)[:16]
}
