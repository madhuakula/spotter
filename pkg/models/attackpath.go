package models

import "time"

// AttackPathFinding represents a single attack path finding
type AttackPathFinding struct {
	CorrelationID string                 `json:"correlation_id"`
	Type          AttackPathType         `json:"type"`
	Path          string                 `json:"path"`
	Impact        string                 `json:"impact"`
	FixHint       string                 `json:"fix_hint"`
	Entities      []AttackPathEntity     `json:"entities"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	Timestamp     time.Time              `json:"timestamp"`
}

// AttackPathType represents the type of attack path
type AttackPathType string

const (
	AttackPathTypeCredentialExfil AttackPathType = "CREDENTIAL_EXFIL"
	AttackPathTypeRBACPivot       AttackPathType = "RBAC_PIVOT"
)

// AttackPathEntity represents an entity in an attack path
type AttackPathEntity struct {
	ID         string            `json:"id"`
	Type       string            `json:"type"`
	Namespace  string            `json:"namespace,omitempty"`
	Properties map[string]string `json:"properties,omitempty"`
}

// AttackPathResult represents the result of attack path analysis
type AttackPathResult struct {
	Findings         []AttackPathFinding `json:"findings"`
	TotalPaths       int                 `json:"total_paths"`
	PathsByType      map[string]int      `json:"paths_by_type"`
	CacheHit         bool                `json:"cache_hit"`
	AnalysisDuration time.Duration       `json:"analysis_duration"`
	Timestamp        time.Time           `json:"timestamp"`
}

// GraphFacts represents the facts extracted from Kubernetes resources for graph storage
type GraphFacts struct {
	Pods            []PodFact            `json:"pods"`
	Secrets         []SecretFact         `json:"secrets"`
	ConfigMaps      []ConfigMapFact      `json:"config_maps"`
	ServiceAccounts []ServiceAccountFact `json:"service_accounts"`
	Roles           []RoleFact           `json:"roles"`
	ApiPermissions  []ApiPermissionFact  `json:"api_permissions"`
	Relationships   []RelationshipFact   `json:"relationships"`
}

// PodFact represents a Pod entity in the graph
type PodFact struct {
	ID         string `json:"id"`
	Namespace  string `json:"namespace"`
	InternetOK bool   `json:"internet_ok"`
}

// SecretFact represents a Secret entity in the graph
type SecretFact struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	CredLike  bool   `json:"cred_like"`
	Reason    string `json:"reason"`
}

// ConfigMapFact represents a ConfigMap entity in the graph
type ConfigMapFact struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
	CredLike  bool   `json:"cred_like"`
	Reason    string `json:"reason"`
}

// ServiceAccountFact represents a ServiceAccount entity in the graph
type ServiceAccountFact struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
}

// RoleFact represents a Role entity in the graph
type RoleFact struct {
	ID        string `json:"id"`
	Namespace string `json:"namespace"`
}

// ApiPermissionFact represents an API permission entity in the graph
type ApiPermissionFact struct {
	ID       string `json:"id"`
	Resource string `json:"resource"`
	Verb     string `json:"verb"`
	Scope    string `json:"scope"`
}

// RelationshipFact represents a relationship between entities in the graph
type RelationshipFact struct {
	Type   RelationshipType `json:"type"`
	FromID string           `json:"from_id"`
	ToID   string           `json:"to_id"`
}

// RelationshipType represents the type of relationship
type RelationshipType string

const (
	RelationshipUsesSecret    RelationshipType = "USES_SECRET"
	RelationshipUsesConfigMap RelationshipType = "USES_CONFIG_MAP"
	RelationshipUsesSA        RelationshipType = "USES_SA"
	RelationshipBoundTo       RelationshipType = "BOUND_TO"
	RelationshipAllows        RelationshipType = "ALLOWS"
)
