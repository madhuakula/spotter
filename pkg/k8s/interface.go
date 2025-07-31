package k8s

import (
	"context"

	"k8s.io/apimachinery/pkg/runtime/schema"
)

// ResourceInfo contains information about a discovered resource
type ResourceInfo struct {
	GVK        schema.GroupVersionKind
	Namespaced bool
	Verbs      []string
	ShortNames []string
	Categories []string
}

// Client defines the interface for Kubernetes operations
type Client interface {
	// GetResources retrieves all resources of specified types from the cluster
	GetResources(ctx context.Context, gvks []schema.GroupVersionKind, namespaces []string) ([]map[string]interface{}, error)

	// GetResource retrieves a specific resource by name and namespace
	GetResource(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (map[string]interface{}, error)

	// ListNamespaces lists all namespaces in the cluster
	ListNamespaces(ctx context.Context) ([]string, error)

	// WatchResources watches for resource changes
	WatchResources(ctx context.Context, gvks []schema.GroupVersionKind, namespaces []string) (<-chan ResourceEvent, error)

	// ValidateConnection validates the connection to the Kubernetes cluster
	ValidateConnection(ctx context.Context) error

	// DiscoverAllResources discovers all available API resources in the cluster
	DiscoverAllResources(ctx context.Context) ([]schema.GroupVersionKind, error)

	// DiscoverResourcesWithScope discovers all available API resources with scope information
	DiscoverResourcesWithScope(ctx context.Context) ([]ResourceInfo, error)
}

// ResourceEvent represents a resource change event
type ResourceEvent struct {
	Type     EventType              `json:"type"`
	Resource map[string]interface{} `json:"resource"`
	Error    error                  `json:"error,omitempty"`
}

// EventType represents the type of resource event
type EventType string

const (
	EventTypeAdded    EventType = "ADDED"
	EventTypeModified EventType = "MODIFIED"
	EventTypeDeleted  EventType = "DELETED"
	EventTypeError    EventType = "ERROR"
)

// ResourceScanner defines the interface for scanning Kubernetes resources
type ResourceScanner interface {
	// ScanCluster scans the entire cluster for resources
	ScanCluster(ctx context.Context, options ScanOptions) ([]map[string]interface{}, error)

	// ScanNamespaces scans specific namespaces for resources
	ScanNamespaces(ctx context.Context, namespaces []string, options ScanOptions) ([]map[string]interface{}, error)

	// ScanManifests scans YAML/JSON manifests from files or directories
	ScanManifests(ctx context.Context, paths []string, options ScanOptions) ([]map[string]interface{}, error)

	// ScanHelmCharts scans Helm charts for security issues
	ScanHelmCharts(ctx context.Context, chartPaths []string, options ScanOptions) ([]map[string]interface{}, error)
}

// ScanOptions defines options for resource scanning
type ScanOptions struct {
	// IncludeNamespaces specifies namespaces to include
	IncludeNamespaces []string

	// ExcludeNamespaces specifies namespaces to exclude
	ExcludeNamespaces []string

	// ResourceTypes specifies which resource types to scan
	ResourceTypes []schema.GroupVersionKind

	// IncludeSystemNamespaces includes system namespaces like kube-system
	IncludeSystemNamespaces bool

	// IncludeClusterResources includes cluster-scoped resources
	IncludeClusterResources bool

	// Recursive enables recursive scanning of directories
	Recursive bool

	// MaxConcurrency limits the number of concurrent operations
	MaxConcurrency int

	// Timeout specifies the timeout for operations
	Timeout string

	// Performance optimization options
	BatchSize    int    // Number of resources to process in each batch
	CacheEnabled bool   // Enable resource caching
	CacheTTL     string // Cache time-to-live
	Parallelism  int    // Number of parallel workers

	// Memory optimization
	MemoryLimit      int64 // Maximum memory usage in bytes
	ResourcePoolSize int   // Size of resource object pool for reuse

	// Advanced filtering
	MinSeverity   string            // Minimum severity level to report
	ExcludeRules  []string          // Rule IDs to exclude from scanning
	IncludeRules  []string          // Only run these specific rule IDs
	CustomFilters map[string]string // Custom filter expressions

	// NamespacePatterns defines patterns for identifying system namespaces
	// If empty, uses dynamic detection based on common patterns
	NamespacePatterns NamespaceFilterConfig

	// ResourceFilterConfig defines how to filter resources dynamically
	ResourceFilterConfig ResourceFilterConfig

	// HelmOptions defines Helm-specific options for chart scanning
	HelmOptions HelmOptions
}

// NamespaceFilterConfig defines patterns for namespace filtering
type NamespaceFilterConfig struct {
	// SystemPrefixes defines prefixes that indicate system namespaces
	// WARNING: Use with caution as users can create namespaces with these prefixes
	SystemPrefixes []string

	// SystemNames defines exact namespace names that are considered system
	// This is the most secure option for custom system namespaces
	SystemNames []string

	// SystemPatterns defines patterns within namespace names that indicate system namespaces
	// WARNING: Use with caution as users can create namespaces matching these patterns
	SystemPatterns []string

	// UseDynamicDetection enables automatic detection of system namespaces
	// When true, uses secure validation based on Kubernetes metadata and well-known system namespaces
	UseDynamicDetection bool

	// UseSecureValidation enables strict validation that checks namespace metadata
	// to determine if a namespace is truly system-managed (recommended for security)
	UseSecureValidation bool
}

// ResourceFilterConfig defines how to filter resources
type ResourceFilterConfig struct {
	// RequiredVerbs defines verbs that resources must support to be included
	RequiredVerbs []string

	// ExcludedCategories defines resource categories to exclude
	ExcludedCategories []string

	// ExcludedKindPatterns defines patterns in Kind names to exclude
	ExcludedKindPatterns []string

	// UseDynamicFiltering enables intelligent filtering based on resource metadata
	UseDynamicFiltering bool
}

// HelmOptions defines Helm-specific configuration options
type HelmOptions struct {
	// ReleaseName specifies the release name for helm template
	ReleaseName string

	// Namespace specifies the target namespace
	Namespace string

	// KubeVersion specifies the Kubernetes version to use
	KubeVersion string

	// ValuesFiles specifies paths to values files
	ValuesFiles []string

	// SetValues specifies values to set (--set)
	SetValues []string

	// SetStringValues specifies string values to set (--set-string)
	SetStringValues []string

	// SkipCRDs skips Custom Resource Definitions
	SkipCRDs bool

	// SkipTests skips test resources
	SkipTests bool

	// ValidateSchema enables schema validation
	ValidateSchema bool

	// IncludeCRDs includes Custom Resource Definitions
	IncludeCRDs bool

	// UpdateDependencies updates chart dependencies before rendering
	UpdateDependencies bool
}

// ManifestParser defines the interface for parsing Kubernetes manifests
type ManifestParser interface {
	// ParseFile parses a single YAML/JSON file
	ParseFile(ctx context.Context, filePath string) ([]map[string]interface{}, error)

	// ParseDirectory parses all YAML/JSON files in a directory
	ParseDirectory(ctx context.Context, dirPath string, recursive bool) ([]map[string]interface{}, error)

	// ParseContent parses YAML/JSON content from a string
	ParseContent(ctx context.Context, content string) ([]map[string]interface{}, error)

	// ValidateManifest validates a Kubernetes manifest
	ValidateManifest(ctx context.Context, manifest map[string]interface{}) error
}
