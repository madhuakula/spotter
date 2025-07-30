package k8s

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/yaml"
)

// Scanner implements the ResourceScanner interface
type Scanner struct {
	client Client
	parser ManifestParser
	cache  *ResourceCache
	metrics *ScanMetrics
}

// ResourceCache provides caching for scanned resources
type ResourceCache struct {
	mu    sync.RWMutex
	data  map[string]CacheEntry
	ttl   time.Duration
}

// CacheEntry represents a cached resource entry
type CacheEntry struct {
	resources []map[string]interface{}
	timestamp time.Time
}

// ScanMetrics tracks scanning performance metrics
type ScanMetrics struct {
	mu              sync.RWMutex
	ResourcesScanned int64
	BatchesProcessed int64
	CacheHits       int64
	CacheMisses     int64
	ScanDuration    time.Duration
	MemoryUsage     int64
}

// NewScanner creates a new resource scanner
func NewScanner(client Client) ResourceScanner {
	return &Scanner{
		client: client,
		parser: NewManifestParser(),
		cache:  NewResourceCache(5 * time.Minute),
		metrics: &ScanMetrics{},
	}
}

// NewResourceCache creates a new resource cache with specified TTL
func NewResourceCache(ttl time.Duration) *ResourceCache {
	return &ResourceCache{
		data: make(map[string]CacheEntry),
		ttl:  ttl,
	}
}

// Get retrieves a cached entry if it exists and is not expired
func (c *ResourceCache) Get(key string) ([]map[string]interface{}, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	
	entry, exists := c.data[key]
	if !exists {
		return nil, false
	}
	
	if time.Since(entry.timestamp) > c.ttl {
		delete(c.data, key)
		return nil, false
	}
	
	return entry.resources, true
}

// Set stores a cache entry
func (c *ResourceCache) Set(key string, resources []map[string]interface{}) {
	c.mu.Lock()
	defer c.mu.Unlock()
	
	c.data[key] = CacheEntry{
		resources: resources,
		timestamp: time.Now(),
	}
}

// Clear removes all cached entries
func (c *ResourceCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data = make(map[string]CacheEntry)
}

// GetMetrics returns current scan metrics
func (s *Scanner) GetMetrics() ScanMetrics {
	s.metrics.mu.RLock()
	defer s.metrics.mu.RUnlock()
	return *s.metrics
}

// updateMemoryUsage updates the current memory usage metric
func (s *Scanner) updateMemoryUsage() {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s.metrics.mu.Lock()
	s.metrics.MemoryUsage = int64(m.Alloc)
	s.metrics.mu.Unlock()
}

// generateCacheKey creates a cache key based on scan type and options
func (s *Scanner) generateCacheKey(scanType string, options ScanOptions) string {
	// Create a simple cache key based on scan parameters
	key := fmt.Sprintf("%s:%v:%v:%v", scanType, options.ResourceTypes, options.IncludeNamespaces, options.ExcludeNamespaces)
	return key
}

// processBatch processes resources in batches for better performance
func (s *Scanner) processBatch(ctx context.Context, resources []map[string]interface{}, batchSize int, options ScanOptions) []map[string]interface{} {
	if batchSize <= 0 {
		batchSize = 100 // Default batch size
	}

	var result []map[string]interface{}
	for i := 0; i < len(resources); i += batchSize {
		end := i + batchSize
		if end > len(resources) {
			end = len(resources)
		}
		batch := resources[i:end]
		processedBatch := s.filterResources(batch, options)
		result = append(result, processedBatch...)
		
		s.metrics.mu.Lock()
		s.metrics.BatchesProcessed++
		s.metrics.ResourcesScanned += int64(len(batch))
		s.metrics.mu.Unlock()
		
		// Check memory limits and trigger GC if needed
		if options.MemoryLimit > 0 {
			s.checkMemoryLimit(options.MemoryLimit)
		}
	}
	return result
}

// checkMemoryLimit checks if memory usage exceeds limit and triggers GC
func (s *Scanner) checkMemoryLimit(limit int64) {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	if int64(m.Alloc) > limit {
		runtime.GC()
	}
}

// processParallel processes resources in parallel for better performance
func (s *Scanner) processParallel(ctx context.Context, resources []map[string]interface{}, parallelism int, options ScanOptions) []map[string]interface{} {
	if parallelism <= 0 {
		parallelism = runtime.NumCPU()
	}

	if len(resources) == 0 {
		return resources
	}

	// Calculate batch size for parallel processing
	batchSize := len(resources) / parallelism
	if batchSize == 0 {
		batchSize = 1
	}

	var wg sync.WaitGroup
	resultChan := make(chan []map[string]interface{}, parallelism)

	for i := 0; i < len(resources); i += batchSize {
		end := i + batchSize
		if end > len(resources) {
			end = len(resources)
		}

		wg.Add(1)
		go func(batch []map[string]interface{}) {
			defer wg.Done()
			processed := s.filterResources(batch, options)
			resultChan <- processed
		}(resources[i:end])
	}

	go func() {
		wg.Wait()
		close(resultChan)
	}()

	var result []map[string]interface{}
	for batch := range resultChan {
		result = append(result, batch...)
	}

	return result
}

// ScanCluster scans the entire cluster for resources with optimization features
func (s *Scanner) ScanCluster(ctx context.Context, options ScanOptions) ([]map[string]interface{}, error) {
	start := time.Now()
	defer func() {
		s.metrics.mu.Lock()
		s.metrics.ScanDuration = time.Since(start)
		s.metrics.mu.Unlock()
		s.updateMemoryUsage()
	}()

	// Check cache if enabled
	if options.CacheEnabled {
		cacheKey := s.generateCacheKey("cluster", options)
		if cached, found := s.cache.Get(cacheKey); found {
			s.metrics.mu.Lock()
			s.metrics.CacheHits++
			s.metrics.mu.Unlock()
			return cached, nil
		}
		s.metrics.mu.Lock()
		s.metrics.CacheMisses++
		s.metrics.mu.Unlock()
	}

	// Original scanning logic with optimization
	resourceInfos, gvks, err := s.determineResourceTypesWithScope(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to determine resource types: %w", err)
	}
	if len(gvks) == 0 {
		return nil, fmt.Errorf("no resource types specified")
	}

	// Separate cluster-scoped and namespaced resources
	clusterScopedGVKs := []schema.GroupVersionKind{}
	namespacedGVKs := []schema.GroupVersionKind{}

	for _, gvk := range gvks {
		if s.isClusterScopedResource(gvk, resourceInfos) {
			clusterScopedGVKs = append(clusterScopedGVKs, gvk)
		} else {
			namespacedGVKs = append(namespacedGVKs, gvk)
		}
	}

	var allResources []map[string]interface{}

	// Get cluster-scoped resources
	if len(clusterScopedGVKs) > 0 && options.IncludeClusterResources {
		clusterResources, err := s.client.GetResources(ctx, clusterScopedGVKs, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get cluster-scoped resources: %w", err)
		}
		allResources = append(allResources, clusterResources...)
	}

	// Get namespaced resources
	if len(namespacedGVKs) > 0 {
		namespaces, err := s.determineNamespaces(ctx, options)
		if err != nil {
			return nil, fmt.Errorf("failed to determine namespaces: %w", err)
		}

		namespacedResources, err := s.client.GetResources(ctx, namespacedGVKs, namespaces)
		if err != nil {
			return nil, fmt.Errorf("failed to get namespaced resources: %w", err)
		}
		allResources = append(allResources, namespacedResources...)
	}

	// Apply optimization based on options
	var result []map[string]interface{}
	if options.Parallelism > 1 {
		result = s.processParallel(ctx, allResources, options.Parallelism, options)
	} else if options.BatchSize > 0 {
		result = s.processBatch(ctx, allResources, options.BatchSize, options)
	} else {
		result = s.filterResources(allResources, options)
	}

	// Cache results if enabled
	if options.CacheEnabled {
		cacheKey := s.generateCacheKey("cluster", options)
		s.cache.Set(cacheKey, result)
	}

	return result, nil
}

// ScanNamespaces scans specific namespaces for resources
func (s *Scanner) ScanNamespaces(ctx context.Context, namespaces []string, options ScanOptions) ([]map[string]interface{}, error) {
	_, gvks, err := s.determineResourceTypesWithScope(ctx, options)
	if err != nil {
		return nil, fmt.Errorf("failed to determine resource types: %w", err)
	}
	if len(gvks) == 0 {
		return nil, fmt.Errorf("no resource types specified")
	}

	resources, err := s.client.GetResources(ctx, gvks, namespaces)
	if err != nil {
		return nil, fmt.Errorf("failed to get resources: %w", err)
	}

	return s.filterResources(resources, options), nil
}

// ScanManifests scans YAML/JSON manifests from files or directories
func (s *Scanner) ScanManifests(ctx context.Context, paths []string, options ScanOptions) ([]map[string]interface{}, error) {
	var allResources []map[string]interface{}

	for _, path := range paths {
		resources, err := s.scanPath(ctx, path, options)
		if err != nil {
			return nil, fmt.Errorf("failed to scan path %s: %w", path, err)
		}
		allResources = append(allResources, resources...)
	}

	return s.filterResources(allResources, options), nil
}

// ScanHelmCharts scans Helm charts for security issues
func (s *Scanner) ScanHelmCharts(ctx context.Context, chartPaths []string, options ScanOptions) ([]map[string]interface{}, error) {
	var allResources []map[string]interface{}

	for _, chartPath := range chartPaths {
		// Render the Helm chart using helm template command
		renderedManifests, err := s.renderHelmChart(ctx, chartPath, options)
		if err != nil {
			return nil, fmt.Errorf("failed to render Helm chart %s: %w", chartPath, err)
		}

		// Parse the rendered manifests
		resources, err := s.parser.ParseContent(ctx, renderedManifests)
		if err != nil {
			return nil, fmt.Errorf("failed to parse rendered manifests from chart %s: %w", chartPath, err)
		}

		// Filter resources based on scan options
		filteredResources := s.filterResources(resources, options)
		allResources = append(allResources, filteredResources...)
	}

	return allResources, nil
}

// renderHelmChart renders a Helm chart using the helm template command
func (s *Scanner) renderHelmChart(ctx context.Context, chartPath string, options ScanOptions) (string, error) {
	// Build helm template command
	args := []string{"template"}
	
	// Add release name if specified
	if options.HelmOptions.ReleaseName != "" {
		args = append(args, options.HelmOptions.ReleaseName)
	}
	
	// Add chart path
	args = append(args, chartPath)
	
	// Add namespace if specified
	if options.HelmOptions.Namespace != "" {
		args = append(args, "--namespace", options.HelmOptions.Namespace)
	}
	
	// Add Kubernetes version if specified
	if options.HelmOptions.KubeVersion != "" {
		args = append(args, "--kube-version", options.HelmOptions.KubeVersion)
	}
	
	// Add values files
	for _, valuesFile := range options.HelmOptions.ValuesFiles {
		args = append(args, "--values", valuesFile)
	}
	
	// Add set values
	for _, setValue := range options.HelmOptions.SetValues {
		args = append(args, "--set", setValue)
	}
	
	// Add set-string values
	for _, setStringValue := range options.HelmOptions.SetStringValues {
		args = append(args, "--set-string", setStringValue)
	}
	
	// Add other flags
	if options.HelmOptions.SkipCRDs {
		args = append(args, "--skip-crds")
	}
	
	if options.HelmOptions.SkipTests {
		args = append(args, "--skip-tests")
	}
	
	if options.HelmOptions.ValidateSchema {
		args = append(args, "--validate")
	}
	
	if options.HelmOptions.IncludeCRDs {
		args = append(args, "--include-crds")
	}
	
	// Execute helm template command
	cmd := exec.CommandContext(ctx, "helm", args...)
	output, err := cmd.Output()
	if err != nil {
		if exitError, ok := err.(*exec.ExitError); ok {
			return "", fmt.Errorf("helm template failed: %s", string(exitError.Stderr))
		}
		return "", fmt.Errorf("failed to execute helm template: %w", err)
	}
	
	return string(output), nil
}

// Helper methods

func (s *Scanner) determineNamespaces(ctx context.Context, options ScanOptions) ([]string, error) {
	if len(options.IncludeNamespaces) > 0 {
		return options.IncludeNamespaces, nil
	}

	allNamespaces, err := s.client.ListNamespaces(ctx)
	if err != nil {
		return nil, err
	}

	var filteredNamespaces []string
	for _, ns := range allNamespaces {
		if s.shouldIncludeNamespace(ns, options) {
			filteredNamespaces = append(filteredNamespaces, ns)
		}
	}

	return filteredNamespaces, nil
}

func (s *Scanner) shouldIncludeNamespace(namespace string, options ScanOptions) bool {
	// Check exclude list
	for _, excluded := range options.ExcludeNamespaces {
		if namespace == excluded {
			return false
		}
	}

	// Check system namespaces
	if !options.IncludeSystemNamespaces && s.isSystemNamespace(namespace, options.NamespacePatterns) {
		return false
	}

	return true
}

// isSystemNamespace checks if a namespace is a system namespace using secure validation
func (s *Scanner) isSystemNamespace(namespace string, config NamespaceFilterConfig) bool {
	// If secure validation is enabled, prioritize metadata-based detection
	if config.UseSecureValidation {
		// First check exact matches from config (highest priority)
		for _, sysNs := range config.SystemNames {
			if namespace == sysNs {
				return true
			}
		}
		
		// Then use secure metadata-based validation
		return s.isWellKnownSystemNamespace(namespace)
	}
	
	// Legacy mode: if dynamic detection is disabled and no custom patterns provided, use minimal defaults
	if !config.UseDynamicDetection && len(config.SystemPrefixes) == 0 && len(config.SystemNames) == 0 && len(config.SystemPatterns) == 0 {
		return false
	}
	
	// Check exact matches from config (highest priority)
	for _, sysNs := range config.SystemNames {
		if namespace == sysNs {
			return true
		}
	}
	
	// Check prefixes from config (only if explicitly configured and secure validation is disabled)
	if !config.UseSecureValidation {
		for _, prefix := range config.SystemPrefixes {
			if strings.HasPrefix(namespace, prefix) {
				return true
			}
		}
		
		// Check patterns from config (only if explicitly configured and secure validation is disabled)
		for _, pattern := range config.SystemPatterns {
			if strings.Contains(namespace, pattern) {
				return true
			}
		}
	}
	
	// Dynamic detection - use secure validation if available
	if config.UseDynamicDetection {
		return s.isWellKnownSystemNamespace(namespace)
	}
	
	return false
}

// isWellKnownSystemNamespace checks against a strict list of known Kubernetes system namespaces
// These are namespaces that are created and managed by Kubernetes itself, not user-created
func (s *Scanner) isWellKnownSystemNamespace(namespace string) bool {
	// Core Kubernetes system namespaces that are created by the system
	// These cannot be created by regular users and are managed by Kubernetes
	wellKnownSystemNamespaces := map[string]bool{
		"kube-system":      true, // Core Kubernetes components
		"kube-public":      true, // Publicly readable cluster info
		"kube-node-lease":  true, // Node heartbeat leases
		"kubernetes-dashboard": true, // Official Kubernetes dashboard
	}
	
	// Check exact matches for well-known system namespaces
	if wellKnownSystemNamespaces[namespace] {
		return true
	}
	
	// Additional validation: check if namespace has system-managed labels/annotations
	// This provides a more secure way to identify system namespaces
	return s.hasSystemManagedMetadata(namespace)
}

// hasSystemManagedMetadata checks if a namespace has metadata indicating it's system-managed
func (s *Scanner) hasSystemManagedMetadata(namespace string) bool {
	// Try to get namespace metadata to check for system indicators
	ctx := context.Background()
	namespaceResource, err := s.client.GetResource(ctx, 
		schema.GroupVersionKind{Group: "", Version: "v1", Kind: "Namespace"}, 
		"", namespace)
	if err != nil {
		// If we can't get the namespace, assume it's not system-managed
		return false
	}
	
	// Check for system-managed labels
	if labels, ok := namespaceResource["metadata"].(map[string]interface{})["labels"].(map[string]interface{}); ok {
		// Check for Kubernetes system labels
		if _, hasSystemLabel := labels["kubernetes.io/managed-by"]; hasSystemLabel {
			return true
		}
		if _, hasSystemLabel := labels["control-plane"]; hasSystemLabel {
			return true
		}
		if managedBy, ok := labels["app.kubernetes.io/managed-by"].(string); ok {
			if managedBy == "kube-system" || managedBy == "kubernetes" {
				return true
			}
		}
	}
	
	// Check for system-managed annotations
	if annotations, ok := namespaceResource["metadata"].(map[string]interface{})["annotations"].(map[string]interface{}); ok {
		// Check for system annotations
		if _, hasSystemAnnotation := annotations["kubernetes.io/managed-by"]; hasSystemAnnotation {
			return true
		}
	}
	
	return false
}

func (s *Scanner) isClusterScopedResource(gvk schema.GroupVersionKind, resourceInfos []ResourceInfo) bool {
	// Find the resource info for this GVK
	for _, info := range resourceInfos {
		if info.GVK.Group == gvk.Group && info.GVK.Version == gvk.Version && info.GVK.Kind == gvk.Kind {
			return !info.Namespaced
		}
	}
	// Default to namespaced if not found
	return false
}

func (s *Scanner) determineResourceTypes(ctx context.Context, options ScanOptions) ([]schema.GroupVersionKind, error) {
	_, gvks, err := s.determineResourceTypesWithScope(ctx, options)
	return gvks, err
}

func (s *Scanner) determineResourceTypesWithScope(ctx context.Context, options ScanOptions) ([]ResourceInfo, []schema.GroupVersionKind, error) {
	if len(options.ResourceTypes) > 0 {
		// If specific resource types are provided, we still need to get their scope info
		allResourceInfos, err := s.client.DiscoverResourcesWithScope(ctx)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to discover cluster resources: %w", err)
		}
		return allResourceInfos, options.ResourceTypes, nil
	}

	// Dynamically discover all available resources in the cluster
	allResourceInfos, err := s.client.DiscoverResourcesWithScope(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to discover cluster resources: %w", err)
	}

	// Create a more intelligent filtering system
	var filteredResourceInfos []ResourceInfo
	var filteredGVKs []schema.GroupVersionKind

	for _, info := range allResourceInfos {
		if s.shouldIncludeResource(info, options.ResourceFilterConfig) {
			filteredResourceInfos = append(filteredResourceInfos, info)
			filteredGVKs = append(filteredGVKs, info.GVK)
		}
	}

	return filteredResourceInfos, filteredGVKs, nil
}

// shouldIncludeResource determines if a resource should be included in scanning
// based on its characteristics and the provided configuration
func (s *Scanner) shouldIncludeResource(info ResourceInfo, config ResourceFilterConfig) bool {
	// If dynamic filtering is disabled and no custom config provided, include all resources
	if !config.UseDynamicFiltering && len(config.RequiredVerbs) == 0 && len(config.ExcludedCategories) == 0 && len(config.ExcludedKindPatterns) == 0 {
		return true
	}

	// Check required verbs (default to "list" if not specified)
	requiredVerbs := config.RequiredVerbs
	if len(requiredVerbs) == 0 && config.UseDynamicFiltering {
		requiredVerbs = []string{"list"}
	}
	
	for _, requiredVerb := range requiredVerbs {
		hasVerb := false
		for _, verb := range info.Verbs {
			if verb == requiredVerb {
				hasVerb = true
				break
			}
		}
		if !hasVerb {
			return false
		}
	}

	// Check excluded categories
	excludedCategories := config.ExcludedCategories
	if len(excludedCategories) == 0 && config.UseDynamicFiltering {
		excludedCategories = []string{"events", "metrics"}
	}
	
	for _, category := range info.Categories {
		for _, excluded := range excludedCategories {
			if category == excluded {
				return false
			}
		}
	}

	// Check excluded kind patterns
	excludedPatterns := config.ExcludedKindPatterns
	if len(excludedPatterns) == 0 && config.UseDynamicFiltering {
		// Default patterns for problematic resources
		excludedPatterns = []string{
			"Event", "Endpoints", "EndpointSlice", "ComponentStatus", "Binding", "TokenReview",
			"Lease", "Status", "NodeMetrics", "PodMetrics",
			"AccessReview", "SubjectReview", "metrics",
		}
	}
	
	for _, pattern := range excludedPatterns {
		if strings.Contains(strings.ToLower(info.GVK.Kind), strings.ToLower(pattern)) {
			return false
		}
	}

	return true
}

func (s *Scanner) filterResources(resources []map[string]interface{}, options ScanOptions) []map[string]interface{} {
	// TODO: Implement resource filtering based on options
	// This could include filtering by labels, annotations, etc.
	return resources
}

func (s *Scanner) scanPath(ctx context.Context, path string, options ScanOptions) ([]map[string]interface{}, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if info.IsDir() {
		return s.parser.ParseDirectory(ctx, path, options.Recursive)
	}

	return s.parser.ParseFile(ctx, path)
}

// FileManifestParser implements the ManifestParser interface
type FileManifestParser struct{}

// NewManifestParser creates a new manifest parser
func NewManifestParser() ManifestParser {
	return &FileManifestParser{}
}

// ParseFile parses a single YAML/JSON file
func (p *FileManifestParser) ParseFile(ctx context.Context, filePath string) ([]map[string]interface{}, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filePath, err)
	}

	return p.ParseContent(ctx, string(content))
}

// ParseDirectory parses all YAML/JSON files in a directory
func (p *FileManifestParser) ParseDirectory(ctx context.Context, dirPath string, recursive bool) ([]map[string]interface{}, error) {
	var allResources []map[string]interface{}
	var mu sync.Mutex

	walkFunc := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			if !recursive && path != dirPath {
				return fs.SkipDir
			}
			return nil
		}

		if !p.isManifestFile(path) {
			return nil
		}

		resources, err := p.ParseFile(ctx, path)
		if err != nil {
			return fmt.Errorf("failed to parse file %s: %w", path, err)
		}

		mu.Lock()
		allResources = append(allResources, resources...)
		mu.Unlock()

		return nil
	}

	err := filepath.WalkDir(dirPath, walkFunc)
	return allResources, err
}

// ParseContent parses YAML/JSON content from a string
func (p *FileManifestParser) ParseContent(ctx context.Context, content string) ([]map[string]interface{}, error) {
	var resources []map[string]interface{}

	// Split content by YAML document separator
	documents := strings.Split(content, "\n---\n")

	for _, doc := range documents {
		doc = strings.TrimSpace(doc)
		if doc == "" || strings.HasPrefix(doc, "#") {
			continue
		}

		var resource map[string]interface{}
		if err := yaml.Unmarshal([]byte(doc), &resource); err != nil {
			return nil, fmt.Errorf("failed to unmarshal YAML document: %w", err)
		}

		if len(resource) > 0 {
			resources = append(resources, resource)
		}
	}

	return resources, nil
}

// ValidateManifest validates a Kubernetes manifest
func (p *FileManifestParser) ValidateManifest(ctx context.Context, manifest map[string]interface{}) error {
	// Basic validation
	if manifest["apiVersion"] == nil {
		return fmt.Errorf("missing apiVersion field")
	}

	if manifest["kind"] == nil {
		return fmt.Errorf("missing kind field")
	}

	// Convert to unstructured for further validation
	unstructuredObj := &unstructured.Unstructured{Object: manifest}
	if unstructuredObj.GetName() == "" && unstructuredObj.GetGenerateName() == "" {
		// Some resources like ConfigMaps might not have names in templates
		// This is a soft validation
	}

	return nil
}

func (p *FileManifestParser) isManifestFile(filePath string) bool {
	ext := strings.ToLower(filepath.Ext(filePath))
	return ext == ".yaml" || ext == ".yml" || ext == ".json"
}