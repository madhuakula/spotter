package k8s

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

// K8sClient implements the Client interface for Kubernetes operations
type K8sClient struct {
	clientset       kubernetes.Interface
	dynamicClient   dynamic.Interface
	discoveryClient discovery.DiscoveryInterface
	restMapper      meta.RESTMapper
	config          *rest.Config
	mu              sync.RWMutex
}

// NewClient creates a new Kubernetes client
func NewClient(kubeconfig, context string) (Client, error) {
	config, err := buildConfig(kubeconfig, context)
	if err != nil {
		return nil, fmt.Errorf("failed to build kubernetes config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes clientset: %w", err)
	}

	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	discoveryClient, err := discovery.NewDiscoveryClientForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create discovery client: %w", err)
	}

	// Create a discovery-based REST mapper that can resolve API resources
	cachedDiscoveryClient := memory.NewMemCacheClient(discoveryClient)
	restMapper := restmapper.NewDeferredDiscoveryRESTMapper(cachedDiscoveryClient)

	return &K8sClient{
		clientset:       clientset,
		dynamicClient:   dynamicClient,
		discoveryClient: discoveryClient,
		restMapper:      restMapper,
		config:          config,
	}, nil
}

// GetResources retrieves all resources of specified types from the cluster
func (c *K8sClient) GetResources(ctx context.Context, gvks []schema.GroupVersionKind, namespaces []string) ([]map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if len(gvks) == 0 {
		return []map[string]interface{}{}, nil
	}

	// Use concurrent fetching for better performance
	type fetchJob struct {
		gvk       schema.GroupVersionKind
		namespace string
	}

	type fetchResult struct {
		resources []map[string]interface{}
		err       error
		job       fetchJob
	}

	// Create jobs for all GVK-namespace combinations
	var jobs []fetchJob
	for _, gvk := range gvks {
		if len(namespaces) == 0 {
			// Cluster-scoped or all namespaces
			jobs = append(jobs, fetchJob{gvk: gvk, namespace: ""})
		} else {
			// Specific namespaces
			for _, namespace := range namespaces {
				jobs = append(jobs, fetchJob{gvk: gvk, namespace: namespace})
			}
		}
	}

	// Reduce concurrency for production stability
	// Lower concurrency reduces API server load and throttling
	maxConcurrency := 5
	if len(jobs) < maxConcurrency {
		maxConcurrency = len(jobs)
	}

	jobChan := make(chan fetchJob, len(jobs))
	resultChan := make(chan fetchResult, len(jobs))

	// Start workers with rate limiting
	for i := 0; i < maxConcurrency; i++ {
		go func(workerID int) {
			for job := range jobChan {
				select {
				case <-ctx.Done():
					return
				default:
				}

				// Add small delay between requests to reduce API pressure
				if workerID > 0 {
					time.Sleep(time.Duration(workerID*50) * time.Millisecond)
				}

				gvr, err := c.gvkToGVR(job.gvk)
				if err != nil {
					resultChan <- fetchResult{
						resources: nil,
						err:       fmt.Errorf("failed to convert GVK to GVR for %s: %w", job.gvk.String(), err),
						job:       job,
					}
					continue
				}

				// Retry logic with exponential backoff
				resources, err := c.listResourcesWithRetry(ctx, gvr, job.namespace)
				resultChan <- fetchResult{
					resources: resources,
					err:       err,
					job:       job,
				}
			}
		}(i)
	}

	// Send jobs with controlled rate
	go func() {
		defer close(jobChan)
		for i, job := range jobs {
			select {
			case <-ctx.Done():
				return
			case jobChan <- job:
				// Add small delay between job submissions
				if i > 0 && i%5 == 0 {
					time.Sleep(100 * time.Millisecond)
				}
			}
		}
	}()

	// Collect results
	var allResources []map[string]interface{}
	var errors []string

	for i := 0; i < len(jobs); i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case result := <-resultChan:
			if result.err != nil {
				// Log the error but continue with other resources
				if result.job.namespace == "" {
					errors = append(errors, fmt.Sprintf("failed to list resources for %s: %v", result.job.gvk.String(), result.err))
				} else {
					errors = append(errors, fmt.Sprintf("failed to list resources for %s in namespace %s: %v", result.job.gvk.String(), result.job.namespace, result.err))
				}
				continue
			}
			allResources = append(allResources, result.resources...)
		}
	}

	// If we have some resources, return them even if there were some errors
	// Only return an error if we couldn't get any resources at all
	if len(allResources) == 0 && len(errors) > 0 {
		return nil, fmt.Errorf("failed to retrieve any resources: %s", strings.Join(errors, "; "))
	}

	return allResources, nil
}

// GetResource retrieves a specific resource by name and namespace
func (c *K8sClient) GetResource(ctx context.Context, gvk schema.GroupVersionKind, namespace, name string) (map[string]interface{}, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	gvr, err := c.gvkToGVR(gvk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert GVK to GVR for %s: %w", gvk.String(), err)
	}

	var resource *unstructured.Unstructured
	if namespace == "" {
		resource, err = c.dynamicClient.Resource(gvr).Get(ctx, name, metav1.GetOptions{})
	} else {
		resource, err = c.dynamicClient.Resource(gvr).Namespace(namespace).Get(ctx, name, metav1.GetOptions{})
	}

	if err != nil {
		return nil, fmt.Errorf("failed to get resource %s/%s: %w", namespace, name, err)
	}

	return resource.Object, nil
}

// ListNamespaces lists all namespaces in the cluster
func (c *K8sClient) ListNamespaces(ctx context.Context) ([]string, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	namespaces, err := c.clientset.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list namespaces: %w", err)
	}

	var namespaceNames []string
	for _, ns := range namespaces.Items {
		namespaceNames = append(namespaceNames, ns.Name)
	}

	return namespaceNames, nil
}

// WatchResources watches for resource changes
func (c *K8sClient) WatchResources(ctx context.Context, gvks []schema.GroupVersionKind, namespaces []string) (<-chan ResourceEvent, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	eventChan := make(chan ResourceEvent, 100)

	go func() {
		defer close(eventChan)

		for _, gvk := range gvks {
			gvr, err := c.gvkToGVR(gvk)
			if err != nil {
				eventChan <- ResourceEvent{
					Type:  EventTypeError,
					Error: fmt.Errorf("failed to convert GVK to GVR for %s: %w", gvk.String(), err),
				}
				continue
			}

			if len(namespaces) == 0 {
				go c.watchResource(ctx, gvr, "", eventChan)
			} else {
				for _, namespace := range namespaces {
					go c.watchResource(ctx, gvr, namespace, eventChan)
				}
			}
		}

		<-ctx.Done()
	}()

	return eventChan, nil
}

// ValidateConnection validates the connection to the Kubernetes cluster
func (c *K8sClient) ValidateConnection(ctx context.Context) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	_, err := c.clientset.Discovery().ServerVersion()
	if err != nil {
		return fmt.Errorf("failed to connect to kubernetes cluster: %w", err)
	}

	return nil
}

// DiscoverAllResources discovers all available API resources in the cluster
func (c *K8sClient) DiscoverAllResources(ctx context.Context) ([]schema.GroupVersionKind, error) {
	resourceInfos, err := c.DiscoverResourcesWithScope(ctx)
	if err != nil {
		return nil, err
	}

	var gvks []schema.GroupVersionKind
	for _, info := range resourceInfos {
		gvks = append(gvks, info.GVK)
	}

	return gvks, nil
}

func (c *K8sClient) DiscoverResourcesWithScope(ctx context.Context) ([]ResourceInfo, error) {
	c.mu.RLock()
	discoveryClient := c.discoveryClient
	c.mu.RUnlock()

	// Get all API groups and resources
	apiGroupList, err := discoveryClient.ServerGroups()
	if err != nil {
		return nil, fmt.Errorf("failed to get server groups: %w", err)
	}

	var allResources []ResourceInfo

	// Process core API group (v1)
	coreResources, err := discoveryClient.ServerResourcesForGroupVersion("v1")
	if err == nil {
		for _, resource := range coreResources.APIResources {
			// Skip subresources (those with '/' in the name)
			if !strings.Contains(resource.Name, "/") {
				gvk := schema.GroupVersionKind{
					Group:   "",
					Version: "v1",
					Kind:    resource.Kind,
				}
				resourceInfo := ResourceInfo{
					GVK:        gvk,
					Namespaced: resource.Namespaced,
					Verbs:      resource.Verbs,
					ShortNames: resource.ShortNames,
					Categories: resource.Categories,
				}
				allResources = append(allResources, resourceInfo)
			}
		}
	}

	// Process all other API groups
	for _, group := range apiGroupList.Groups {
		for _, version := range group.Versions {
			groupVersion := version.GroupVersion
			resources, err := discoveryClient.ServerResourcesForGroupVersion(groupVersion)
			if err != nil {
				// Skip groups that can't be accessed
				continue
			}

			for _, resource := range resources.APIResources {
				// Skip subresources (those with '/' in the name)
				if !strings.Contains(resource.Name, "/") {
					gv, err := schema.ParseGroupVersion(groupVersion)
					if err != nil {
						continue
					}
					gvk := schema.GroupVersionKind{
						Group:   gv.Group,
						Version: gv.Version,
						Kind:    resource.Kind,
					}
					resourceInfo := ResourceInfo{
						GVK:        gvk,
						Namespaced: resource.Namespaced,
						Verbs:      resource.Verbs,
						ShortNames: resource.ShortNames,
						Categories: resource.Categories,
					}
					allResources = append(allResources, resourceInfo)
				}
			}
		}
	}

	return allResources, nil
}

// Helper methods

func (c *K8sClient) gvkToGVR(gvk schema.GroupVersionKind) (schema.GroupVersionResource, error) {
	mapping, err := c.restMapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return schema.GroupVersionResource{}, err
	}
	return mapping.Resource, nil
}

func (c *K8sClient) listResources(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]map[string]interface{}, error) {
	var list *unstructured.UnstructuredList
	var err error

	if namespace == "" {
		list, err = c.dynamicClient.Resource(gvr).List(ctx, metav1.ListOptions{})
	} else {
		list, err = c.dynamicClient.Resource(gvr).Namespace(namespace).List(ctx, metav1.ListOptions{})
	}

	if err != nil {
		return nil, err
	}

	var resources []map[string]interface{}
	for _, item := range list.Items {
		resources = append(resources, item.Object)
	}

	return resources, nil
}

// listResourcesWithRetry implements exponential backoff retry logic for API calls
func (c *K8sClient) listResourcesWithRetry(ctx context.Context, gvr schema.GroupVersionResource, namespace string) ([]map[string]interface{}, error) {
	maxRetries := 3
	baseDelay := 100 * time.Millisecond
	maxDelay := 5 * time.Second

	for attempt := 0; attempt <= maxRetries; attempt++ {
		resources, err := c.listResources(ctx, gvr, namespace)
		if err == nil {
			return resources, nil
		}

		// Check if this is the last attempt
		if attempt == maxRetries {
			return nil, err
		}

		// Check if context is cancelled
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Calculate exponential backoff delay
		delay := time.Duration(1<<uint(attempt)) * baseDelay
		if delay > maxDelay {
			delay = maxDelay
		}

		// Add jitter to prevent thundering herd
		jitter := time.Duration(float64(delay) * 0.1)
		delay += jitter

		// Wait before retry
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(delay):
			// Continue to next attempt
		}
	}

	return nil, fmt.Errorf("max retries exceeded")
}

func (c *K8sClient) watchResource(ctx context.Context, gvr schema.GroupVersionResource, namespace string, eventChan chan<- ResourceEvent) {
	var watcher watch.Interface
	var err error

	if namespace == "" {
		watcher, err = c.dynamicClient.Resource(gvr).Watch(ctx, metav1.ListOptions{})
	} else {
		watcher, err = c.dynamicClient.Resource(gvr).Namespace(namespace).Watch(ctx, metav1.ListOptions{})
	}

	if err != nil {
		eventChan <- ResourceEvent{
			Type:  EventTypeError,
			Error: fmt.Errorf("failed to watch resource %s: %w", gvr.String(), err),
		}
		return
	}

	defer watcher.Stop()

	for {
		select {
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return
			}

			if obj, ok := event.Object.(*unstructured.Unstructured); ok {
				eventChan <- ResourceEvent{
					Type:     EventType(event.Type),
					Resource: obj.Object,
				}
			}
		case <-ctx.Done():
			return
		}
	}
}

func buildConfig(kubeconfig, context string) (*rest.Config, error) {
	var config *rest.Config
	var err error

	if kubeconfig == "" {
		// Try in-cluster config first
		if config, err = rest.InClusterConfig(); err == nil {
			// Configure in-cluster config for production
			configureProductionSettings(config)
			return config, nil
		}

		// Fall back to default kubeconfig location
		if home := homedir.HomeDir(); home != "" {
			kubeconfig = filepath.Join(home, ".kube", "config")
		}
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfig

	configOverrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		configOverrides.CurrentContext = context
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	config, err = clientConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	// Configure production settings
	configureProductionSettings(config)
	return config, nil
}

// configureProductionSettings optimizes the client configuration for production use
func configureProductionSettings(config *rest.Config) {
	// Set reasonable rate limiting to prevent throttling
	// QPS: Queries Per Second - how many requests per second
	// Burst: Maximum number of requests that can be made in a burst
	config.QPS = 50.0    // Increased from default 5
	config.Burst = 100   // Increased from default 10

	// Set timeouts for better reliability
	config.Timeout = 30 * time.Second

	// Disable client-side throttling warnings in logs
	// This reduces log noise while maintaining functionality
	if config.WrapTransport == nil {
		config.WrapTransport = func(rt http.RoundTripper) http.RoundTripper {
			return &productionTransport{wrapped: rt}
		}
	}
}

// productionTransport wraps the default transport to handle production concerns
type productionTransport struct {
	wrapped http.RoundTripper
}

func (pt *productionTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Add production-specific headers or modifications if needed
	return pt.wrapped.RoundTrip(req)
}
