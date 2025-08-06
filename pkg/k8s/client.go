package k8s

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

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

	var allResources []map[string]interface{}
	var errors []string

	for _, gvk := range gvks {
		gvr, err := c.gvkToGVR(gvk)
		if err != nil {
			// Log the error but continue with other resources
			errors = append(errors, fmt.Sprintf("failed to convert GVK to GVR for %s: %v", gvk.String(), err))
			continue
		}

		if len(namespaces) == 0 {
			// Cluster-scoped or all namespaces
			resources, err := c.listResources(ctx, gvr, "")
			if err != nil {
				// Log the error but continue with other resources
				errors = append(errors, fmt.Sprintf("failed to list resources for %s: %v", gvk.String(), err))
				continue
			}
			allResources = append(allResources, resources...)
		} else {
			// Specific namespaces
			for _, namespace := range namespaces {
				resources, err := c.listResources(ctx, gvr, namespace)
				if err != nil {
					// Log the error but continue with other resources
					errors = append(errors, fmt.Sprintf("failed to list resources for %s in namespace %s: %v", gvk.String(), namespace, err))
					continue
				}
				allResources = append(allResources, resources...)
			}
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
	// Priority order for kubeconfig file selection:
	// 1. Check if there env var KUBECONFIG, if yes use that path
	// 2. If that's not found, then check if user passes --kubeconfig flag then use that
	// 3. If that's also not found, then directly use ~/.kube/config path

	var kubeconfigPath string

	// 1. Check KUBECONFIG environment variable first
	if envKubeconfig := os.Getenv("KUBECONFIG"); envKubeconfig != "" {
		kubeconfigPath = envKubeconfig
	} else if kubeconfig != "" {
		// 2. Use the kubeconfig flag if provided
		kubeconfigPath = kubeconfig
	} else {
		// 3. Try in-cluster config first, then fall back to default kubeconfig location
		if config, err := rest.InClusterConfig(); err == nil {
			return config, nil
		}

		// Fall back to default kubeconfig location
		if home := homedir.HomeDir(); home != "" {
			kubeconfigPath = filepath.Join(home, ".kube", "config")
		} else {
			return nil, fmt.Errorf("unable to determine kubeconfig path: no KUBECONFIG environment variable, no --kubeconfig flag, and no home directory found")
		}
	}

	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	loadingRules.ExplicitPath = kubeconfigPath

	configOverrides := &clientcmd.ConfigOverrides{}
	if context != "" {
		configOverrides.CurrentContext = context
	}

	clientConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides)
	return clientConfig.ClientConfig()
}
