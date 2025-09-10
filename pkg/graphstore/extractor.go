package graphstore

import (
	"fmt"
	"strings"

	"github.com/madhuakula/spotter/pkg/models"
)

// FactExtractor extracts graph facts from Kubernetes resources
type FactExtractor struct{}

// NewFactExtractor creates a new fact extractor
func NewFactExtractor() *FactExtractor {
	return &FactExtractor{}
}

// ExtractFacts extracts graph facts from a list of Kubernetes resources
func (e *FactExtractor) ExtractFacts(resources []map[string]interface{}) (*models.GraphFacts, error) {
	facts := &models.GraphFacts{
		Pods:            []models.PodFact{},
		Secrets:         []models.SecretFact{},
		ConfigMaps:      []models.ConfigMapFact{},
		ServiceAccounts: []models.ServiceAccountFact{},
		Roles:           []models.RoleFact{},
		ApiPermissions:  []models.ApiPermissionFact{},
		Relationships:   []models.RelationshipFact{},
	}

	// Process each resource
	for _, resource := range resources {
		if err := e.extractFromResource(resource, facts); err != nil {
			// Log error but continue processing other resources
			continue
		}
	}

	return facts, nil
}

// extractFromResource extracts facts from a single Kubernetes resource
func (e *FactExtractor) extractFromResource(resource map[string]interface{}, facts *models.GraphFacts) error {
	kind := e.getStringField(resource, "kind")
	if kind == "" {
		return fmt.Errorf("resource missing kind field")
	}

	switch kind {
	case "Pod":
		return e.extractPodFacts(resource, facts)
	case "Secret":
		return e.extractSecretFacts(resource, facts)
	case "ConfigMap":
		return e.extractConfigMapFacts(resource, facts)
	case "ServiceAccount":
		return e.extractServiceAccountFacts(resource, facts)
	case "Role", "ClusterRole":
		return e.extractRoleFacts(resource, facts)
	case "RoleBinding", "ClusterRoleBinding":
		return e.extractRoleBindingFacts(resource, facts)
	}

	return nil
}

// extractPodFacts extracts Pod facts and relationships
func (e *FactExtractor) extractPodFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")
	namespace := e.getStringField(metadata, "namespace")
	if namespace == "" {
		namespace = "default"
	}

	podID := fmt.Sprintf("%s/%s", namespace, name)

	// Determine if pod has internet access (simplified heuristic)
	internetOK := e.hasInternetAccess(resource)

	// Add pod fact
	facts.Pods = append(facts.Pods, models.PodFact{
		ID:         podID,
		Namespace:  namespace,
		InternetOK: internetOK,
	})

	// Extract volume relationships
	e.extractPodVolumeRelationships(resource, podID, facts)

	// Extract service account relationship
	e.extractPodServiceAccountRelationship(resource, podID, facts)

	return nil
}

// extractSecretFacts extracts Secret facts
func (e *FactExtractor) extractSecretFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")
	namespace := e.getStringField(metadata, "namespace")
	if namespace == "" {
		namespace = "default"
	}

	secretID := fmt.Sprintf("%s/%s", namespace, name)
	secretType := e.getStringField(resource, "type")

	// Determine if this secret contains credentials
	credLike, reason := e.isCredentialLike(secretType, metadata)

	facts.Secrets = append(facts.Secrets, models.SecretFact{
		ID:        secretID,
		Namespace: namespace,
		CredLike:  credLike,
		Reason:    reason,
	})

	return nil
}

// extractConfigMapFacts extracts ConfigMap facts
func (e *FactExtractor) extractConfigMapFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")
	namespace := e.getStringField(metadata, "namespace")
	if namespace == "" {
		namespace = "default"
	}

	configMapID := fmt.Sprintf("%s/%s", namespace, name)

	// Check if ConfigMap contains credential-like data
	credLike, reason := e.isConfigMapCredentialLike(resource)

	facts.ConfigMaps = append(facts.ConfigMaps, models.ConfigMapFact{
		ID:        configMapID,
		Namespace: namespace,
		CredLike:  credLike,
		Reason:    reason,
	})

	return nil
}

// extractServiceAccountFacts extracts ServiceAccount facts
func (e *FactExtractor) extractServiceAccountFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")
	namespace := e.getStringField(metadata, "namespace")
	if namespace == "" {
		namespace = "default"
	}

	saID := fmt.Sprintf("%s/%s", namespace, name)

	facts.ServiceAccounts = append(facts.ServiceAccounts, models.ServiceAccountFact{
		ID:        saID,
		Namespace: namespace,
	})

	return nil
}

// extractRoleFacts extracts Role/ClusterRole facts and API permissions
func (e *FactExtractor) extractRoleFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")
	namespace := e.getStringField(metadata, "namespace")
	kind := e.getStringField(resource, "kind")

	var roleID string
	if kind == "ClusterRole" {
		roleID = fmt.Sprintf("cluster/%s", name)
		namespace = "cluster"
	} else {
		if namespace == "" {
			namespace = "default"
		}
		roleID = fmt.Sprintf("%s/%s", namespace, name)
	}

	facts.Roles = append(facts.Roles, models.RoleFact{
		ID:        roleID,
		Namespace: namespace,
	})

	// Extract API permissions from rules
	rules := e.getArrayField(resource, "rules")
	for i, rule := range rules {
		ruleMap, ok := rule.(map[string]interface{})
		if !ok {
			continue
		}

		resources := e.getStringArrayField(ruleMap, "resources")
		verbs := e.getStringArrayField(ruleMap, "verbs")

		for _, resourceType := range resources {
			for _, verb := range verbs {
				permID := fmt.Sprintf("%s-%d-%s-%s", roleID, i, resourceType, verb)

				facts.ApiPermissions = append(facts.ApiPermissions, models.ApiPermissionFact{
					ID:       permID,
					Resource: resourceType,
					Verb:     verb,
					Scope:    namespace,
				})

				// Add relationship between role and permission
				facts.Relationships = append(facts.Relationships, models.RelationshipFact{
					Type:   models.RelationshipAllows,
					FromID: roleID,
					ToID:   permID,
				})
			}
		}
	}

	return nil
}

// extractRoleBindingFacts extracts RoleBinding/ClusterRoleBinding relationships
func (e *FactExtractor) extractRoleBindingFacts(resource map[string]interface{}, facts *models.GraphFacts) error {
	metadata := e.getMapField(resource, "metadata")
	namespace := e.getStringField(metadata, "namespace")
	kind := e.getStringField(resource, "kind")

	// Get role reference
	roleRef := e.getMapField(resource, "roleRef")
	roleName := e.getStringField(roleRef, "name")
	roleKind := e.getStringField(roleRef, "kind")

	var roleID string
	if roleKind == "ClusterRole" || kind == "ClusterRoleBinding" {
		roleID = fmt.Sprintf("cluster/%s", roleName)
	} else {
		if namespace == "" {
			namespace = "default"
		}
		roleID = fmt.Sprintf("%s/%s", namespace, roleName)
	}

	// Get subjects
	subjects := e.getArrayField(resource, "subjects")
	for _, subject := range subjects {
		subjectMap, ok := subject.(map[string]interface{})
		if !ok {
			continue
		}

		subjectKind := e.getStringField(subjectMap, "kind")
		subjectName := e.getStringField(subjectMap, "name")
		subjectNamespace := e.getStringField(subjectMap, "namespace")

		if subjectKind == "ServiceAccount" {
			if subjectNamespace == "" {
				subjectNamespace = namespace
			}
			if subjectNamespace == "" {
				subjectNamespace = "default"
			}

			saID := fmt.Sprintf("%s/%s", subjectNamespace, subjectName)

			// Add relationship between service account and role
			facts.Relationships = append(facts.Relationships, models.RelationshipFact{
				Type:   models.RelationshipBoundTo,
				FromID: saID,
				ToID:   roleID,
			})
		}
	}

	return nil
}

// extractPodVolumeRelationships extracts relationships between pods and volumes
func (e *FactExtractor) extractPodVolumeRelationships(resource map[string]interface{}, podID string, facts *models.GraphFacts) {
	spec := e.getMapField(resource, "spec")
	volumes := e.getArrayField(spec, "volumes")

	for _, volume := range volumes {
		volumeMap, ok := volume.(map[string]interface{})
		if !ok {
			continue
		}

		// Check for secret volume
		if secretVol := e.getMapField(volumeMap, "secret"); secretVol != nil {
			secretName := e.getStringField(secretVol, "secretName")
			if secretName != "" {
				namespace := strings.Split(podID, "/")[0]
				secretID := fmt.Sprintf("%s/%s", namespace, secretName)
				facts.Relationships = append(facts.Relationships, models.RelationshipFact{
					Type:   models.RelationshipUsesSecret,
					FromID: podID,
					ToID:   secretID,
				})
			}
		}

		// Check for configMap volume
		if configMapVol := e.getMapField(volumeMap, "configMap"); configMapVol != nil {
			configMapName := e.getStringField(configMapVol, "name")
			if configMapName != "" {
				namespace := strings.Split(podID, "/")[0]
				configMapID := fmt.Sprintf("%s/%s", namespace, configMapName)
				facts.Relationships = append(facts.Relationships, models.RelationshipFact{
					Type:   models.RelationshipUsesConfigMap,
					FromID: podID,
					ToID:   configMapID,
				})
			}
		}
	}
}

// extractPodServiceAccountRelationship extracts the relationship between pod and service account
func (e *FactExtractor) extractPodServiceAccountRelationship(resource map[string]interface{}, podID string, facts *models.GraphFacts) {
	spec := e.getMapField(resource, "spec")
	serviceAccountName := e.getStringField(spec, "serviceAccountName")
	if serviceAccountName == "" {
		serviceAccountName = e.getStringField(spec, "serviceAccount")
	}
	if serviceAccountName == "" {
		serviceAccountName = "default"
	}

	namespace := strings.Split(podID, "/")[0]
	saID := fmt.Sprintf("%s/%s", namespace, serviceAccountName)

	facts.Relationships = append(facts.Relationships, models.RelationshipFact{
		Type:   models.RelationshipUsesSA,
		FromID: podID,
		ToID:   saID,
	})
}

// Helper methods for extracting fields from Kubernetes resources

func (e *FactExtractor) getStringField(obj map[string]interface{}, field string) string {
	if val, ok := obj[field]; ok {
		if str, ok := val.(string); ok {
			return str
		}
	}
	return ""
}

func (e *FactExtractor) getMapField(obj map[string]interface{}, field string) map[string]interface{} {
	if val, ok := obj[field]; ok {
		if m, ok := val.(map[string]interface{}); ok {
			return m
		}
	}
	return nil
}

func (e *FactExtractor) getArrayField(obj map[string]interface{}, field string) []interface{} {
	if val, ok := obj[field]; ok {
		if arr, ok := val.([]interface{}); ok {
			return arr
		}
	}
	return nil
}

func (e *FactExtractor) getStringArrayField(obj map[string]interface{}, field string) []string {
	arr := e.getArrayField(obj, field)
	var result []string
	for _, item := range arr {
		if str, ok := item.(string); ok {
			result = append(result, str)
		}
	}
	return result
}

// hasInternetAccess determines if a pod has internet access (simplified heuristic)
func (e *FactExtractor) hasInternetAccess(resource map[string]interface{}) bool {
	// This is a simplified heuristic. In a real implementation, you would
	// analyze network policies, service mesh configuration, etc.

	// For now, assume pods have internet access unless they're in system namespaces
	metadata := e.getMapField(resource, "metadata")
	namespace := e.getStringField(metadata, "namespace")

	systemNamespaces := []string{"kube-system", "kube-public", "kube-node-lease"}
	for _, sysNs := range systemNamespaces {
		if namespace == sysNs {
			return false
		}
	}

	return true
}

// isCredentialLike determines if a secret contains credential-like data
func (e *FactExtractor) isCredentialLike(secretType string, metadata map[string]interface{}) (bool, string) {
	credentialTypes := []string{
		"kubernetes.io/service-account-token",
		"kubernetes.io/dockercfg",
		"kubernetes.io/dockerconfigjson",
		"kubernetes.io/basic-auth",
		"kubernetes.io/ssh-auth",
		"kubernetes.io/tls",
		"Opaque", // Many credential secrets use Opaque type
	}

	for _, credType := range credentialTypes {
		if secretType == credType {
			return true, fmt.Sprintf("Secret type: %s", credType)
		}
	}

	// Check annotations for credential indicators
	annotations := e.getMapField(metadata, "annotations")
	for key := range annotations {
		if strings.Contains(strings.ToLower(key), "credential") ||
			strings.Contains(strings.ToLower(key), "password") ||
			strings.Contains(strings.ToLower(key), "token") ||
			strings.Contains(strings.ToLower(key), "key") {
			return true, fmt.Sprintf("Annotation indicates credentials: %s", key)
		}
	}

	return false, ""
}

// isConfigMapCredentialLike determines if a ConfigMap contains credential-like data
func (e *FactExtractor) isConfigMapCredentialLike(resource map[string]interface{}) (bool, string) {
	metadata := e.getMapField(resource, "metadata")
	name := e.getStringField(metadata, "name")

	// Check name for credential indicators
	credentialKeywords := []string{"password", "secret", "key", "token", "credential", "auth"}
	nameLower := strings.ToLower(name)
	for _, keyword := range credentialKeywords {
		if strings.Contains(nameLower, keyword) {
			return true, fmt.Sprintf("Name suggests credentials: %s", name)
		}
	}

	// Check data keys for credential indicators
	data := e.getMapField(resource, "data")
	for key := range data {
		keyLower := strings.ToLower(key)
		for _, keyword := range credentialKeywords {
			if strings.Contains(keyLower, keyword) {
				return true, fmt.Sprintf("Data key suggests credentials: %s", key)
			}
		}
	}

	return false, ""
}
