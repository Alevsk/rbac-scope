package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

// BindingSubject represents a Kubernetes subject
type BindingSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
}

// RBACBinding represents a RoleBinding or ClusterRoleBinding
type RBACBinding struct {
	Type      string           `json:"type"` // RoleBinding or ClusterRoleBinding
	Name      string           `json:"name"`
	Namespace string           `json:"namespace,omitempty"`
	Subjects  []BindingSubject `json:"subjects"` // List of subject names (ServiceAccounts)
	RoleRef   string           `json:"roleRef"`  // Name of the Role/ClusterRole being referenced
}

// RuleVerb represents a permission verb (get, list, etc.)
type RuleVerb map[string]struct{}

// RuleResourceName maps resource names to verbs
type RuleResourceName map[string]RuleVerb

// RuleResource maps resources to their resource names
type RuleResource map[string]RuleResourceName

// RuleApiGroup maps API groups to resources
type RuleApiGroup map[string]RuleResource

// RBACRole represents a Role or ClusterRole
type RBACRole struct {
	Type        string       `json:"type"` // Role or ClusterRole
	Name        string       `json:"name"`
	Namespace   string       `json:"namespace,omitempty"`
	Permissions RuleApiGroup `json:"permissions,omitempty"` // Permissions by API group, resource, resource name and verb
}

// ServiceAccountRBAC represents all RBAC information for a service account
type ServiceAccountRBAC struct {
	Roles []RBACRole `json:"roles"` // Roles bound to this service account
}

// RBACExtractor implements Extractor for RBAC resources
type RBACExtractor struct {
	opts *Options
}

// NewRBACExtractor creates a new RBACExtractor
func NewRBACExtractor(opts *Options) *RBACExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	return &RBACExtractor{
		opts: opts,
	}
}

// Extract processes the manifests and returns structured RBAC data
func (e *RBACExtractor) Extract(ctx context.Context, manifests []*renderer.Manifest) (*Result, error) {
	if err := e.Validate(manifests); err != nil {
		return nil, fmt.Errorf("validation failed: %w", err)
	}

	result := NewResult()
	var roles []RBACRole
	var bindings []RBACBinding

	for _, manifest := range manifests {
		// Get kind and metadata
		kind, ok := manifest.Content["kind"].(string)
		if !ok {
			if e.opts != nil && e.opts.StrictParsing {
				return nil, fmt.Errorf("missing kind in manifest")
			}
			continue
		}

		metadata, ok := manifest.Content["metadata"].(map[string]interface{})
		if !ok {
			if e.opts != nil && e.opts.StrictParsing {
				return nil, fmt.Errorf("invalid metadata in manifest")
			}
			continue
		}

		name := metadata["name"].(string)

		namespace := "default" // Default namespace for cluster scoped resources
		if ns, ok := metadata["namespace"].(string); ok {
			namespace = ns
		}
		// namespace for cluster wide resources
		if kind == "ClusterRole" || kind == "ClusterRoleBinding" {
			namespace = "*"
		}

		switch kind {
		case "Role", "ClusterRole":
			rbacRole := RBACRole{
				Type:        kind,
				Name:        name,
				Namespace:   namespace,
				Permissions: RuleApiGroup{},
			}

			// Extract rules
			if rules, ok := manifest.Content["rules"].([]interface{}); ok {
				for _, r := range rules {
					rule, ok := r.(map[string]interface{})
					if !ok {
						continue
					}

					apiGroups := toStringSlice(rule["apiGroups"])
					resources := toStringSlice(rule["resources"])
					resourceNames := toStringSlice(rule["resourceNames"])
					verbs := toStringSlice(rule["verbs"])

					if resourceNames == nil {
						resourceNames = []string{""}
					}

					// Optimization: If any list is empty, this rule grants no permissions.
					if len(resources) == 0 || len(verbs) == 0 {
						continue
					}

					for _, apiGroup := range apiGroups {
						// Get or create the map for the current apiGroup
						// This reduces lookups for `rbacRole.Permissions[apiGroup]`
						_, agExists := rbacRole.Permissions[apiGroup]
						if !agExists {
							rbacRole.Permissions[apiGroup] = RuleResource{}
						}

						for _, resource := range resources {
							// Get or create the map for the current resource within the apiGroup
							// This reduces lookups for `rbacRole.Permissions[apiGroup][resource]`
							_, resExists := rbacRole.Permissions[apiGroup][resource]
							if !resExists {
								rbacRole.Permissions[apiGroup][resource] = RuleResourceName{}
							}

							for _, resourceName := range resourceNames {
								_, verbExists := rbacRole.Permissions[apiGroup][resource][resourceName]
								if !verbExists {
									rbacRole.Permissions[apiGroup][resource][resourceName] = RuleVerb{}
								}

								for _, verb := range verbs {
									rbacRole.Permissions[apiGroup][resource][resourceName][verb] = struct{}{}
								}
							}
						}
					}

				}
			}
			roles = append(roles, rbacRole)

		case "RoleBinding", "ClusterRoleBinding":
			// Extract subjects
			var subjects []BindingSubject
			if subjectsArray, ok := manifest.Content["subjects"].([]interface{}); ok {
				for _, s := range subjectsArray {
					subject, ok := s.(map[string]interface{})
					if !ok {
						continue
					}

					if subjectKind, ok := subject["kind"].(string); ok && subjectKind == "ServiceAccount" {
						if subjectName, ok := subject["name"].(string); ok {
							if subjectNamespace, ok := subject["namespace"].(string); ok {
								subjects = append(subjects, BindingSubject{
									Kind:      subjectKind,
									Name:      subjectName,
									Namespace: subjectNamespace,
								})
							}
						}
					}
				}
			}

			// Extract roleRef
			roleRef := ""
			if ref, ok := manifest.Content["roleRef"].(map[string]interface{}); ok {
				if refName, ok := ref["name"].(string); ok {
					roleRef = refName
				}
			}

			bindings = append(bindings, RBACBinding{
				Type:      kind,
				Name:      name,
				Namespace: namespace,
				Subjects:  subjects,
				RoleRef:   roleRef,
			})
		}
	}

	// Create a map to store ServiceAccountRBAC by service account name and namespace
	rbacMap := make(map[string]map[string]ServiceAccountRBAC)

	// First, create maps for roles by name and type for quick lookup
	rolesByName := make(map[string]map[string]RBACRole)
	clusterRolesByName := make(map[string]RBACRole)
	for _, role := range roles {
		if role.Type == "ClusterRole" {
			clusterRolesByName[role.Name] = role
		} else {
			rolesByName[role.Name] = make(map[string]RBACRole)
			rolesByName[role.Name][role.Namespace] = role
		}
	}

	// Process bindings to organize roles by service account
	for _, binding := range bindings {
		for _, subject := range binding.Subjects {
			// Initialize maps if they don't exist
			if _, exists := rbacMap[subject.Name]; !exists {
				rbacMap[subject.Name] = make(map[string]ServiceAccountRBAC)
			}

			// Initialize the ServiceAccountRBAC if it doesn't exist
			if _, exists := rbacMap[subject.Name][subject.Namespace]; !exists {
				rbacMap[subject.Name][subject.Namespace] = ServiceAccountRBAC{}
			}
			saRBAC := rbacMap[subject.Name][subject.Namespace]

			// Add the referenced role based on the binding type
			var role RBACRole
			var exists bool
			if binding.Type == "ClusterRoleBinding" {
				role, exists = clusterRolesByName[binding.RoleRef]
			} else {
				role, exists = rolesByName[binding.RoleRef][binding.Namespace]
			}

			if exists {
				// Check if the role is already added
				alreadyAddedRole := false
				for _, r := range saRBAC.Roles {
					if r.Name == role.Name && r.Type == role.Type {
						alreadyAddedRole = true
						break
					}
				}
				if !alreadyAddedRole {
					saRBAC.Roles = append(saRBAC.Roles, role)
				}
			}

			// Update the map
			rbacMap[subject.Name][subject.Namespace] = saRBAC
		}
	}

	result.Data["roles"] = roles
	result.Data["bindings"] = bindings
	result.Data["rbac"] = rbacMap
	// Update metadata
	result.Metadata["roleCount"] = len(roles)
	result.Metadata["bindingCount"] = len(bindings)

	return result, nil
}

// Validate checks if the manifests can be processed
func (e *RBACExtractor) Validate(manifests []*renderer.Manifest) error {
	if len(manifests) == 0 {
		return ErrInvalidInput
	}

	return nil
}

// GetOptions returns the extractor options
func (e *RBACExtractor) GetOptions() *Options {
	return e.opts
}

// SetOptions sets the extractor options
func (e *RBACExtractor) SetOptions(opts *Options) {
	if opts != nil {
		e.opts = opts
	}
}

// toStringSlice converts an interface{} to []string
func toStringSlice(v interface{}) []string {
	if v == nil {
		return nil
	}

	if slice, ok := v.([]interface{}); ok {
		result := make([]string, 0, len(slice))
		for _, item := range slice {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	}

	return nil
}
