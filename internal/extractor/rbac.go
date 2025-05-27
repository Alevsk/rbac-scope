package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

// RBACPermission represents a permission from a Role or ClusterRole
type RBACPermission struct {
	APIGroups []string `json:"apiGroups"`
	Resources []string `json:"resources"`
	Verbs     []string `json:"verbs"`
}

// RBACBinding represents a RoleBinding or ClusterRoleBinding
type RBACBinding struct {
	Type      string   `json:"type"` // RoleBinding or ClusterRoleBinding
	Name      string   `json:"name"`
	Namespace string   `json:"namespace,omitempty"`
	Subjects  []string `json:"subjects"` // List of subject names (ServiceAccounts)
	RoleRef   string   `json:"roleRef"`  // Name of the Role/ClusterRole being referenced
}

// RBACRole represents a Role or ClusterRole
type RBACRole struct {
	Type        string           `json:"type"` // Role or ClusterRole
	Name        string           `json:"name"`
	Namespace   string           `json:"namespace,omitempty"`
	Permissions []RBACPermission `json:"permissions"`
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
		namespace := ""
		if ns, ok := metadata["namespace"].(string); ok {
			namespace = ns
		}

		switch kind {
		case "Role", "ClusterRole":
			rbacRole := RBACRole{
				Type:      kind,
				Name:      name,
				Namespace: namespace,
			}

			// Extract rules
			if rules, ok := manifest.Content["rules"].([]interface{}); ok {
				for _, r := range rules {
					rule, ok := r.(map[string]interface{})
					if !ok {
						continue
					}

					permission := RBACPermission{
						APIGroups: toStringSlice(rule["apiGroups"]),
						Resources: toStringSlice(rule["resources"]),
						Verbs:     toStringSlice(rule["verbs"]),
					}
					rbacRole.Permissions = append(rbacRole.Permissions, permission)
				}
			}
			roles = append(roles, rbacRole)

		case "RoleBinding", "ClusterRoleBinding":
			// Extract subjects
			var subjects []string
			if subjectsArray, ok := manifest.Content["subjects"].([]interface{}); ok {
				for _, s := range subjectsArray {
					subject, ok := s.(map[string]interface{})
					if !ok {
						continue
					}

					if subjectKind, ok := subject["kind"].(string); ok && subjectKind == "ServiceAccount" {
						if subjectName, ok := subject["name"].(string); ok {
							subjects = append(subjects, subjectName)
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
			if _, exists := rbacMap[subject]; !exists {
				rbacMap[subject] = make(map[string]ServiceAccountRBAC)
			}

			// For ClusterRoleBindings, we need to add the binding to the "*" namespace
			// since they apply cluster-wide
			namespace := binding.Namespace
			if binding.Type == "ClusterRoleBinding" {
				namespace = "*"
			}

			// Initialize the ServiceAccountRBAC if it doesn't exist
			if _, exists := rbacMap[subject][namespace]; !exists {
				rbacMap[subject][namespace] = ServiceAccountRBAC{}
			}
			saRBAC := rbacMap[subject][namespace]

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
			rbacMap[subject][namespace] = saRBAC
		}
	}

	result.Data["roles"] = roles
	result.Data["bindings"] = bindings
	result.Data["rbac"] = rbacMap
	// Update metadata
	result.Metadata["roleCount"] = len(roles)

	return result, nil
}

// Validate checks if the manifests can be processed
func (e *RBACExtractor) Validate(manifests []*renderer.Manifest) error {
	if len(manifests) == 0 {
		return ErrInvalidInput
	}

	for _, manifest := range manifests {
		if manifest.Content == nil {
			return fmt.Errorf("%w: empty manifest", ErrInvalidInput)
		}
	}

	return nil
}

// GetOptions returns the extractor options
func (e *RBACExtractor) GetOptions() *Options {
	return e.opts
}

// SetOptions sets the extractor options
func (e *RBACExtractor) SetOptions(opts *Options) {
	e.opts = opts
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
