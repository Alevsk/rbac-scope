package extractor

import (
	"context"
	"fmt"

	"github.com/alevsk/rbac-ops/internal/renderer"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
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

// RBACExtractor implements Extractor for RBAC resources
type RBACExtractor struct {
	decoder runtime.Decoder
	opts    *Options
}

// NewRBACExtractor creates a new RBACExtractor
func NewRBACExtractor(opts *Options) *RBACExtractor {
	if opts == nil {
		opts = DefaultOptions()
	}

	scheme := runtime.NewScheme()
	utilruntime.Must(corev1.AddToScheme(scheme))
	utilruntime.Must(rbacv1.AddToScheme(scheme))

	return &RBACExtractor{
		decoder: serializer.NewCodecFactory(scheme).UniversalDeserializer(),
		opts:    opts,
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
		obj, gvk, err := e.decoder.Decode(manifest.Raw, nil, nil)
		if err != nil {
			if e.opts != nil && e.opts.StrictParsing {
				return nil, fmt.Errorf("failed to decode manifest: %w", err)
			}
			continue
		}

		switch gvk.Kind {
		case "Role":
			role := obj.(*rbacv1.Role)
			rbacRole := RBACRole{
				Type:      "Role",
				Name:      role.Name,
				Namespace: role.Namespace,
			}
			for _, rule := range role.Rules {
				rbacRole.Permissions = append(rbacRole.Permissions, RBACPermission{
					APIGroups: rule.APIGroups,
					Resources: rule.Resources,
					Verbs:     rule.Verbs,
				})
			}
			roles = append(roles, rbacRole)

		case "ClusterRole":
			clusterRole := obj.(*rbacv1.ClusterRole)
			rbacRole := RBACRole{
				Type: "ClusterRole",
				Name: clusterRole.Name,
			}
			for _, rule := range clusterRole.Rules {
				rbacRole.Permissions = append(rbacRole.Permissions, RBACPermission{
					APIGroups: rule.APIGroups,
					Resources: rule.Resources,
					Verbs:     rule.Verbs,
				})
			}
			roles = append(roles, rbacRole)

		case "RoleBinding":
			binding := obj.(*rbacv1.RoleBinding)
			var subjects []string
			for _, subject := range binding.Subjects {
				if subject.Kind == "ServiceAccount" {
					subjects = append(subjects, subject.Name)
				}
			}
			bindings = append(bindings, RBACBinding{
				Type:      "RoleBinding",
				Name:      binding.Name,
				Namespace: binding.Namespace,
				Subjects:  subjects,
				RoleRef:   binding.RoleRef.Name,
			})

		case "ClusterRoleBinding":
			binding := obj.(*rbacv1.ClusterRoleBinding)
			var subjects []string
			for _, subject := range binding.Subjects {
				if subject.Kind == "ServiceAccount" {
					subjects = append(subjects, subject.Name)
				}
			}
			bindings = append(bindings, RBACBinding{
				Type:     "ClusterRoleBinding",
				Name:     binding.Name,
				Subjects: subjects,
				RoleRef:  binding.RoleRef.Name,
			})
		}
	}

	result.Metadata["roleCount"] = len(roles)
	result.Metadata["bindingCount"] = len(bindings)
	result.Data["roles"] = roles
	result.Data["bindings"] = bindings

	return result, nil
}

// Validate checks if the manifests can be processed
func (e *RBACExtractor) Validate(manifests []*renderer.Manifest) error {
	if len(manifests) == 0 {
		return ErrInvalidInput
	}

	for _, manifest := range manifests {
		if len(manifest.Raw) == 0 {
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
