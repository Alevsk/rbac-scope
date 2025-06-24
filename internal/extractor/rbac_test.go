package extractor

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
	"gopkg.in/yaml.v3"
)

func TestRBACExtractor_GetSetOptions(t *testing.T) {
	defaultOpts := DefaultOptions()
	e := NewRBACExtractor(nil) // Starts with default options

	// 1. Test GetOptions returns default options initially
	if !reflect.DeepEqual(e.GetOptions(), defaultOpts) {
		t.Errorf("GetOptions() initial = %v, want %v", e.GetOptions(), defaultOpts)
	}

	// 2. Test SetOptions with new options
	newOpts := &Options{StrictParsing: true, IncludeMetadata: false}
	e.SetOptions(newOpts)
	if !reflect.DeepEqual(e.GetOptions(), newOpts) {
		t.Errorf("GetOptions() after SetOptions(newOpts) = %v, want %v", e.GetOptions(), newOpts)
	}

	// 3. Test SetOptions with nil (should retain current options)
	e.SetOptions(nil)
	if !reflect.DeepEqual(e.GetOptions(), newOpts) {
		t.Errorf("GetOptions() after SetOptions(nil) = %v, want %v (should be unchanged)", e.GetOptions(), newOpts)
	}
}

func TestRBACExtractor_Extract(t *testing.T) {
	tests := []struct {
		name          string
		manifest      string
		want          int
		wantErr       bool
		strictParsing bool
		wantRole      *RBACRole
		wantBinding   *RBACBinding
	}{
		{
			name: "valid role",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]`,
			want:    0, // No binding, so not counted
			wantErr: false,
			wantRole: &RBACRole{
				Type:      "Role",
				Name:      "pod-reader",
				Namespace: "default",
				Permissions: RuleApiGroup{
					"": RuleResource{
						"pods": RuleResourceName{
							"": RuleVerb{
								"get":   struct{}{},
								"list":  struct{}{},
								"watch": struct{}{},
							},
						},
					},
				},
			},
		},
		{
			name: "valid cluster role",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]`,
			want:    0, // No binding, so not counted
			wantErr: false,
			wantRole: &RBACRole{
				Type:      "ClusterRole",
				Name:      "pod-reader",
				Namespace: "*",
				Permissions: RuleApiGroup{
					"": RuleResource{
						"pods": RuleResourceName{
							"": RuleVerb{
								"get":   struct{}{},
								"list":  struct{}{},
								"watch": struct{}{},
							},
						},
					},
				},
			},
		},
		{
			name: "valid role binding",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["pod1", "pod2"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io`,
			want:    1, // Role with binding
			wantErr: false,
			wantRole: &RBACRole{
				Type:      "Role",
				Name:      "pod-reader",
				Namespace: "default",
				Permissions: RuleApiGroup{
					"": RuleResource{
						"pods": RuleResourceName{
							"pod1": RuleVerb{
								"get":   struct{}{},
								"list":  struct{}{},
								"watch": struct{}{},
							},
							"pod2": RuleVerb{
								"get":   struct{}{},
								"list":  struct{}{},
								"watch": struct{}{},
							},
						},
					},
				},
			},
			wantBinding: &RBACBinding{
				Type:      "RoleBinding",
				Name:      "read-pods",
				Namespace: "default",
				Subjects:  []BindingSubject{{Kind: "ServiceAccount", Name: "test-sa", Namespace: "default"}},
				RoleRef:   "pod-reader",
			},
		},
		{
			name: "valid cluster role binding",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["pod1"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-pods
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io`,
			want:    1, // ClusterRole with binding
			wantErr: false,
			wantRole: &RBACRole{
				Type:      "ClusterRole",
				Name:      "pod-reader",
				Namespace: "*",
				Permissions: RuleApiGroup{
					"": RuleResource{
						"pods": RuleResourceName{
							"pod1": RuleVerb{
								"get":   struct{}{},
								"list":  struct{}{},
								"watch": struct{}{},
							},
						},
					},
				},
			},
		},
		{
			name: "multiple rbac resources",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["pod1", "pod2"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io`,
			want:    1, // One role with binding
			wantErr: false,
		},
		{
			name: "non-rbac resource",
			manifest: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
data:
  key: value`,
			want:    0,
			wantErr: false,
		},
		{
			name:     "invalid yaml",
			manifest: "invalid: [yaml",
			want:     0,
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Set strict parsing if specified
			opts := DefaultOptions()
			opts.StrictParsing = tt.strictParsing
			e := NewRBACExtractor(opts)

			// Split manifest into multiple documents if needed
			docs := bytes.Split([]byte(tt.manifest), []byte("\n---\n"))
			var manifests []*renderer.Manifest
			for _, doc := range docs {
				// Parse YAML into map[string]interface{}
				var content map[string]interface{}
				if err := yaml.Unmarshal(doc, &content); err == nil {
					manifests = append(manifests, &renderer.Manifest{Raw: doc, Content: content})
				}
			}

			result, err := e.Extract(context.Background(), manifests)

			if (err != nil) != tt.wantErr {
				t.Errorf("RBACExtractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			// Verify roles
			var ok bool
			var roles []RBACRole
			roles, ok = result.Data["roles"].([]RBACRole)
			if !ok {
				t.Errorf("RBACExtractor.Extract() result.Data[\"roles\"] is not []RBACRole")
				return
			}

			// Verify bindings
			var bindings []RBACBinding
			bindings, ok = result.Data["bindings"].([]RBACBinding)
			if !ok {
				t.Errorf("RBACExtractor.Extract() result.Data[\"bindings\"] is not []RBACBinding")
				return
			}

			// Verify expected role if provided
			if tt.wantRole != nil {
				found := false
				for _, role := range roles {
					if role.Name == tt.wantRole.Name && role.Type == tt.wantRole.Type {
						if !reflect.DeepEqual(role, *tt.wantRole) {
							t.Errorf("RBACExtractor.Extract() got role = %v, want %v", role, *tt.wantRole)
						}
						found = true
						break
					}
				}
				if !found {
					t.Errorf("RBACExtractor.Extract() role %s/%s not found", tt.wantRole.Type, tt.wantRole.Name)
				}
			}

			// Verify expected binding if provided
			if tt.wantBinding != nil {
				found := false
				for _, binding := range bindings {
					if binding.Name == tt.wantBinding.Name && binding.Type == tt.wantBinding.Type {
						if !reflect.DeepEqual(binding, *tt.wantBinding) {
							t.Errorf("RBACExtractor.Extract() got binding = %v, want %v", binding, *tt.wantBinding)
						}
						found = true
						break
					}
				}
				if !found {
					t.Errorf("RBACExtractor.Extract() binding %s/%s not found", tt.wantBinding.Type, tt.wantBinding.Name)
				}
			}

			// Verify total number of bindings matches want
			if len(bindings) != tt.want {
				t.Errorf("RBACExtractor.Extract() got %d bindings, want %d", len(bindings), tt.want)
			}
		})
	}
}

func TestRBACExtractor_ServiceAccountMapping(t *testing.T) {
	manifest := `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: default
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
  resourceNames: ["pod1", "pod2"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: secret-reader
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get"]
  resourceNames: ["secret1"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: read-pods
  namespace: default
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: default
- kind: ServiceAccount
  name: another-sa
  namespace: default
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: read-secrets
subjects:
- kind: ServiceAccount
  name: test-sa
  namespace: default
roleRef:
  kind: ClusterRole
  name: secret-reader
  apiGroup: rbac.authorization.k8s.io`

	e := NewRBACExtractor(nil)
	docs := bytes.Split([]byte(manifest), []byte("\n---\n"))
	var manifests []*renderer.Manifest
	for _, doc := range docs {
		var content map[string]interface{}
		if err := yaml.Unmarshal(doc, &content); err == nil {
			manifests = append(manifests, &renderer.Manifest{Raw: doc, Content: content})
		}
	}

	result, err := e.Extract(context.Background(), manifests)
	if err != nil {
		t.Fatalf("RBACExtractor.Extract() error = %v", err)
	}

	rbacMap, ok := result.Data["rbac"].(map[string]map[string]ServiceAccountRBAC)
	if !ok {
		t.Fatal("RBACExtractor.Extract() result.Data[\"rbac\"] is not map[string]map[string]ServiceAccountRBAC")
	}

	// Check test-sa in default namespace and cluster-wide namespace
	testSARBAC, ok := rbacMap["test-sa"]["default"]
	if !ok {
		t.Errorf("test-sa not found in default namespace")
		return
	}

	// test-sa should have 1 role in default namespace and 1 cluster role
	if len(testSARBAC.Roles) != 2 {
		t.Errorf("test-sa has %d roles in default namespace, want 2", len(testSARBAC.Roles))
	}
	// Check another-sa in default namespace
	anotherSARBAC, ok := rbacMap["another-sa"]["default"]
	if !ok {
		t.Errorf("another-sa not found in default namespace")
		return
	}
	if len(anotherSARBAC.Roles) != 1 {
		t.Errorf("another-sa has %d roles, want 1", len(anotherSARBAC.Roles))
	}
}
