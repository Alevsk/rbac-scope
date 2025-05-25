package extractor

import (
	"bytes"
	"context"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
)

func TestRBACExtractor_Extract(t *testing.T) {
	tests := []struct {
		name     string
		manifest string
		want     int
		wantErr  bool
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
			want:    1,
			wantErr: false,
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
			want:    1,
			wantErr: false,
		},
		{
			name: "valid role binding",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
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
			want:    1,
			wantErr: false,
		},
		{
			name: "valid cluster role binding",
			manifest: `apiVersion: rbac.authorization.k8s.io/v1
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
			want:    1,
			wantErr: false,
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
			want:    2,
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
			name:     "empty input",
			manifest: "",
			want:     0,
			wantErr:  true,
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
			e := NewRBACExtractor(nil)
			// Split manifest into multiple documents if needed
			docs := bytes.Split([]byte(tt.manifest), []byte("\n---\n"))
			var manifests []*renderer.Manifest
			for _, doc := range docs {
				manifests = append(manifests, &renderer.Manifest{Raw: doc})
			}
			result, err := e.Extract(context.Background(), manifests)

			if (err != nil) != tt.wantErr {
				t.Errorf("RBACExtractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil {
				return
			}

			// Check if we got the expected number of RBAC resources
			gotRoles := result.Metadata["roleCount"].(int)
			gotBindings := result.Metadata["bindingCount"].(int)
			got := gotRoles + gotBindings

			if got != tt.want {
				t.Errorf("RBACExtractor.Extract() got %d RBAC resources, want %d", got, tt.want)
			}

			// Verify that metadata counts match the actual data
			roles := result.Data["roles"].([]RBACRole)
			bindings := result.Data["bindings"].([]RBACBinding)
			if len(roles) != gotRoles {
				t.Errorf("RBACExtractor.Extract() roles count = %d, want %d", len(roles), gotRoles)
			}
			if len(bindings) != gotBindings {
				t.Errorf("RBACExtractor.Extract() bindings count = %d, want %d", len(bindings), gotBindings)
			}
		})
	}
}
