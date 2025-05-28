package extractor

import (
	"bytes"
	"context"
	"reflect"
	"testing"

	"github.com/alevsk/rbac-ops/internal/renderer"
	"gopkg.in/yaml.v3"
)

func TestIdentityExtractor_Extract(t *testing.T) {
	tests := []struct {
		name          string
		manifest      string
		want          int
		wantErr       bool
		strictParsing bool
		wantIdentity  *Identity
	}{
		{
			name: "valid service account with all fields",
			manifest: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: test-sa
  namespace: default
  labels:
    app: test
  annotations:
    description: "Test service account"
automountServiceAccountToken: true
secrets:
- name: test-secret
imagePullSecrets:
- name: docker-registry`,
			want:    1,
			wantErr: false,
			wantIdentity: &Identity{
				Name:           "test-sa",
				Namespace:      "default",
				AutomountToken: true,
				Labels: map[string]string{
					"app": "test",
				},
				Annotations: map[string]string{
					"description": "Test service account",
				},
				Secrets:          []string{"test-secret"},
				ImagePullSecrets: []string{"docker-registry"},
			},
		},
		{
			name: "service account with minimal fields",
			manifest: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: minimal-sa
  namespace: default`,
			want:    1,
			wantErr: false,
			wantIdentity: &Identity{
				Name:           "minimal-sa",
				Namespace:      "default",
				AutomountToken: false,
				Labels:         map[string]string{},
				Annotations:    map[string]string{},
			},
		},
		{
			name: "multiple service accounts",
			manifest: `apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa1
  namespace: ns1
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: sa2
  namespace: ns2`,
			want:    2,
			wantErr: false,
		},
		{
			name: "non-service account resource",
			manifest: `apiVersion: v1
kind: ConfigMap
metadata:
  name: test-cm
  namespace: default`,
			want:    0,
			wantErr: false,
		},
		{
			name: "missing kind field",
			manifest: `apiVersion: v1
metadata:
  name: test-sa
  namespace: default`,
			want:          0,
			wantErr:       true,
			strictParsing: true,
		},
		{
			name: "missing metadata field",
			manifest: `apiVersion: v1
kind: ServiceAccount
spec:
  containers: []`,
			want:          0,
			wantErr:       true,
			strictParsing: true,
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
			e := NewIdentityExtractor(opts)

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
				t.Errorf("IdentityExtractor.Extract() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if err != nil {
				return
			}

			var ok bool
			var identityData map[string]map[string]Identity
			identityData, ok = result.Data["identities"].(map[string]map[string]Identity)
			if !ok {
				t.Errorf("IdentityExtractor.Extract() result.Data[\"identities\"] is not map[string]map[string]Identity")
				return
			}

			// Count total identities across all namespaces
			var totalIdentities int
			for _, namespaceMap := range identityData {
				totalIdentities += len(namespaceMap)
			}

			if totalIdentities != tt.want {
				t.Errorf("IdentityExtractor.Extract() got %d identities, want %d", totalIdentities, tt.want)
			}

			// Verify specific identity if provided
			if tt.wantIdentity != nil {
				var ok bool
				var gotIdentity Identity
				gotIdentity, ok = identityData[tt.wantIdentity.Name][tt.wantIdentity.Namespace]
				if !ok {
					t.Errorf("IdentityExtractor.Extract() identity %s/%s not found", tt.wantIdentity.Namespace, tt.wantIdentity.Name)
					return
				}

				if !reflect.DeepEqual(gotIdentity, *tt.wantIdentity) {
					t.Errorf("IdentityExtractor.Extract() got identity = %v, want %v", gotIdentity, *tt.wantIdentity)
				}
			}

			// Verify metadata
			if count, ok := result.Metadata["count"].(int); !ok || count != tt.want {
				t.Errorf("IdentityExtractor.Extract() metadata count = %v, want %d", count, tt.want)
			}
		})
	}
}
